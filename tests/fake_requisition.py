# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""An in-process stand-in for Requisition's lab /v1 API, for tests only. Not Requisition.

It follows the semantics read from the Requisition version of 2026-10-26, rule by rule, so the adapters can be
tested end to end without the real server (which the tests must not write to):

* propose: members, the derived hash, argument
  validation, 201 {request_id, status: pending};
* GET: pending until two approvals (here: ``approve()``), then the statement minted once on the first
  GET; ``refuse()`` is a rejected
  approval;
* execute: members, not_after window, nonce claim and exact retry by
  body digest, binding, display digest, single spend LAST
  on the allow path, the signed decision and its response;
* records: the lab labels and key id (bin/lab-verify DEV_KEY_IDS), Ed25519
  over the signed payload's bytes, receipt_hash = SHA-256 of them;
* the chain (Requisition's lab as of 2026-11-09): every record is appended to its ``chain_scope``
  at ``sequence`` = head + 1 with ``previous_hash`` = the head's ``receipt_hash`` (nil for the first),
  both inside the signed bytes. The scope has the lab's form ``requisition-lab:account:<uuid>``.

Test controls that model an operator, not a route: ``snapshot()``/``restore()`` (a database dump and
restore: every row, the chain included, back to the dump; the signing keys are not database state and
stay), ``pump_denies(n)`` (n signed denies another caller provokes on the same chain),
``records_between()`` (the fence's fetch hook in tests: that lab has NO such route) and ``export()`` (a store dump for bin/verify_chain.py, labelled as the
fake's).
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from requisition_aws import canonical
from requisition_aws.client import parse_instant, instant

KEY_ID = "requisition_lab_dev_ed25519_v0"
MLDSA_KEY_ID = "requisition_lab_dev_mldsa87_v0"  # the key id of the lab's ML-DSA-87 seat
ELEVEN = ("chain_scope", "sequence", "receipt_type", "subject_type", "subject_id", "status",
          "payload_hash", "previous_hash", "occurred_at", "metadata", "schema_version")
LABELS = {"profile": "lab", "signer": "dev", "n6_profile": "not_followed", "hands": "one-person"}
PROPOSE_MEMBERS = {"principal", "act_type", "act_hash", "act_hash_alg", "display", "class", "exp", "arm_statement_id"}
EXECUTE_MEMBERS = {"principal", "act_type", "act_hash", "act_hash_alg", "display_projection", "statement_id", "nonce", "not_after"}
CHAIN_SCOPE = "requisition-lab:account:00000000-0000-4000-8000-0000000000f1"  # the lab's form; a made-up account
FAKE_PROVENANCE = "produced by tests/fake_requisition.py (an in-process stand-in), NOT by Requisition"
# the database: what a dump holds and a restore puts back (the signing keys are not in it)
DB_STATE = ("requests", "statements", "claims", "spent", "chains", "outcomes", "idempotency", "cosigs", "_gets")


def _holds_float(value):
    """Does the decoded JSON ``value`` hold a float at any depth? The fake's own check, not the code under test's:
    Requisition's execute API is specified to refuse a float argument as float_refused (the name this package's
    intake gives it), and json.loads reads 1.0, 1e5 and -0.0 as floats."""
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_holds_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_holds_float(v) for v in value)
    return False


class FakeRequisition:
    def __init__(self, credential="rqc_test_credential", principal="rqp_" + "0" * 32, act_types=None, now=None,
                 mldsa87_kinds=(), newer_routes=False, cosign=None, chain_scope=CHAIN_SCOPE):
        # mldsa87_kinds: record kinds ("statement", "decision") signed by an ML-DSA-87 seat instead
        # (the key file then carries both entries).
        # newer_routes: the newer routes (POST /v1/outcomes, GET /v1/sanction-requests?act_hash=,
        # idempotency_key on propose). Off, they answer as the Requisition version of 2026-10-26 does:
        # GET /v1/sanction-requests is 405 method_not_allowed, /v1/outcomes 404 route_unknown.
        self.mldsa87_kinds = set(mldsa87_kinds)
        # cosign (a planned shape, not from code): None (today), "signed"
        # (Ed25519 record + an ML-DSA-87 co-signature over the same bytes, beside it as "cosignature"),
        # "seat_absent" or "signed_bytes_over_bound" (Ed25519 only, the signed cosign member says so)
        self.cosign = cosign
        self.cosigs: dict[str, dict] = {}
        self.cosign_tamper = None  # a test hook: callable(cosignature) -> cosignature
        self.auto_approve_after = None  # dry runs only: approve a request on its Nth GET
        self.corrupt_signatures = False  # test hook: every primary signature answered is replaced
        self.cosign_with = None  # test hook: "ed25519" -> the co-signature is the Ed25519 key's
        self.response_tamper = None  # test hook: callable(execute answer) -> answer
        self._gets: dict[str, int] = {}
        self.newer_routes = newer_routes
        self.outcomes: list[dict] = []
        self.idempotency: dict[str, str] = {}
        self.credential = credential
        self.principal = principal
        self.caller_id = "rqcl_" + "1" * 32
        self.act_types = act_types or {}
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc).replace(microsecond=0))
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.registry = {
            "entries": [
                {
                    "key_id": KEY_ID,
                    "algorithm": "ed25519",
                    "public_key": base64.b64encode(raw).decode(),
                    "public_key_fingerprint": hashlib.sha256(raw).hexdigest(),
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                    "status": "active",
                    "profile": "lab",
                    "signer": "dev",
                }
            ]
        }
        self.mldsa_key = None
        if self.mldsa87_kinds or cosign:
            self.mldsa_key = MLDSA87PrivateKey.generate()
            raw_ml = self.mldsa_key.public_key().public_bytes_raw()
            self.registry["entries"].append({
                "key_id": MLDSA_KEY_ID,
                "algorithm": "mldsa87",
                "public_key": base64.b64encode(raw_ml).decode(),
                "public_key_fingerprint": hashlib.sha256(raw_ml).hexdigest(),
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
                "status": "active",
                "status_changed_at": "2026-01-01T00:00:00Z",
                "profile": "lab",
                "signer": "dev",
            })
        self.requests: dict[str, dict] = {}
        self.statements: dict[str, dict] = {}
        self.claims: dict[str, dict] = {}
        self.spent: set[str] = set()
        self.sequence = 0  # the last sequence assigned (in the current scope)
        self.chain_scope = chain_scope  # a test may switch it: later records go to that scope's chain
        self.chains: dict[str, list[dict]] = {}  # chain_scope -> its records in order (the store's rows)
        self.down = False
        self.force_deny: str | None = None  # a step-1 deny (e.g. authority_freeze), signed, no spend
        self.status_override: int | None = None
        self.fail_paths: set[str] = set()  # paths answered 503
        self.calls: list[tuple[str, str]] = []
        # the caller credential's lifecycle: a refused credential answers 401 with its state's code
        # (in Requisition's order: revoked, then expired, only after the secret matched); ``also_valid``
        # are other live credentials (a re-mint); ``expire_on = (method, path prefix)`` expires the
        # presented live credential AT that request (the expiry lands on that very call)
        self.credential_states: dict[str, str] = {}
        self.also_valid: set[str] = set()
        self.expire_on: tuple[str, str] | None = None
        self.auth_log: list[tuple[str, str, str | None]] = []  # (method, path, the credential presented)
        self.lock = threading.Lock()
        self._server = None

    # --- test controls ---------------------------------------------------------------------------

    def approve(self, request_id):
        self.requests[request_id]["approved"] = True

    def revoke(self, request_id):
        """An approval revoked after its statement was minted (Requisition then answers an
        exact retry of the allow decision_superseded)."""
        self.requests[request_id]["revoked"] = True

    def refuse(self, request_id):
        self.requests[request_id]["refused"] = "approval_expired_at_execution"

    # --- the database as an operator sees it (F1: rollback) --------------------------------------

    def snapshot(self):
        """A dump of every row (requests, statements, nonce claims, spends, the chains, outcomes,
        idempotency keys): what pg_dump would hold. Opaque to callers."""
        with self.lock:
            return copy.deepcopy({name: getattr(self, name) for name in DB_STATE})

    def restore(self, snap):
        """Put the database back to ``snap`` (pg_restore into the same service). The keys stay."""
        with self.lock:
            for name, value in copy.deepcopy(snap).items():
                setattr(self, name, value)

    def head(self, chain_scope=None):
        chain = self.chains.get(chain_scope or self.chain_scope) or []
        return chain[-1] if chain else None

    def records_between(self, chain_scope, after, before):
        """TEST-ONLY fetch hook: the records of ``chain_scope`` with after < sequence < before, in
        order (envelopes). The lab of 2026-11-09 has no such route."""
        with self.lock:
            chain = self.chains.get(chain_scope) or []
            return [copy.deepcopy(r) for r in chain
                    if after < json.loads(r["signed_payload"])["sequence"] < before]

    def export(self, chain_scope=None):
        """A store dump of one chain for bin/verify_chain.py: every row in order, each with its
        co-signature when it has one, labelled as the fake's."""
        with self.lock:
            scope = chain_scope or self.chain_scope
            rows = []
            for r in self.chains.get(scope) or []:
                row = {"record": copy.deepcopy(r)}
                if r["receipt_hash"] in self.cosigs:
                    row["cosignature"] = copy.deepcopy(self.cosigs[r["receipt_hash"]])
                rows.append(row)
            return {"provenance": FAKE_PROVENANCE, "chain_scope": scope, "records": rows}

    def pump_denies(self, n):
        """``n`` signed denies (statement_unknown) that another caller provokes on this chain: cheap,
        validly signed records that advance the sequence. Returns their envelopes."""
        out = []
        for _ in range(n):
            body = {"principal": self.principal, "act_type": "payments.refund_send", "act_hash": "0" * 96,
                    "act_hash_alg": canonical.ACT_HASH_ALG, "display_projection": {"pump": True},
                    "statement_id": "f" * 64, "nonce": uuid.uuid4().hex,
                    "not_after": instant(self.now() + dt.timedelta(seconds=60))}
            with self.lock:
                status, answer, _ = self.execute(body)
            assert status == 200 and answer["verdict"] == "deny", answer
            out.append(answer["decision"])
        return out

    def start(self, unix_path=None):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, obj=None, raw=None):
                data = raw if raw is not None else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method):
                fake.calls.append((method, self.path))
                if fake.down:
                    self.close_connection = True
                    self.wfile.write(b"")
                    return
                if fake.status_override or self.path in fake.fail_paths:
                    return self._send(fake.status_override or 503, {"error": "service_unavailable"})
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                status, obj, raw = fake.dispatch(method, self.path, self.headers, body)
                self._send(status, obj, raw)

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        if unix_path:
            import socketserver

            class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
                daemon_threads = True

            Handler.address_string = lambda self: "unix"
            self._server = UnixServer(unix_path, Handler)
        else:
            self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        if unix_path:
            return "http://localhost"
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    # --- records -------------------------------------------------------------------------------

    def _record(self, receipt_type, subject_type, subject_id, metadata, kind=None):
        chain = self.chains.setdefault(self.chain_scope, [])
        self.sequence = len(chain) + 1  # as Requisition reserves it: head + 1 under the chain lock
        previous_hash = chain[-1]["receipt_hash"] if chain else None  # head/1: nil for the first
        pq = kind in self.mldsa87_kinds
        key_id = MLDSA_KEY_ID if pq else KEY_ID
        if self.cosign and not pq:
            metadata = {**metadata, "cosign": {"algorithm": "mldsa87", "status": self.cosign,
                                               "key_id": (KEY_ID if self.cosign_with == "ed25519" else MLDSA_KEY_ID)
                                               if self.cosign == "signed" else None}}
        fields = {
            "chain_scope": self.chain_scope,
            "sequence": self.sequence,
            "receipt_type": receipt_type,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "status": "recorded",
            "payload_hash": None,
            "previous_hash": previous_hash,
            "occurred_at": instant(self.now()),
            "metadata": {**metadata, **LABELS, "key_id": key_id},
            "schema_version": "agent_receipt.v1" if pq else 1,
        }
        payload = canonical.encode(fields).decode()
        signer = self.mldsa_key if pq else self.key  # pure ML-DSA-87, empty context
        record = {
            "signature": base64.b64encode(signer.sign(payload.encode())).decode(),
            "key_id": key_id,
            "signed_payload": payload,
            "receipt_hash": hashlib.sha256(payload.encode()).hexdigest(),
        }
        if self.cosign == "signed" and not pq:
            cosigner, cos_id = (self.key, KEY_ID) if self.cosign_with == "ed25519" else (self.mldsa_key, MLDSA_KEY_ID)
            self.cosigs[record["receipt_hash"]] = {
                "signature": base64.b64encode(cosigner.sign(payload.encode())).decode(),
                "key_id": cos_id, "signed_payload": payload, "receipt_hash": record["receipt_hash"]}
        chain.append(dict(record))  # the stored row is the record as signed (before any test corruption)
        if self.corrupt_signatures:
            record["signature"] = base64.b64encode(b"\x00" * len(base64.b64decode(record["signature"]))).decode()
        return record

    def _with_cosignature(self, answer, record):
        cos = self.cosigs.get(record["receipt_hash"])
        if cos is not None:
            answer["cosignature"] = self.cosign_tamper(dict(cos)) if self.cosign_tamper else dict(cos)
        return answer

    @staticmethod
    def agent_receipt_form(record):
        """Requisition's AgentReceipt form: the eleven fields as signed, plus signature and key_id."""
        signed = json.loads(record["signed_payload"])
        return {**{k: signed[k] for k in ELEVEN}, "signature": record["signature"], "key_id": record["key_id"]}

    # --- dispatch ------------------------------------------------------------------------------

    def dispatch(self, method, path, headers, body):
        with self.lock:
            if method == "GET" and path == "/v1/keys":
                return 200, None, json.dumps(self.registry).encode()
            bearer = headers.get("authorization") or ""
            presented = bearer[len("Bearer "):] if bearer.startswith("Bearer ") else None
            self.auth_log.append((method, path, presented))
            live = presented is not None and (presented == self.credential or presented in self.also_valid)
            if self.expire_on and live and method == self.expire_on[0] and path.startswith(self.expire_on[1]):
                self.credential_states[presented] = "caller_credential_expired"
                self.expire_on = None
            if presented in self.credential_states:
                return 401, {"error": self.credential_states[presented]}, None
            if not live:
                return 401, {"error": "caller_unauthenticated"}, None
            try:
                parsed = json.loads(body) if body else {}
            except ValueError:
                return 400, {"error": "malformed_request"}, None
            if method == "POST" and path == "/v1/sanction-requests":
                return self.propose(parsed)
            if path.startswith("/v1/sanction-requests?"):
                if not (self.newer_routes and method == "GET"):
                    return 405, {"error": "method_not_allowed"}, None  # the Requisition version of 2026-10-26
                return self.lookup(path.split("?", 1)[1])
            if method == "POST" and path == "/v1/outcomes" and self.newer_routes:
                return self.outcome(parsed)
            if method == "GET" and path.startswith("/v1/sanction-requests/"):
                return self.fetch(path.rsplit("/", 1)[1])
            if method == "POST" and path == "/v1/execute":
                return self.execute(parsed)
            return 404, {"error": "route_unknown"}, None

    def propose(self, body):
        allowed = PROPOSE_MEMBERS | ({"idempotency_key"} if self.newer_routes else set())
        if set(body) - allowed:
            return 400, {"error": "member_out_of_schema"}, None
        key = body.pop("idempotency_key", None)
        if key is not None:
            known = self.idempotency.get(key)
            if known is not None:
                return 201, {"request_id": known, "status": "pending"}, None
        if not {"principal", "act_type", "act_hash", "act_hash_alg", "display"} <= set(body):
            return 400, {"error": "missing_member"}, None
        if body["principal"] != self.principal:
            return 403, {"error": "caller_grant_principal_not_covered"}, None
        schema = self.act_types.get(body["act_type"])
        if schema is None:
            return 400, {"error": "act_type_unknown"}, None
        if body["act_hash_alg"] != canonical.ACT_HASH_ALG:
            return 400, {"error": "act_hash_alg_unknown"}, None
        if _holds_float(body["display"]):
            return 400, {"error": "float_refused"}, None
        try:
            schema.validate(body["display"])
        except canonical.IntakeRefusal as refusal:
            return 400, {"error": refusal.code}, None
        if canonical.act_hash(body["act_type"], body["display"]) != body["act_hash"]:
            return 400, {"error": "act_hash_derived_mismatch"}, None
        rid = str(uuid.uuid4())
        self.requests[rid] = {
            "body": body,
            "approval_id": str(uuid.uuid4()),
            "approved": False,
            "refused": None,
            "statement": None,
        }
        if key is not None:
            self.idempotency[key] = rid
        return 201, {"request_id": rid, "status": "pending"}, None

    # --- the newer routes (assumed shapes until their code exists; see client.py) -------------------------

    def lookup(self, query):
        """The act_hash lookup, as a shape: the caller's own, newest first, at most 20, spent
        ones left out unless include_spent=true; read only (never mints)."""
        from urllib.parse import parse_qs

        q = parse_qs(query)
        if set(q) - {"act_hash", "include_spent"}:
            return 400, {"error": "member_out_of_schema"}, None
        act_hash = q.get("act_hash", [None])[0]
        if not act_hash:
            return 400, {"error": "missing_member"}, None
        include_spent = q.get("include_spent", ["false"])[0] == "true"
        found = []
        for rid, row in reversed(list(self.requests.items())):
            if row["body"]["act_hash"] != act_hash or row["body"]["principal"] != self.principal:
                continue
            status = "refused" if row["refused"] else ("sanctioned" if row["statement"] else "pending")
            spent = bool(row["statement"]) and row["statement"]["receipt_hash"] in self.spent
            if spent and not include_spent:
                continue
            entry = {"request_id": rid, "status": status, "spent": spent}
            if row["statement"]:
                entry["statement_id"] = row["statement"]["receipt_hash"]
            if row["refused"]:
                entry["refused_code"] = row["refused"]
            found.append(entry)
        return 200, {"requests": found[:20]}, None

    def outcome(self, body):
        """The outcome report, as a shape: the order is form, then the allow
        this caller holds (one answer, 404, for any mismatch), then the claim per statement."""
        required = {"principal", "statement_id", "decision_receipt_hash", "outcome", "result_digest"}
        if set(body) - required - {"detail_code"}:
            return 400, {"error": "member_out_of_schema"}, None
        if not required <= set(body):
            return 400, {"error": "missing_member"}, None
        if body["outcome"] not in ("succeeded", "failed"):
            return 400, {"error": "malformed_member"}, None
        allow = next((c["response"] for c in self.claims.values()
                      if c["response"]["receipt_hash"] == body["decision_receipt_hash"]
                      and c["response"]["verdict"] == "allow"
                      and c["response"]["statement_id"] == body["statement_id"]
                      and body["principal"] == self.principal), None)
        if allow is None:
            return 404, {"error": "outcome_decision_unknown"}, None
        digest = hashlib.sha256(canonical.encode(body)).hexdigest()
        prior = next((o for o in self.outcomes if o["statement_id"] == body["statement_id"]), None)
        if prior is not None:
            if prior["digest"] != digest:
                return 409, {"error": "outcome_already_recorded"}, None
            return 200, self._with_cosignature({"record": prior["record"]}, prior["record"]), None
        signed = json.loads(allow["decision"]["signed_payload"])["metadata"]
        metadata = {"evidence": "caller_report", "statement_id": body["statement_id"], "statement_id_label": "lab-v0",
                    "decision_receipt_hash": body["decision_receipt_hash"], "caller_id": self.caller_id,
                    "principal": body["principal"], "act_type": signed["act_type"], "act_hash": signed["act_hash"],
                    "act_hash_alg": signed["act_hash_alg"], "outcome": body["outcome"],
                    "result_digest": body["result_digest"], "result_digest_alg": "sha256",
                    "reported_at": instant(self.now())}
        if "detail_code" in body:
            metadata["detail_code"] = body["detail_code"]
        record = self._record("requisition.lab.outcome.v0", "requisition.lab.outcome_claim", str(uuid.uuid4()),
                              metadata, kind="outcome")
        self.outcomes.append({**body, "digest": digest, "record": record})
        return 200, self._with_cosignature({"record": record}, record), None

    def fetch(self, rid):
        row = self.requests.get(rid)
        if row is None:
            return 404, {"error": "sanction_request_unknown"}, None
        if self.auto_approve_after is not None:
            self._gets[rid] = self._gets.get(rid, 0) + 1
            if self._gets[rid] >= self.auto_approve_after:
                row["approved"] = True
        if row["statement"]:
            st = row["statement"]
            return 200, self._with_cosignature({"status": "sanctioned", "statement_id": st["receipt_hash"],
                                                "statement_id_label": "lab-v0", "statement": st}, st), None
        if row["refused"]:
            return 200, {"status": "refused", "refused_code": row["refused"]}, None
        if not row["approved"]:
            return 200, {"status": "pending"}, None
        body = row["body"]
        now = self.now()
        record = self._record(
            "requisition.lab.statement.v0",
            "requisition.lab.sanction_request",
            rid,
            kind="statement",
            metadata={
                "statement_id_label": "lab-v0",
                "request_id": rid,
                "approval_request_id": row["approval_id"],
                "caller_id": self.caller_id,
                "grant_id": "g",
                "principal": body["principal"],
                "act_type": body["act_type"],
                "act_hash": body["act_hash"],
                "act_hash_alg": body["act_hash_alg"],
                "class": "high",
                "display_digest": canonical.display_digest(body["display"]),
                "display_schema_digest": "d",
                "registry_digest": "r",
                "sanctioners": ["u1", "u2"],
                "iat": instant(now),
                "nbf": instant(now),
                "exp": instant(now + dt.timedelta(seconds=300)),
            },
        )
        row["statement"] = record
        self.statements[record["receipt_hash"]] = {"record": record, "row": row}
        return self.fetch(rid)

    def execute(self, body):
        if set(body) - EXECUTE_MEMBERS:
            return 400, {"error": "member_out_of_schema"}, None
        if "statement_id" not in body:
            return 400, {"error": "statement_id_required"}, None
        if not EXECUTE_MEMBERS <= set(body):
            return 400, {"error": "missing_member"}, None
        not_after = parse_instant(body["not_after"])
        now = self.now()
        if not_after is None:
            return 400, {"error": "malformed_member"}, None
        if not (now < not_after and (not_after - now).total_seconds() <= 300):
            return 400, {"error": "not_after_out_of_window"}, None
        if _holds_float(body["display_projection"]):
            return 400, {"error": "float_refused"}, None
        digest = hashlib.sha256(canonical.encode(body)).hexdigest()
        claim = self.claims.get((self.caller_id, body["nonce"]))  # the nonce claim: per (caller, nonce)
        if claim is not None:
            if claim["digest"] != digest:
                return 409, {"error": "nonce_reused_with_different_body"}, None
            stored = claim["response"]
            if stored["verdict"] == "allow":
                # as Requisition: a stored allow re-runs steps 1-5; any deny now is decision_superseded
                found = self.statements.get(body["statement_id"])
                row = found["row"] if found else None
                exp = parse_instant(json.loads(found["record"]["signed_payload"])["metadata"]["exp"]) if found else None
                if self.force_deny or row is None or row.get("revoked") or exp is None or now >= exp:
                    return 409, {"error": "decision_superseded"}, None
            return 200, self._tampered(self._with_cosignature(dict(stored), stored["decision"])), None
        verdict, code = "allow", None
        found = self.statements.get(body["statement_id"])
        if self.force_deny:
            verdict, code = "deny", self.force_deny
        elif found is None:
            verdict, code = "deny", "statement_unknown"
        else:
            signed = json.loads(found["record"]["signed_payload"])["metadata"]
            if any(body[k] != signed[k] for k in ("principal", "act_type", "act_hash", "act_hash_alg")):
                verdict, code = "deny", "act_binding_mismatch"
            elif canonical.display_digest(body["display_projection"]) != signed["display_digest"]:
                verdict, code = "deny", "display_projection_mismatch"
            elif found["row"].get("revoked"):
                verdict, code = "deny", "approval_revoked"
            elif body["statement_id"] in self.spent:
                verdict, code = "deny", "statement_spent"
            else:
                self.spent.add(body["statement_id"])
        metadata = {
            "verdict": verdict,
            "statement_id": body["statement_id"],
            "statement_id_label": "lab-v0",
            "caller_id": self.caller_id,
            "principal": body["principal"],
            "act_type": body["act_type"],
            "act_hash": body["act_hash"],
            "act_hash_alg": body["act_hash_alg"],
            "display_projection_digest": canonical.display_digest(body["display_projection"]),
            "nonce": body["nonce"],
            "not_after": body["not_after"],
            "decided_at": instant(now),
        }
        if code:
            metadata["code"] = code
        if verdict == "allow":
            metadata["exec_not_after"] = instant(min(not_after, now + dt.timedelta(seconds=60)))
        claim_id = str(uuid.uuid4())
        record = self._record("requisition.lab.decision.v0", "requisition.lab.nonce_claim", claim_id, metadata,
                              kind="decision")
        response = {
            "verdict": verdict,
            "code": code,
            "decision": record,
            "decision_receipt_id": str(uuid.uuid4()),
            "receipt_hash": record["receipt_hash"],
            "statement_id": body["statement_id"],
            "statement_id_label": "lab-v0",
            "exec_not_after": metadata.get("exec_not_after"),
        }
        if "decision" in self.mldsa87_kinds:  # the AgentReceipt form beside the envelope
            response["receipt"] = self.agent_receipt_form(record)
        self.claims[(self.caller_id, body["nonce"])] = {"digest": digest, "response": response}
        return 200, self._tampered(self._with_cosignature(dict(response), record)), None

    def _tampered(self, answer):
        return self.response_tamper(dict(answer)) if self.response_tamper else answer
