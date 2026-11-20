# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The flow both adapters share: propose (deduplicated), read the sanction, execute (idempotent),
and check every answer before anything runs. Every failure raises a ``RequisitionError``; the
adapters turn that into "do not run the tool" (fail closed).

What is checked, against Requisition's own record shapes:

* a statement (``GET /v1/sanction-requests/:id``):
  ``statement_id`` = ``receipt_hash`` = SHA-256 of ``signed_payload``; the signed
  ``request_id``, ``principal``, ``act_type``, ``act_hash``, ``act_hash_alg`` and ``display_digest``
  are what the adapter proposed;
* a decision (``POST /v1/execute``): ``receipt_hash``
  = SHA-256 of ``signed_payload``; ``receipt_type`` ``requisition.lab.decision.v0``; the signed
  ``verdict`` and ``code`` equal the response's; the signed ``principal``, ``act_type``, ``act_hash``,
  ``act_hash_alg``, ``statement_id``, ``nonce`` and ``not_after`` equal the body sent; the signed
  ``display_projection_digest`` is the digest of the arguments; an allow carries ``exec_not_after``
  and the tool may run only before it;
* the signature of both (Ed25519, or ML-DSA-87 for the lab's post-quantum seat), when a pinned key
  file is given (``keys.KeyRegistry``);
* the ML-DSA-87 co-signature, when the answer carries
  ``cosignature``: a four-field envelope whose ``signed_payload`` and ``receipt_hash`` EQUAL the
  record's (the same bytes, never re-serialized), whose ``key_id`` equals the signed
  ``metadata.cosign.key_id``, with ``cosign.status`` ``signed``, and whose signature verifies under
  that key's mldsa87 entry. A record whose signed ``cosign.status`` is ``signed`` but which arrives
  without the co-signature was stripped: refused. With ``require_pq`` a record with no checked
  ML-DSA-87 signature (``cosign`` absent, ``seat_absent`` or ``signed_bytes_over_bound``) is refused.

The newer routes, when the server has them (``client.py``'s feature check; otherwise today's behaviour):

* before filing, ``GET /v1/sanction-requests?act_hash=`` finds a request this caller already filed
  for the same arguments object (a lost local store, a crash between propose and the store write);
  a pending one, or a sanctioned one whose statement the server says is unspent, is adopted;
* propose carries ``idempotency_key`` = SHA-256 over (act_hash, the reservation's token), so a
  filer that crashed mid-propose and is taken over files the same request, not a second;
* ``report_outcome`` sends ``POST /v1/outcomes`` after the tool ran (succeeded or failed, with the
  SHA-256 of the result bytes). It never raises: the effect has happened; a report that cannot be
  made is returned as its status for the caller to show.

F1 (fence.py): every signed record read here (the statement, the decision, the outcome
record), after its signature checks, enters the Store's position memory; a record at a held position
with a different hash raises ``authority_equivocated`` (both kept as evidence). ``claim`` is the one
atomic claim (statement + the approval it names) every form makes before acting on an allow.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import canonical, fence
from .client import (
    Client,
    RequisitionError,
    RequisitionRefused,
    instant,
    loads_strict,
    parse_instant,
)
from .keys import KeyRegistry
from .store import Store

DECISION_TYPE = "requisition.lab.decision.v0"  # the receipt_type Requisition signs into a decision
STATEMENT_TYPE = "requisition.lab.statement.v0"  # the receipt_type Requisition signs into a statement
OUTCOME_TYPE = "requisition.lab.outcome.v0"  # the outcome record (not in the Requisition version of 2026-10-26)
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
# signed denies after which the statement can never allow again: the proposal leaves dedupe
CLOSING_DENIES = {
    "statement_spent",
    "approval_revoked",
    "approval_expired_at_execution",
    "statement_unknown",
    "statement_key_unknown",
}


class RecordInvalid(RequisitionError):
    """An answer whose signed record does not bind what the adapter sent: never run on it."""


class StaleExecute(RequisitionError):
    """A stored execute body whose ``not_after`` has passed: fail closed, never re-sign."""


@dataclass
class Sanction:
    request_id: str
    act_type: str
    act_hash: str
    status: str  # pending | sanctioned | refused
    approval_url: str
    statement_id: str | None = None
    statement: dict | None = None
    approval_id: str | None = None
    refused_code: str | None = None
    filed_now: bool = False
    cosignature: dict | None = None


@dataclass
class Decision:
    verdict: str
    code: str | None
    statement_id: str
    exec_not_after: str | None
    decision: dict
    response: dict
    replayed: bool
    nonce: str
    signature_checked: bool
    metadata: dict = field(default_factory=dict)
    pq_checked: bool = False  # an ML-DSA-87 signature (primary or co-signature) checked here

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def arguments_object(agent: str, session: str, tool: str, tool_args: dict, tool_digest: str | None = None) -> dict:
    """The arguments object of the demo's argument rows (Requisition's demo seed file, the set aws_demo):
    ``{agent, session, tool, args}``. ``tool`` holds the act type name (the seed's enum). A v2 row
    (G2) adds ``tool_digest``: the digest of the tool definition the call is made under."""
    out = {"agent": agent, "session": session, "tool": tool, "args": tool_args}
    if tool_digest is not None:
        out["tool_digest"] = tool_digest
    return out


def idempotency_key_for(act_hash: str, token: str) -> str:
    """The propose idempotency key: 64 lower-case hex, stable across a takeover of the same
    reservation (store.reserve_proposal keeps the token), new for every genuinely new proposal."""
    return hashlib.sha256(canonical.encode(["requisition-aws/propose", act_hash, token])).hexdigest()


def result_bytes(result: Any) -> bytes:
    """The bytes an outcome's ``result_digest`` covers: bytes as given; a str as UTF-8; anything
    else as CanonicalPayload v3 (the same encoder as the act hash), or, if it holds a float (outside
    v3's domain), compact JSON with sorted keys."""
    if isinstance(result, (bytes, bytearray)):
        return bytes(result)
    if isinstance(result, str):
        return result.encode("utf-8")
    try:
        return canonical.encode(result)
    except (canonical.CanonicalRefusal, canonical.IntakeRefusal, ValueError, TypeError):
        return json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def result_digest(result: Any) -> str:
    return hashlib.sha256(result_bytes(result)).hexdigest()


def _is_signed_outcome(record: Any, decision: Decision) -> bool:
    """The outcome answer's record names this allow (signature checks are the offline check's)."""
    try:
        signed = _signed(record)
    except RecordInvalid:
        return False
    md = signed["metadata"]
    return (signed.get("receipt_type") == OUTCOME_TYPE and md.get("decision_receipt_hash") == decision.decision["receipt_hash"]
            and md.get("statement_id") == decision.statement_id)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signed(envelope: Any) -> dict:
    if not isinstance(envelope, dict) or not all(isinstance(envelope.get(k), str) for k in ENVELOPE):
        raise RecordInvalid("record is not a four-field envelope")
    if _sha256(envelope["signed_payload"]) != envelope["receipt_hash"]:
        raise RecordInvalid("receipt_hash is not the SHA-256 of signed_payload")
    try:
        signed = loads_strict(envelope["signed_payload"])
    except ValueError:
        raise RecordInvalid("signed_payload is not a JSON object") from None
    if not isinstance(signed, dict) or not isinstance(signed.get("metadata"), dict):
        raise RecordInvalid("signed_payload carries no metadata")
    return signed


class Gate:
    def __init__(
        self,
        client: Client,
        store: Store,
        *,
        approval_base_url: str,
        keys: KeyRegistry | None = None,
        clock: Callable[[], float] = time.time,
        not_after_seconds: int = 120,
        configured_secrets: tuple[str, ...] = (),
        require_pq: bool = False,
        allow_classical_only: bool = False,
    ):
        if not 0 < not_after_seconds <= 300:  # Requisition's bound on not_after
            raise ValueError("not_after_seconds must be in (0, 300]")
        self.client = client
        self.store = store
        self.approval_base_url = approval_base_url.rstrip("/")
        self.keys = keys
        self.clock = clock
        self.not_after_seconds = not_after_seconds
        self.configured_secrets = configured_secrets
        self.outcome_records: list[dict] = []  # the signed outcome records, for the offline check
        self.require_pq = require_pq
        # whether a record needs an ML-DSA-87 signature is the pinned key file's statement (it holds an
        # ML-DSA-87 key of the record's signer), not the record's own ``cosign`` claim. ``require_pq`` tightens it
        # to every record; only ``allow_classical_only`` lifts the policy, and it is explicit.
        self.allow_classical_only = allow_classical_only
        if require_pq and keys is None:
            raise ValueError("require_pq needs a pinned key file: an unchecked signature proves nothing")

    def now(self) -> dt.datetime:
        return dt.datetime.fromtimestamp(self.clock(), dt.timezone.utc)

    def approval_url(self, approval_id: str | None) -> str:
        # GET /v1/sanction-requests/:id does not answer the approval request id while pending:
        # until the statement exists, the link is the console's list.
        return f"{self.approval_base_url}/approvals" + (f"/{approval_id}" if approval_id else "")

    # --- propose (deduplicated on act_hash) ----------------------------------------------

    def file_or_find(self, act_type: str, args: dict, *, schema: canonical.ArgsSchema | None = None) -> Sanction:
        canonical.check_arguments(args, self.configured_secrets)
        if schema is not None:
            schema.validate(args, self.configured_secrets)
        act_hash = canonical.act_hash(act_type, args)

        for _attempt in range(2):
            existing = self.store.open_proposal(act_hash)
            if existing is None or existing.get("state") == "filing":
                reserved, record = self.store.reserve_proposal(act_hash, act_type)
                if not reserved:
                    if record.get("state") == "filing":
                        raise RequisitionError("another invocation is filing this proposal; retry")
                    existing = record
                else:
                    try:
                        found = self._lookup_open(act_hash)
                        if found is None:
                            key = idempotency_key_for(act_hash, record["token"])
                            request_id = self.client.propose(act_type, args, idempotency_key=key)["request_id"]
                        else:
                            request_id = found
                    except BaseException:
                        self.store.release_reservation(act_hash, record)
                        raise
                    existing = self.store.record_filed(act_hash, record, request_id)
                    sanction = self._read(existing["request_id"], act_type, act_hash, args)
                    sanction.filed_now = found is None
                    return sanction
            try:
                return self._read(existing["request_id"], act_type, act_hash, args)
            except RequisitionRefused as refusal:
                if refusal.code != "sanction_request_unknown":
                    raise
                # a stored request this caller cannot see (a rebuilt database): leave dedupe, file anew
                self.store.close_proposal(act_hash, existing["request_id"], "sanction_request_unknown")
        raise RequisitionError("could not file or find a sanction request")

    def _lookup_open(self, act_hash: str) -> str | None:
        """A request already filed for this act_hash that can still allow, or None (also
        when the server has no lookup). A refused request, or a sanctioned one whose ``spent`` is not
        stated false, is never adopted: a new call files anew. (The lookup's default already
        leaves spent ones out; this does not rely on it.)"""
        rows = self.client.find_by_act_hash(act_hash)
        if not rows:
            return None
        for wanted in ("sanctioned", "pending"):
            for row in rows:
                if row["status"] != wanted:
                    continue
                if wanted == "sanctioned" and row.get("spent") is not False:
                    continue
                return row["request_id"]
        return None

    def read(self, sanction: Sanction, args: dict) -> Sanction:
        return self._read(sanction.request_id, sanction.act_type, sanction.act_hash, args)

    def _read(self, request_id: str, act_type: str, act_hash: str, args: dict) -> Sanction:
        answer = self.client.get_request(request_id)
        status = answer["status"]
        sanction = Sanction(request_id, act_type, act_hash, status, self.approval_url(None))
        if status == "refused":
            sanction.refused_code = answer.get("refused_code")
            self.store.close_proposal(act_hash, request_id, f"refused:{sanction.refused_code}")
        elif status == "sanctioned":
            envelope = answer.get("statement")
            signed = _signed(envelope)
            md = signed["metadata"]
            if signed.get("receipt_type") != STATEMENT_TYPE:
                raise RecordInvalid("statement record has another receipt_type")
            if answer.get("statement_id") != envelope["receipt_hash"]:
                raise RecordInvalid("statement_id is not the statement's receipt_hash")
            expected = {
                "request_id": request_id,
                "principal": self.client.principal,
                "act_type": act_type,
                "act_hash": act_hash,
                "act_hash_alg": canonical.ACT_HASH_ALG,
                "display_digest": canonical.display_digest(args),
            }
            wrong = [k for k, v in expected.items() if md.get(k) != v]
            if wrong:
                raise RecordInvalid(f"statement does not bind what was proposed: {wrong}")
            reason = self.keys.check(envelope) if self.keys is not None else None
            if reason is not None:
                raise RecordInvalid(f"statement signature does not verify under the pinned lab key ({reason})")
            self._cosigned(answer, envelope, md)
            self._remember(envelope)
            sanction.cosignature = answer.get("cosignature")
            sanction.statement_id = envelope["receipt_hash"]
            sanction.statement = envelope
            sanction.approval_id = md.get("approval_request_id")
            sanction.approval_url = self.approval_url(sanction.approval_id)
            self.store.update_proposal(act_hash, request_id, statement_id=sanction.statement_id)
        return sanction

    # --- execute (idempotent by the stored body) -----------------------------------------

    def execute(self, sanction: Sanction, args: dict, key: str) -> Decision:
        if sanction.status != "sanctioned" or not sanction.statement_id:
            raise RequisitionError("not sanctioned")
        stored = self.store.get("executes", key)
        created = False
        if stored is None:
            not_after = instant(self.now() + dt.timedelta(seconds=self.not_after_seconds))
            body = self.client.execute_body(sanction.act_type, args, sanction.statement_id, key, not_after)
            created, stored = self.store.claim_execute(key, sanction.request_id, body, not_after)
        return self._send(key, stored, args, replayed=not created)

    def replay_stored(self, key: str, args: dict) -> Decision | None:
        """If an execute body is stored under ``key`` (a retry of a call already executed or
        attempted), replay it verbatim and return the decision; else None. Checked BEFORE propose:
        the proposal of an allowed call is closed, so dedupe alone would file a new request for a
        mere retry. A stored body whose ``not_after`` has passed raises StaleExecute."""
        stored = self.store.get("executes", key)
        if stored is None:
            return None
        return self._send(key, stored, args, replayed=True)

    def execute_fresh(self, sanction: Sanction, args: dict, nonce: str) -> Decision:
        """A second execute of the same statement under a NEW nonce (the demo's replay attempt).
        Requisition answers a signed deny ``statement_spent``."""
        return self.execute(sanction, args, nonce)

    def _send(self, key: str, stored: dict, args: dict, *, replayed: bool) -> Decision:
        not_after = parse_instant(stored["not_after"])
        if not_after is None or not_after <= self.now():
            raise StaleExecute("the stored execute body's not_after has passed; refusing to re-sign a new one")
        body = Store.body_of(stored)
        sent = loads_strict(body)
        response = self.client.execute(body)
        decision = self._check_decision(response, sent, args, replayed)
        self.store.record_response(key, response)
        if decision.allowed or decision.code in CLOSING_DENIES:
            self.store.close_proposal(
                sent["act_hash"], stored["request_id"], "spent" if decision.allowed else decision.code
            )
        return decision

    def _check_decision(self, response: dict, sent: dict, args: dict, replayed: bool) -> Decision:
        envelope = response.get("decision")
        signed = _signed(envelope)
        md = signed["metadata"]
        if response.get("receipt_hash") != envelope["receipt_hash"]:
            raise RecordInvalid("response receipt_hash is not the decision's")
        if signed.get("receipt_type") != DECISION_TYPE:
            raise RecordInvalid("decision record has another receipt_type")
        if md.get("verdict") != response.get("verdict") or md.get("code") != response.get("code"):
            raise RecordInvalid("the response's verdict or code is not the signed one")
        bound = ("principal", "act_type", "act_hash", "act_hash_alg", "statement_id", "nonce", "not_after")
        wrong = [k for k in bound if md.get(k) != sent.get(k)]
        if md.get("display_projection_digest") != canonical.display_digest(args):
            wrong.append("display_projection_digest")
        if wrong:
            raise RecordInvalid(f"decision does not bind what was sent: {wrong}")
        checked = False
        if self.keys is not None:
            reason = self.keys.check(envelope)
            if reason is not None:
                raise RecordInvalid(f"decision signature does not verify under the pinned lab key ({reason})")
            checked = True
        pq_checked = self._cosigned(response, envelope, md)
        if md["verdict"] == "allow":
            if md.get("exec_not_after") != response.get("exec_not_after") or parse_instant(md.get("exec_not_after")) is None:
                raise RecordInvalid("an allow without a signed exec_not_after")
        self._remember(envelope)
        return Decision(
            verdict=md["verdict"],
            code=md.get("code"),
            statement_id=md["statement_id"],
            exec_not_after=md.get("exec_not_after"),
            decision=envelope,
            response=response,
            replayed=replayed,
            nonce=md["nonce"],
            signature_checked=checked,
            metadata=md,
            pq_checked=pq_checked,
        )

    def report_outcome(self, decision: Decision, succeeded: bool, result: Any,
                       detail_code: str | None = None) -> str:
        """The outcome record for an allow that was acted on. Returns ``recorded``,
        ``recorded (replayed)``, ``unsupported`` (the server predates the route) or
        ``not recorded: <reason>``. Never raises: the effect has already happened."""
        if not decision.allowed:
            return "not recorded: not an allow"
        digest = result_digest(result)
        try:
            answer = self.client.report_outcome(decision.statement_id, decision.decision["receipt_hash"],
                                                "succeeded" if succeeded else "failed", digest, detail_code)
        except RequisitionRefused as refusal:
            return f"not recorded: {refusal.code} (HTTP {refusal.status})"
        except (RequisitionError, ValueError) as error:
            return f"not recorded: {type(error).__name__}"
        if answer is None:
            return "unsupported"
        record = answer.get("record")
        if not _is_signed_outcome(record, decision):
            return "not recorded: the answer carries no outcome record bound to this allow"
        if self.keys is None:  # F1: an unverified record is never remembered
            return "not recorded: no pinned key file"
        reason = self.keys.check(record)
        if reason is not None:
            return f"not recorded: the outcome record's signature does not verify under the pinned lab key ({reason})"
        try:
            admission = self.store.admit(record)
        except ValueError:
            return "not recorded: the outcome record carries no chain position"
        if not admission.admitted:
            return f"not recorded: {admission.code} (evidence kept)"
        self.outcome_records.append({"record": record, "cosignature": answer.get("cosignature"),
                                     "statement_id": decision.statement_id})
        return "recorded"

    def _cosigned(self, answer: dict, envelope: dict, md: dict) -> bool:
        """True when an ML-DSA-87 signature over this record's bytes was checked here (the record's
        own, or its co-signature). Raises RecordInvalid on any co-signature defect, a stripped
        co-signature, or (``require_pq``) no ML-DSA-87 signature at all."""
        primary_pq = self.keys is not None and self.keys.algorithm(envelope["key_id"]) == "mldsa87"
        cos = answer.get("cosignature")
        cosign = md.get("cosign")
        status = cosign.get("status") if isinstance(cosign, dict) else None
        if cos is None:
            if status == "signed":
                raise RecordInvalid("the record says it is co-signed (cosign.status signed) but no co-signature came: stripped")
            if not primary_pq and (self.require_pq or self._pq_by_policy(envelope)):
                raise RecordInvalid(f"no ML-DSA-87 signature: cosign.status is {status or 'absent'} (post-quantum required"
                                    + ("" if self.require_pq else " by the pinned key file: it holds an ML-DSA-87 key of this signer") + ")")
            return primary_pq
        if not isinstance(cos, dict) or not all(isinstance(cos.get(k), str) for k in ENVELOPE):
            raise RecordInvalid("the co-signature is not a four-field envelope")
        if cos["signed_payload"] != envelope["signed_payload"] or cos["receipt_hash"] != envelope["receipt_hash"]:
            raise RecordInvalid("the co-signature does not cover the record's own bytes")
        if status != "signed" or cos["key_id"] != cosign.get("key_id"):
            raise RecordInvalid("the co-signature's key_id is not the signed cosign.key_id, or cosign.status is not signed")
        if self.keys is None:
            return False
        if self.keys.algorithm(cos["key_id"]) != "mldsa87" or not self.keys.verify(cos):
            raise RecordInvalid("the ML-DSA-87 co-signature does not verify under the pinned key file"
                                f" ({self.keys.check(cos) or 'not an ML-DSA-87 key'})")
        return True

    def _pq_by_policy(self, envelope: dict) -> bool:
        return (self.keys is not None and not self.allow_classical_only and self.keys.pq_expected(envelope))

    # --- F1: the position memory and the claim (fence.py) -------------------------------------------

    def _remember(self, envelope: dict) -> fence.Admission:
        """Every signed record read, after its signature checks: remembered by its signed position; a
        different record at a held position is refused (both kept as evidence). Without a pinned key
        file nothing was verified, so nothing is remembered: refused (fail closed)."""
        if self.keys is None:
            raise RecordInvalid("no pinned key file: an unverified record is never remembered (F1); refused")
        try:
            admission = self.store.admit(envelope)
        except ValueError:
            raise RecordInvalid("the signed record carries no chain position") from None
        if not admission.admitted:
            raise fence.refuse(admission.code)
        return admission

    def claim(self, decision: Decision, info: dict) -> fence.Admission:
        """The one claim before acting on an allow, persisted before the effect: the statement and the
        approval its statement named (as read here). ``.code`` None: act; otherwise never act."""
        return self.store.admit(decision.decision, spend={"statement_id": decision.statement_id,
                                                          "approval_request_id": None, **info})

    def runnable(self, decision: Decision) -> bool:
        """An allow may be acted on only before its signed exec_not_after."""
        until = parse_instant(decision.exec_not_after)
        return decision.allowed and until is not None and self.now() < until
