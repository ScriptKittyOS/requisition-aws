# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A stdlib HTTP client for Requisition's lab ``/v1`` execute API.

Routes:

  POST /v1/sanction-requests       201 {request_id, status: "pending"}
  GET  /v1/sanction-requests/:id   200 {status: pending | sanctioned (+statement_id,
                                        statement_id_label, statement) | refused (+refused_code)}
  POST /v1/execute                 200 a signed decision {verdict, code, decision, decision_receipt_id,
                                        receipt_hash, statement_id, statement_id_label, exec_not_after}
  GET  /v1/keys                    200 the lab key file, byte for byte, no credential

Body shapes, from the code (an argument row, ``act_hash_derivation: args_sha384``):

* propose:
  ``{"principal", "act_type", "act_hash", "act_hash_alg": "sha384+canonical_payload.v3",
  "display": <the arguments object>}``; optional ``class``, ``exp``; ``arm_statement_id`` is refused
  on a row with no ``arm_link``. No nonce, no idempotency key.
* execute:
  ``{"principal", "act_type", "act_hash", "act_hash_alg", "display_projection": <the same arguments
  object>, "statement_id", "nonce", "not_after"}``. ``nonce`` matches ``[A-Za-z0-9_-]{1,128}``;
  ``not_after`` is ``YYYY-MM-DDTHH:MM:SSZ`` in ``(now, now + 300 s]``.
  The nonce claim is unique per (caller, nonce) and holds
  the SHA-256 of the body's canonical bytes: the same body
  again is the exact retry (the stored decision); a different body is
  ``nonce_reused_with_different_body`` (409).
* every refusal before a decision is ``{"error": <code>}`` with the code's HTTP status;
  signed denies come back 200 with ``verdict: "deny"``.

Additions not in the Requisition version of 2026-10-26 (their shapes are the planned ones, not read from code):

* ``GET /v1/sanction-requests?act_hash=<hex>`` 200 ``{"requests": [{request_id, status,
  statement_id?, refused_code?, spent}]}``, the caller's own, newest first, at most 20; a spent one is
  left out unless ``include_spent=true``. Read only: a co-approved request reads
  ``pending`` until ``GET .../:id`` mints the statement;
* ``idempotency_key`` on propose, form ``[A-Za-z0-9_-]{1,128}``: the same key and body replays the
  first answer; the same key with another body is 409 ``idempotency_key_reused_with_different_body``;
* ``POST /v1/outcomes`` ``{principal, statement_id, decision_receipt_hash, outcome: succeeded |
  failed, result_digest (sha256 hex of the tool's result bytes), detail_code?}`` 200 ``{"record":
  <a requisition.lab.outcome.v0 envelope>, "cosignature"?}``; an exact retry answers the stored
  record; another report 409 ``outcome_already_recorded``; no matching allow 404
  ``outcome_decision_unknown``;
* an agent-tool record may carry ``cosignature`` beside it: the ML-DSA-87 co-signature's four-field
  envelope over the SAME signed bytes, announced by the signed ``metadata.cosign``.

Detection: that version answers ``GET /v1/sanction-requests`` (with or without a query)
405 ``method_not_allowed`` (a known path under another method) and
``POST /v1/outcomes`` 404 ``route_unknown``. Either answer means "not
supported": the client remembers it and falls back to today's behaviour (no ``idempotency_key``,
no lookup, no outcome). ``idempotency_key`` is sent only after the lookup route answered 200, since
today's propose refuses an unknown member (``member_out_of_schema``).

The bearer credential is sent only in the Authorization header and never logged or stored.
"""

from __future__ import annotations

import datetime as _dt
import http.client
import ipaddress
import json
import math
import re
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any

from . import canonical

NONCE_FORM = re.compile(r"\A[A-Za-z0-9_-]{1,128}\Z")  # the nonce form Requisition accepts at execute
INSTANT_FORM = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")  # Requisition's instant form
UUID_FORM = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
NOT_AFTER_WINDOW = 300  # seconds: Requisition's bound on not_after
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
HEX96 = re.compile(r"\A[0-9a-f]{96}\Z")
# the answers that mean "this server predates the route" (the Requisition version of 2026-10-26)
UNSUPPORTED = {(404, "route_unknown"), (405, "method_not_allowed")}
OUTCOMES = ("succeeded", "failed")


class RequisitionError(Exception):
    """Base class: every subclass means "do not run the tool"."""


class RequisitionUnavailable(RequisitionError):
    """Unreachable, timed out, a 5xx, or an answer that is not the documented JSON: fail closed."""


class RequisitionRefused(RequisitionError):
    """An unsigned step-0 refusal: ``{"error": code}`` with a 4xx status."""

    def __init__(self, code: str, status: int, body: Any = None):
        super().__init__(f"Requisition refused: {code} (HTTP {status})")
        self.code = code
        self.status = status
        self.body = body


def instant(t: _dt.datetime) -> str:
    """The spec's instant spelling."""
    return t.astimezone(_dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_instant(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str) or not INSTANT_FORM.match(value):
        return None
    return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate member in a Requisition answer")
    return dict(pairs)


def _no_constant(name: str):
    raise ValueError(f"{name} is not JSON (RFC 8259 section 6)")


def _finite_float(lexeme: str) -> float:
    value = float(lexeme)
    if not math.isfinite(value):  # 1e400: a valid lexeme, never an infinite float in the program
        raise ValueError("a number outside the double range (RFC 8259 section 9 limit)")
    return value


MAX_DEPTH = 64  # containers; the 65th is refused (requisition-ts src/json.ts MAX_DEPTH; Requisition's bounded JSON reader has the same bound)
MAX_INTEGER = 9_007_199_254_740_991  # CanonicalPayload v3's integer range (canonical.MAX_INTEGER)


def _check_depth(text):
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting deeper than %d" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1


def _bounded_int(lexeme):
    value = int(lexeme)
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        raise ValueError("an integer outside +-(2^53-1), the canonical form's range")
    return value


def loads_strict(data: bytes | str) -> Any:
    """RFC 8259 JSON text, refusing what Python's json accepts beyond it (requisition-ts
    src/json.ts is the same reader):
    * duplicate members (Requisition refuses them inbound too);
    * NaN, Infinity and -Infinity (RFC 8259 section 6), and any number whose value is not a finite double;
    * bytes that are not UTF-8 (section 8.1): never Python's UTF-16/UTF-32 detection nor its surrogatepass
      decoding of an encoded surrogate; a byte order mark is refused (json.loads refuses U+FEFF in text);
    * nesting deeper than MAX_DEPTH (64) containers, and an integer outside +-(2^53-1), the range CanonicalPayload v3
      allows (one bound, the same in requisition-ts and in Requisition's bounded JSON reader).
    Every refusal is a ValueError (never a RecursionError)."""
    return _loads(data, _bounded_int)


def _finite_int(lexeme):
    value = int(lexeme)
    try:
        float(value)
    except OverflowError:  # as a double it is infinite: refused, as requisition-ts's reader refuses it
        raise ValueError("an integer outside the double range (RFC 8259 section 9 limit)") from None
    return value


def loads_tool_call(data: bytes | str) -> Any:
    """A caller's tool-call body (an MCP or JSON-RPC message): ``loads_strict`` WITHOUT the integer bound, so an
    integer outside +-(2^53-1) in the arguments reaches intake, which answers ``malformed_member`` as Requisition does
    (requisition-ts's ``parseStrict`` keeps such an integer the same way). Everything else ``loads_strict`` refuses is
    refused here too, and an integer that is not a finite double. Only the two tool-call body reads use it; every read
    that used ``loads_strict`` before keeps it (tests/test_tool_call_reader.py pins both by call site)."""
    return _loads(data, _finite_int)


def _loads(data, parse_int):
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")  # strict: UnicodeDecodeError is a ValueError
    _check_depth(data)
    return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_float=_finite_float, parse_int=parse_int)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def plaintext_allowed(host: str, allow_private: bool) -> bool:
    """Plain http carries the bearer credential and every answer in the clear. Allowed only to loopback, or, with ``allow_private`` (REQUISITION_ALLOW_PLAINTEXT_PRIVATE=1,
    the VPC case), to a private or link-local IP LITERAL: a name could resolve anywhere."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    return allow_private and (ip.is_private or ip.is_link_local) and not ip.is_global


@dataclass
class Client:
    """``base_url`` such as ``https://requisition.example`` (``http://`` only to loopback, or to a
    private IP literal with ``allow_plaintext_private``). ``unix_socket``: once Requisition's socket is
    configured, ``/v1`` answers only on it; pass its path then."""

    base_url: str
    credential: str
    principal: str
    timeout: float = 10.0
    unix_socket: str | None = None
    allow_plaintext_private: bool = False

    def __post_init__(self):
        self.features: dict[str, bool] = {}  # "lookup", "outcomes": learned from the server's answers
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be http(s)://host[:port]")
        if parsed.scheme == "http" and not self.unix_socket and \
                not plaintext_allowed(parsed.hostname, self.allow_plaintext_private):
            raise ValueError("base_url must be https unless the host is loopback (or a private IP literal "
                             "with REQUISITION_ALLOW_PLAINTEXT_PRIVATE=1): plain http carries the credential")
        self._parsed = parsed
        if not isinstance(self.credential, str) or not self.credential:
            raise ValueError("a caller credential is required")
        if not isinstance(self.principal, str) or not self.principal:
            raise ValueError("a principal id is required")

    def __repr__(self) -> str:  # never print the credential
        return f"Client(base_url={self.base_url!r}, principal={self.principal!r}, credential=<elided>)"

    # --- transport -----------------------------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        if self.unix_socket:
            return _UnixHTTPConnection(self.unix_socket, self.timeout)
        cls = http.client.HTTPSConnection if self._parsed.scheme == "https" else http.client.HTTPConnection
        return cls(self._parsed.hostname, self._parsed.port, timeout=self.timeout)

    def _request(self, method: str, path: str, body: bytes | None = None, auth: bool = True):
        headers = {"accept": "application/json"}
        if auth:
            headers["authorization"] = "Bearer " + self.credential
        if body is not None:
            headers["content-type"] = "application/json"
        prefix = self._parsed.path.rstrip("/")
        try:
            conn = self._connection()
            try:
                conn.request(method, prefix + path, body=body, headers=headers)
                resp = conn.getresponse()
                status, raw = resp.status, resp.read()
            finally:
                conn.close()
        except (OSError, http.client.HTTPException) as error:
            raise RequisitionUnavailable(f"Requisition unreachable: {type(error).__name__}") from None
        return status, raw

    def _json(self, method: str, path: str, body: bytes | None, ok: int) -> dict:
        status, raw = self._request(method, path, body)
        try:
            parsed = loads_strict(raw)
        except ValueError:
            raise RequisitionUnavailable(f"Requisition answered HTTP {status} with no JSON object") from None
        if not isinstance(parsed, dict):
            raise RequisitionUnavailable(f"Requisition answered HTTP {status} with no JSON object")
        if status == ok:
            return parsed
        code = parsed.get("error") if isinstance(parsed.get("error"), str) else "unknown"
        if status >= 500:
            raise RequisitionUnavailable(f"Requisition unavailable: {code} (HTTP {status})")
        raise RequisitionRefused(code, status, parsed)

    # --- the routes ----------------------------------------------------------------------------

    def propose_body(self, act_type: str, args: dict, *, class_: str | None = None,
                     idempotency_key: str | None = None) -> bytes:
        """The propose body's bytes for an argument row; with
        ``idempotency_key`` only when the server is known to take it."""
        body = {
            "principal": self.principal,
            "act_type": act_type,
            "act_hash": canonical.act_hash(act_type, args),
            "act_hash_alg": canonical.ACT_HASH_ALG,
            "display": args,
        }
        if class_ is not None:
            body["class"] = class_
        if idempotency_key is not None:
            if not HEX64.match(idempotency_key):
                raise ValueError("idempotency_key must be 64 lower-case hex")
            body["idempotency_key"] = idempotency_key
        return canonical.encode(body)

    def propose(self, act_type: str, args: dict, *, class_: str | None = None,
                idempotency_key: str | None = None) -> dict:
        if not self.features.get("lookup"):
            idempotency_key = None  # an older server refuses the member (member_out_of_schema)
        body = self.propose_body(act_type, args, class_=class_, idempotency_key=idempotency_key)
        answer = self._json("POST", "/v1/sanction-requests", body, 201)
        request_id = answer.get("request_id")
        if not isinstance(request_id, str) or not UUID_FORM.match(request_id) or answer.get("status") != "pending":
            raise RequisitionUnavailable("propose answered without a request id")
        return answer

    def get_request(self, request_id: str) -> dict:
        if not isinstance(request_id, str) or not UUID_FORM.match(request_id):
            raise ValueError("request_id is not a UUID")
        answer = self._json("GET", "/v1/sanction-requests/" + request_id, None, 200)
        if answer.get("status") not in ("pending", "sanctioned", "refused"):
            raise RequisitionUnavailable("sanction request answered an unknown status")
        return answer

    def execute_body(
        self, act_type: str, args: dict, statement_id: str, nonce: str, not_after: str
    ) -> bytes:
        """The execute body's bytes. Stored and replayed verbatim on retry."""
        if not NONCE_FORM.match(nonce or ""):
            raise ValueError("nonce must match [A-Za-z0-9_-]{1,128}")
        if parse_instant(not_after) is None:
            raise ValueError("not_after must be YYYY-MM-DDTHH:MM:SSZ")
        return canonical.encode(
            {
                "principal": self.principal,
                "act_type": act_type,
                "act_hash": canonical.act_hash(act_type, args),
                "act_hash_alg": canonical.ACT_HASH_ALG,
                "display_projection": args,
                "statement_id": statement_id,
                "nonce": nonce,
                "not_after": not_after,
            }
        )

    def execute(self, body: bytes) -> dict:
        answer = self._json("POST", "/v1/execute", body, 200)
        if answer.get("verdict") not in ("allow", "deny") or not isinstance(answer.get("decision"), dict):
            raise RequisitionUnavailable("execute answered without a signed decision")
        return answer

    # --- the newer routes, behind the feature check ---------------------------------------------------------

    def _optional(self, feature: str, method: str, path: str, body: bytes | None, ok: tuple[int, ...]):
        """None when the server predates the route (remembered); else the answer; else raise."""
        if self.features.get(feature) is False:
            return None
        status, raw = self._request(method, path, body)
        try:
            parsed = loads_strict(raw)
        except ValueError:
            raise RequisitionUnavailable(f"Requisition answered HTTP {status} with no JSON object") from None
        if not isinstance(parsed, dict):
            raise RequisitionUnavailable(f"Requisition answered HTTP {status} with no JSON object")
        code = parsed.get("error") if isinstance(parsed.get("error"), str) else "unknown"
        if (status, code) in UNSUPPORTED:
            self.features[feature] = False
            return None
        if status in ok:
            self.features[feature] = True
            return parsed
        if status >= 500:
            raise RequisitionUnavailable(f"Requisition unavailable: {code} (HTTP {status})")
        raise RequisitionRefused(code, status, parsed)

    def find_by_act_hash(self, act_hash: str) -> list[dict] | None:
        """The act_hash lookup (spent requests left out, its default). None: the server has no such route
        (fall back to the local store)."""
        if not isinstance(act_hash, str) or not HEX96.match(act_hash):
            raise ValueError("act_hash is not 96 lower-case hex (sha384)")
        answer = self._optional("lookup", "GET", "/v1/sanction-requests?act_hash=" + act_hash, None, (200,))
        if answer is None:
            return None
        rows = answer.get("requests") if "requests" in answer else [answer]
        if not isinstance(rows, list):
            raise RequisitionUnavailable("the act_hash lookup answered without a requests list")
        out = []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("request_id"), str) \
                    or not UUID_FORM.match(row["request_id"]) \
                    or row.get("status") not in ("pending", "sanctioned", "refused"):
                raise RequisitionUnavailable("the act_hash lookup answered a malformed request")
            out.append(row)
        return out

    def outcome_body(self, statement_id: str, receipt_hash: str, outcome: str, result_digest: str,
                     detail_code: str | None = None) -> bytes:
        if outcome not in OUTCOMES:
            raise ValueError("outcome must be succeeded or failed")
        if not HEX64.match(result_digest or "") or not HEX64.match(receipt_hash or ""):
            raise ValueError("result_digest and receipt_hash are 64 lower-case hex")
        body = {"principal": self.principal, "statement_id": statement_id, "decision_receipt_hash": receipt_hash,
                "outcome": outcome, "result_digest": result_digest}
        if detail_code is not None:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", detail_code):
                raise ValueError("detail_code must be a short snake_case code")
            body["detail_code"] = detail_code
        return canonical.encode(body)

    def report_outcome(self, statement_id: str, receipt_hash: str, outcome: str, result_digest: str,
                       detail_code: str | None = None) -> dict | None:
        """``POST /v1/outcomes``: the answer (``record``, ``cosignature``?). None: the server
        has no such route."""
        body = self.outcome_body(statement_id, receipt_hash, outcome, result_digest, detail_code)
        return self._optional("outcomes", "POST", "/v1/outcomes", body, (200, 201))

    def keys(self) -> bytes:
        """``GET /v1/keys``: the lab key file's bytes. No credential is sent."""
        status, raw = self._request("GET", "/v1/keys", None, auth=False)
        if status != 200:
            raise RequisitionUnavailable(f"GET /v1/keys answered HTTP {status}")
        return raw
