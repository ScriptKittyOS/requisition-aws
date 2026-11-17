# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""An AWS Lambda handler for an AgentCore Gateway REQUEST interceptor (MCP targets), gating every
``tools/call`` on Requisition's signed allow for its exact arguments.

AWS's documented contract (fetched 2026-11-09, read-only; tested against fixtures built from it,
never against a live Gateway):

* input (gateway-interceptors-types.html, "Request interceptor input payload"):
  ``{"interceptorInputVersion": "1.0", "mcp": {"rawGatewayRequest": {"body": "<raw>"},
  "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "headers": {...}, "body": {jsonrpc}}}}``;
  ``headers`` only when ``passRequestHeaders`` is true (gateway-interceptors-configuration.html:
  default false). A RESPONSE invocation adds ``gatewayResponse``.
* output: ``{"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": ...}}}``
  to pass the request on, or ``{"mcp": {"transformedGatewayResponse": {"statusCode", "body"}}}``, which
  the Gateway answers immediately ("even if transformedGatewayRequest is also provided").
* tool names are ``${target_name}___${tool_name}`` (gateway-tool-naming.html).
* "The gateway may retry requests to interceptor Lambda functions in case of failures or timeouts"
  (gateway-interceptors.html, security best practices 3): every Requisition call here is idempotent
  through the store.

Behaviour:

* deny by default: ``initialize``, ``ping`` and ``notifications/*`` (the legacy
  handshake; 2026-07-28 removes them), ``tools/list`` (the catalog) and ``server/discover`` (a MUST in
  2026-07-28) pass through untouched; any other non-``tools/call`` method is JSON-RPC -32601.
* a header that contradicts the body (``Mcp-Method``; ``Mcp-Name`` after the ``=?base64?…?=``
  sentinel is decoded) is 400 ``-32020`` HeaderMismatch (transports/streamable-http#server-validation).
* ``tools/call`` of an unregistered tool: a ``CallToolResult`` with ``isError: true`` (denied).
* a registered tool marked drifted at listing (G2, below): ``isError`` naming ``catalog_drift`` or
  ``catalog_unencodable``; nothing is proposed.
* a gated ``tools/call`` carrying MRTR ``inputResponses`` or ``requestState`` (2026-07-28): refused
  ``mrtr_input_unsigned`` (the act hashes only ``arguments``; that input would reach the tool unsigned).
* registered: dedupe/propose; not yet sanctioned: ``isError: true`` "awaiting approval <request id>";
  refused: ``isError: true``; sanctioned: execute (the stored body replayed on a retry); a signed
  ``deny``: ``isError: true`` naming the code.
* a signed ``allow`` passes the request through unchanged ONLY IF: its signature (and, by default,
  its ML-DSA-87 co-signature) was checked here against the pinned key file, it is before its signed
  ``exec_not_after`` (checked on EVERY allow, replayed or not), and this statement has not passed
  through before. **At most one pass-through per statement, always**: a durable "passed" mark is
  written to the store (a conditional write) BEFORE the pass-through is returned; any later
  invocation that resolves to the same statement (a client reusing its JSON-RPC id, a Gateway
  retry, anything) is ``isError`` "this approval was already used; a new call needs a new approval".
  Requisition answers an exact execute retry with the stored allow and no spend check
  (``execute.ex:606-642``), so this mark is the only thing that stops a replay.
* malformed input, Requisition unreachable or any internal error: a JSON-RPC ``error`` with code
  ``FAIL_CLOSED`` (-31000, outside the JSON-RPC reserved range -32768..-32000, as MCP 2026-07-28
  basic/#error-codes asks of new codes). The JSON-RPC ``id`` is echoed.

THE CALLER (G1; caller.py): the source is configuration,
``REQUISITION_CALLER_SOURCE``:

* ``legacy_session`` (the DEFAULT, the pre-G1 behaviour, until one live call measures which headers
  the Gateway forwards under AWS_IAM): the raw ``Mcp-Session-Id`` is the arguments object's
  ``session`` and part of the call key ``sha256(gateway id | Mcp-Session-Id | JSON-RPC id | act_hash)``.
* ``sigv4`` / ``jwt``: the caller key is the SigV4 access-key id of the forwarded ``Authorization``
  (or a JWKS-verified JWT's ``iss|sub``); the signed ``session`` is ``caller_session(caller key,
  client id)`` (the client's own id: ``Mcp-Session-Id`` on a legacy request,
  ``params._meta["requisition/session"]`` on a 2026-07-28 one, whose ``Mcp-Session-Id`` is ignored);
  the call key is ``sha256(gateway id | caller key | JSON-RPC id | act_hash)``. A rotated credential
  between the pending call and the re-call is a new act: pending again (availability, never a
  second run).
* no caller key (no header, passRequestHeaders false, an unverifiable token): ``FAIL_CLOSED`` with
  ``data.code = "caller_identity_absent"``. Every ``tools/call`` logs the request's header NAMES
  (never a value), so one live call measures what arrives.

The gateway id comes from the Lambda's configured environment (``REQUISITION_GATEWAY_ID``, set at
deploy), not ``GATEWAY_ARN`` (documented for HTTP targets only).

TOOL DEFINITIONS (G2; catalog.py): a v2 act type pins the approved tool digests. At REQUEST the
arguments carry this form's pin. At RESPONSE on ``tools/list`` (an interception point the deployed
gateway does not have yet: deploy/gateway/g12-change-set.sh adds it), a registered tool whose
listed definition does not hash to its pin is withheld and MARKED in the store (gateway id, tool
name and pin: ``catalog.mark_key``, so a re-pin is not blocked; a mark from before the pin was in the
key still refuses); a later call to a marked tool, by name or from a cached listing, is refused, and a
marked tool is withheld from every listing, even one whose definition matches again. A listing the
check cannot read (``tools`` not a list, an entry not an object) is ``FAIL_CLOSED``
``catalog_unreadable``. A registered tool absent from one listing is not marked (tools/list pages).
Only the operator clears a mark (``python -m requisition_aws.catalog --clear-mark <gateway-id> <tool>``);
clearing approves nothing: the tool waits ``catalog_recheck_pending`` (a call is refused)
until the next listing re-checks it (still drifted: re-marked; the registered definition: served).
Marks are per Lambda environment until the store is durable.

Configuration refuses to start (every call then fails closed) without ``REQUISITION_KEYS_FILE``, or
with a plain-http ``REQUISITION_URL`` to anything but loopback (a private IP literal only with
``REQUISITION_ALLOW_PLAINTEXT_PRIVATE=1``). ``REQUISITION_REQUIRE_PQ`` defaults to on.

LIMITS (stated, not hidden):

* A Gateway retry after a timed-out FIRST pass-through is refused (fail closed): the approval may be
  lost and the agent must file again. Only the target form binds spend to effect.
* A statement spent here stays spent even if AgentCore Policy then denies or the target fails.
* The local file store is per execution environment; a deployment needs a durable conditional-write store, or
  the "passed" mark is per Lambda environment only. The same holds for F1's position memory and
  approval-keyed spend (fence.py): the deployed Lambda makes NO rollback claim (its /tmp store does
  not survive a new environment) until its store is durable; the claim holds for a local run whose
  store survives.
* F1: every signed record read enters the store's position memory (a different record
  at a held position: ``authority_equivocated``, both kept as evidence), and the pass-through claim
  covers the statement and the signed ``approval_request_id`` it names (a re-minted statement for an
  approval already passed through: ``approval_already_used``).
* Anyone with ``UpdateGateway`` can remove the interceptor, and then calls leave no record.
* The caller key under ``sigv4`` is what the Gateway authenticated, not anything this function can
  check: any principal in the account holding ``lambda:InvokeFunction`` on this function can invoke
  it directly with a forged header. The change set adds a Lambda permission scoped to the Gateway
  (``SourceArn``), but a Lambda permission only ADDS an allow: in one account, a principal whose
  identity policy allows invoke is not stopped by it. Gateway-only invoke also needs every other
  invoke grant removed, or an SCP or permissions boundary that denies it.
* An access-key id names a credential, not a principal: one principal holding two keys is two
  callers (fail closed), and temporary keys rotate.
* Under ``legacy_session`` the session is the Gateway's (or a 2026-07-28 client's own) text, not an
  identity: the pre-G1 limit, kept until the caller source is measured live.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import logging
import os
import re
import time
from typing import Any, Callable

from . import canonical, catalog, fence
from .caller import JwtCaller, LegacySessionCaller, SigV4Caller, caller_session, header, header_values
from .client import Client, RequisitionError, RequisitionRefused, RequisitionUnavailable, loads_strict, loads_tool_call
from .gate import Gate, StaleExecute, arguments_object
from .keys import KeyRegistry
from .registry import ToolRegistry
from .store import Store, idempotency_key

log = logging.getLogger(__name__)
# The Lambda Python runtime leaves the root logger at WARNING unless an application log level is
# configured (awslambdaric bootstrap.py:455-477). This module's own INFO level
# lets the header-names line (the live measurement of which headers arrive) reach the runtime's root handler.
log.setLevel(logging.INFO)

VERSION = "1.0"
# deny by default: each justified from the spec (MCP 2025-11-25 lifecycle for initialize/ping/
# notifications; 2026-07-28 changelog 3 for server/discover); none reaches a tool's effect
PASS_METHODS = {"initialize", "ping", "tools/list", "server/discover"}
SESSION_HEADER = "mcp-session-id"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
CLIENT_SESSION_META = "requisition/session"
CLIENT_SESSION_FORM = re.compile(r"\A[A-Za-z0-9._:-]{1,64}\Z")
MRTR_MEMBERS = ("inputResponses", "requestState")
CALLER_SOURCES = ("legacy_session", "sigv4", "jwt")

# JSON-RPC 2.0 error codes (jsonrpc.org/specification 5.1), MCP's HeaderMismatch, and our refusal code
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
FAIL_CLOSED = -31000  # outside -32768..-32000 (MCP 2026-07-28 basic/#error-codes)
UNAVAILABLE = FAIL_CLOSED  # the old name, kept for the code paths that used it


def _out_request(body: Any) -> dict:
    return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayRequest": {"body": body}}}


def _out_response(body: dict, status: int = 200) -> dict:
    return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayResponse": {"statusCode": status, "body": body}}}


def rpc_error(rpc_id: Any, code: int, message: str, data: Any = None, status: int = 200) -> dict:
    error: dict = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return _out_response({"jsonrpc": "2.0", "id": rpc_id, "error": error}, status)


def tool_error(rpc_id: Any, text: str, meta: dict | None = None) -> dict:
    result: dict = {"content": [{"type": "text", "text": text}], "isError": True}
    if meta:
        result["_meta"] = {"requisition": meta}
    return _out_response({"jsonrpc": "2.0", "id": rpc_id, "result": result})


USED = "Requisition: this approval was already used; a new call needs a new approval"
CREDENTIAL_EXPIRED = "caller_credential_expired"


class _CredentialExpired(Exception):
    """Raised out of the first attempt only: Requisition refused the cached credential as expired."""


def _decode_header_value(value: str) -> str | None:
    """The =?base64?...?= sentinel (transports/streamable-http#value-encoding), else the value."""
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
    return value


class Interceptor:
    def __init__(self, gate: Gate, registry: ToolRegistry, *, gateway_id: str, agent_name: str,
                 caller: LegacySessionCaller | SigV4Caller | JwtCaller | None = None,
                 credential_source: Callable[[], str] | None = None, reread_interval: float = 60.0,
                 monotonic: Callable[[], float] = time.monotonic):
        """``credential_source``: reads the caller credential FRESH from where it is kept (the deployed
        entry: Secrets Manager, its cache bypassed). On ``caller_credential_expired`` the invocation re-reads
        it once and retries once; at most one re-read per ``reread_interval`` seconds per environment."""
        if not gateway_id:
            raise ValueError("gateway_id is required (REQUISITION_GATEWAY_ID)")
        if gate.keys is None:
            raise ValueError("a pinned key file is required (REQUISITION_KEYS_FILE): an allow whose signature "
                             "was not checked here is never passed through")
        for name in registry.names():
            binding = registry.get(name)
            if binding.pinned_digests and binding.pin is None:
                raise ValueError(f"tool {name!r}: its act type pins several tool digests; name the one this "
                                 "gateway sends (REQUISITION_TOOLS {\"act_type\", \"tool_digest\"})")
        self.gate = gate
        self.registry = registry
        self.gateway_id = gateway_id
        self.agent_name = agent_name
        self.caller = caller if caller is not None else LegacySessionCaller()
        if not (isinstance(reread_interval, (int, float)) and reread_interval > 0):
            raise ValueError("reread_interval must be a positive number of seconds")
        self.credential_source = credential_source
        self.reread_interval = float(reread_interval)
        self.monotonic = monotonic
        self._last_reread: float | None = None

    def handle(self, event: Any) -> dict:
        rpc_id = None
        try:
            if isinstance(event, dict) and "http" in event and "mcp" not in event:
                return self._http_target()
            if not isinstance(event, dict) or event.get("interceptorInputVersion") != VERSION:
                return rpc_error(None, INVALID_REQUEST, "unsupported interceptor input")
            mcp = event.get("mcp")
            if not isinstance(mcp, dict):
                return rpc_error(None, INVALID_REQUEST, "no mcp payload")
            if mcp.get("gatewayResponse") is not None:
                return self._response(mcp)
            request = mcp.get("gatewayRequest")
            body = request.get("body") if isinstance(request, dict) else None
            if not isinstance(body, dict):
                return rpc_error(None, INVALID_REQUEST, "no JSON-RPC request body")
            rpc_id = body.get("id")
            if body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
                return rpc_error(rpc_id, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
            if not self._raw_matches(mcp, body):
                return rpc_error(rpc_id, INVALID_REQUEST, "the raw request body does not match the parsed one")
            method = body["method"]
            mismatch = self._header_mismatch(request, body)
            if mismatch:
                return rpc_error(rpc_id, HEADER_MISMATCH, f"Header mismatch: {mismatch}", status=400)
            if method in PASS_METHODS or method.startswith("notifications/"):
                return _out_request(body)
            if method != "tools/call":
                return rpc_error(rpc_id, METHOD_NOT_FOUND, f"method {method!r} is not permitted by the Requisition interceptor")
            return self._tools_call(request, body, rpc_id)
        except Exception as error:  # noqa: BLE001 - fail closed, never pass through on an error
            log.error("requisition interceptor failed closed: %s", type(error).__name__)
            return rpc_error(rpc_id, UNAVAILABLE, "Requisition check failed; the call is refused (fail closed)")

    # --- RESPONSE: the listing check (G2) ----------------------------------------------------------

    def _response(self, mcp: dict) -> dict:
        response = mcp["gatewayResponse"]
        status, body = response.get("statusCode", 200), response.get("body")
        request = mcp.get("gatewayRequest")
        request_body = request.get("body") if isinstance(request, dict) else None
        listing = (isinstance(request_body, dict) and request_body.get("method") == "tools/list"
                   and isinstance(body, dict) and isinstance(body.get("result"), dict) and "tools" in body["result"])
        if listing:
            checked = self._check_listing(body)
            if checked is not None:
                return checked
        # anything else (a signed refusal included) passes as is
        return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayResponse": {
            "statusCode": status, "body": body}}}

    def _check_listing(self, body: dict) -> dict | None:
        tools = body["result"]["tools"]
        if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools):
            return rpc_error(body.get("id"), FAIL_CLOSED, "Requisition: the tools/list result cannot be read; "
                             "refused (fail closed)", {"code": "catalog_unreadable"})
        kept, withheld = [], []
        for definition in tools:
            binding = self.registry.get(definition.get("name"))
            if binding is None or not binding.pinned_digests:
                kept.append(definition)
                continue
            try:
                code = None if catalog.tool_digest(definition) == binding.pin else "catalog_drift"
            except catalog.CatalogRefusal as refusal:
                code = refusal.code
            if code is None:
                marked = self._recheck(binding)
                if marked is None:
                    kept.append(definition)
                else:  # a mark stands until the operator clears it, even when the definition matches again
                    withheld.append({"name": binding.tool_name, "code": marked})
                continue
            self._mark(binding.tool_name, binding.pin, code)
            withheld.append({"name": binding.tool_name, "code": code})
        if not withheld:
            return None
        out = copy.deepcopy(body)
        out["result"]["tools"] = kept
        meta = out["result"].setdefault("_meta", {})
        meta["requisition"] = {**(meta.get("requisition") or {}), "withheld": withheld}
        return {"interceptorOutputVersion": VERSION, "mcp": {"transformedGatewayResponse": {
            "statusCode": 200, "body": out}}}

    def _mark_keys(self, tool_name: str, pin: str) -> tuple[str, str]:
        """This pin's mark key, then the key a mark had before the pin was in it (still honoured)."""
        return catalog.mark_key(self.gateway_id, tool_name, pin), catalog.legacy_mark_key(self.gateway_id, tool_name)

    def _mark(self, tool_name: str, pin: str, code: str) -> None:
        key = catalog.mark_key(self.gateway_id, tool_name, pin)
        current = self.gate.store.get("catalog_marks", key)
        if current is None or current.get("code") != code:
            self.gate.store.compare_and_set("catalog_marks", key, current,
                                            {"gateway_id": self.gateway_id, "tool": tool_name, "pin": pin,
                                             "code": code, "marked_at": self.gate.clock()})

    def _marked(self, binding: Any) -> str | None:
        """The code that refuses ``binding``'s tool (a mark, or a pending re-check), or None."""
        for key in self._mark_keys(binding.tool_name, binding.pin):
            mark = self.gate.store.get("catalog_marks", key)
            if isinstance(mark, dict) and isinstance(mark.get("code"), str):
                return mark["code"]
        return None

    def _recheck(self, binding: Any) -> str | None:
        """A listing showed the registered definition: a pending re-check (the operator cleared the mark) is
        resolved, so the tool is served; a mark that stands is returned (the tool stays withheld)."""
        for key in self._mark_keys(binding.tool_name, binding.pin):
            mark = self.gate.store.get("catalog_marks", key)
            if isinstance(mark, dict) and mark.get("code") == catalog.RECHECK_PENDING:
                self.gate.store.compare_and_set("catalog_marks", key, mark, None)
        return self._marked(binding)

    # --- request metadata --------------------------------------------------------------------------

    @staticmethod
    def _header_mismatch(request: Any, body: dict) -> str | None:
        """A present ``Mcp-Method`` / ``Mcp-Name`` header that contradicts the body (2026-07-28
        transports/streamable-http#server-validation). This function routes on the body only; a
        contradicting header is refused so no component downstream can trust it either."""
        headers = request.get("headers") if isinstance(request, dict) else None
        for name in ("mcp-method", "mcp-name"):
            if len(header_values(headers, name)) > 1:
                return f"more than one {name} header"
        method = header(headers, "mcp-method")
        if method is not None and method != body["method"]:
            return "Mcp-Method does not match the body"
        name = header(headers, "mcp-name")
        if name is not None and body["method"] in ("tools/call", "prompts/get", "resources/read"):
            params = body.get("params") if isinstance(body.get("params"), dict) else {}
            want = params.get("uri") if body["method"] == "resources/read" else params.get("name")
            if _decode_header_value(name) != want:
                return "Mcp-Name does not match the body"
        return None

    @staticmethod
    def _raw_matches(mcp: dict, body: dict) -> bool:
        raw = mcp.get("rawGatewayRequest")
        if raw is None:
            return True
        if not isinstance(raw, dict) or not isinstance(raw.get("body"), str):
            return False
        try:
            parsed = loads_tool_call(raw["body"])  # duplicate members in the raw body are refused; intake judges the arguments
        except ValueError:
            return False
        # typed: 1, 1.0 and true are three different requests (Python's == says equal)
        typed = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"))  # noqa: E731
        return typed(parsed) == typed(body)

    @staticmethod
    def _http_target() -> dict:
        body = json.dumps({"error": "requisition_interceptor_serves_mcp_targets_only"}).encode()
        return {"interceptorOutputVersion": VERSION, "http": {"transformedGatewayResponse": {
            "statusCode": 403, "contentType": "application/json", "body": base64.b64encode(body).decode()}}}

    def _session_id(self, request: dict) -> str | None:
        """The one ``Mcp-Session-Id``, or None: absent, empty, not a string, or two case variants (never the
        first one; caller.header's rule)."""
        return header(request.get("headers"), SESSION_HEADER) or None

    def _caller(self, request: dict, params: dict, rpc_id: Any) -> tuple[str, str] | dict:
        """``(the signed session, the call key's caller part)``, or a FAIL_CLOSED refusal."""
        if isinstance(self.caller, LegacySessionCaller):
            session = self._session_id(request)
            if session is None:
                return rpc_error(rpc_id, FAIL_CLOSED, "no Mcp-Session-Id: the interceptor needs passRequestHeaders "
                                 "true; caller identity absent; refused (fail closed)", {"code": "caller_identity_absent"})
            return session, session
        caller_key = self.caller.key(request.get("headers"))
        if caller_key is None:
            return rpc_error(rpc_id, FAIL_CLOSED, "no caller key: the Authorization header was not forwarded or not "
                             "verifiable (passRequestHeaders must be true; this function logs the header names that "
                             "arrive); refused (fail closed)", {"code": "caller_identity_absent"})
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        if META_VERSION in meta:  # 2026-07-28: Mcp-Session-Id is ignored; the client's own id is explicit
            client_id = meta.get(CLIENT_SESSION_META)
            if client_id is not None and not (isinstance(client_id, str) and CLIENT_SESSION_FORM.match(client_id)):
                return rpc_error(rpc_id, INVALID_PARAMS, f"_meta {CLIENT_SESSION_META!r} must match [A-Za-z0-9._:-]{{1,64}}")
        else:
            client_id = self._session_id(request)
        return caller_session(caller_key, client_id), caller_key

    def _tools_call(self, request: dict, body: dict, rpc_id: Any) -> dict:
        """One invocation. On ``caller_credential_expired`` (and only that refusal) the caller credential is
        re-read and the SAME invocation runs exactly once more; any refusal on that retry fails closed.
        Safe to repeat: every Requisition call precedes the claim, the propose reservation is released on
        failure, and an execute body stored before its call is replayed byte for byte, so the retry can
        neither claim nor pass through twice (one pass-through per approval, unchanged)."""
        try:
            return self._tools_call_once(request, body, rpc_id, may_retry=True)
        except _CredentialExpired:
            why = self._reread_credential()
            if why is not None:
                return rpc_error(rpc_id, FAIL_CLOSED, f"Requisition refused the check ({CREDENTIAL_EXPIRED}); {why}; "
                                 "the call is refused (fail closed)")
            return self._tools_call_once(request, body, rpc_id, may_retry=False)

    def _reread_credential(self) -> str | None:
        """Replace the cached credential with a fresh read. None when it was replaced; otherwise why not."""
        if self.credential_source is None:
            return "no credential source to re-read"
        now = self.monotonic()
        if self._last_reread is not None and now - self._last_reread < self.reread_interval:
            log.warning("requisition interceptor: %s; credential re-read skipped (at most one per %.0f s)",
                        CREDENTIAL_EXPIRED, self.reread_interval)
            return "the credential was re-read too recently"
        self._last_reread = now
        log.warning("requisition interceptor: %s; re-reading the caller credential (once)", CREDENTIAL_EXPIRED)
        try:
            fresh = self.credential_source()
        except Exception as error:  # noqa: BLE001 - an unreadable secret fails closed
            log.error("requisition interceptor: the credential re-read failed (%s)", type(error).__name__)
            return "the credential re-read failed"
        if not isinstance(fresh, str) or not fresh:
            return "the re-read credential is empty"
        if fresh == self.gate.client.credential:
            return "the re-read credential is unchanged"
        self.gate.client.credential = fresh  # later calls in this environment use it (the cache replaced)
        return None

    def _tools_call_once(self, request: dict, body: dict, rpc_id: Any, *, may_retry: bool) -> dict:
        if rpc_id is None:
            return rpc_error(None, INVALID_REQUEST, "tools/call without an id")
        if (isinstance(rpc_id, bool) or not isinstance(rpc_id, (str, int))
                or (isinstance(rpc_id, int) and not -canonical.MAX_INTEGER <= rpc_id <= canonical.MAX_INTEGER)):
            return rpc_error(None, INVALID_REQUEST, "tools/call needs a string or integer id")  # it enters the call key
        params = body.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return rpc_error(rpc_id, INVALID_PARAMS, "tools/call without a tool name")
        tool_args = params.get("arguments", {})
        if not isinstance(tool_args, dict):
            return rpc_error(rpc_id, INVALID_PARAMS, "tools/call arguments are not an object")
        headers = request.get("headers") if isinstance(request, dict) else None
        names = sorted(k.lower() for k in headers if isinstance(k, str)) if isinstance(headers, dict) else []
        log.info("requisition interceptor: request header names: %s", names)  # names only, never a value
        binding = self.registry.get(params["name"])
        if binding is None:
            return tool_error(rpc_id, f"Requisition: tool {params['name']!r} has no registered act type; denied by default")
        marked = self._marked(binding) if binding.pinned_digests else None
        if marked:
            return tool_error(rpc_id, f"Requisition: tool {binding.tool_name!r} is refused ({marked}): its listed "
                                      "definition is not the registered one; nothing was proposed",
                              {"status": "refused", "code": marked})
        if any(member in params for member in MRTR_MEMBERS):
            return rpc_error(rpc_id, FAIL_CLOSED, "Requisition: a gated tools/call carrying MRTR input "
                             "(inputResponses/requestState) is refused: that input is not in the signed act "
                             "(fail closed)", {"code": "mrtr_input_unsigned"})
        resolved = self._caller(request, params, rpc_id)
        if isinstance(resolved, dict):
            return resolved
        session, key_part = resolved
        args = arguments_object(self.agent_name, session, binding.act_type, tool_args, tool_digest=binding.pin)
        meta: dict = {}
        try:
            canonical.check_arguments(args, self.gate.configured_secrets)
            act_hash = canonical.act_hash(binding.act_type, args)
            key = idempotency_key("agentcore-gateway", self.gateway_id, key_part, rpc_id, act_hash)
            meta = {"act_hash": act_hash}
            # a Gateway retry of an invocation already executed: replay its stored body first
            decision = self.gate.replay_stored(key, args)
            if decision is None:
                sanction = self.gate.file_or_find(binding.act_type, args, schema=binding.schema)
                meta["request_id"] = sanction.request_id
                if sanction.status == "pending":
                    return tool_error(rpc_id, f"Requisition: awaiting approval {sanction.request_id} ({sanction.approval_url})",
                                      {**meta, "status": "pending", "approval_url": sanction.approval_url})
                if sanction.status == "refused":
                    return tool_error(rpc_id, f"Requisition: sanction request {sanction.request_id} was refused ({sanction.refused_code})",
                                      {**meta, "status": "refused", "code": sanction.refused_code})
                decision = self.gate.execute(sanction, args, key)
        except (canonical.IntakeRefusal, canonical.CanonicalRefusal) as refusal:
            return tool_error(rpc_id, f"Requisition: arguments refused before sending ({refusal.code}); nothing was proposed")
        except StaleExecute:
            return tool_error(rpc_id, "Requisition: the stored execute for this call has expired; issue the call again (fail closed)")
        except fence.FenceRefused as refusal:  # this relying party's own record refuses: final, never retryable
            return tool_error(rpc_id, f"Requisition: refused by this relying party's own record ({refusal.code}); "
                                      "not passed through", {**meta, "status": "refused", "code": refusal.code})
        except RequisitionUnavailable:
            return rpc_error(rpc_id, UNAVAILABLE, "Requisition unavailable; the call is refused (fail closed)")
        except RequisitionError as error:
            code = getattr(error, "code", None) or type(error).__name__
            if may_retry and isinstance(error, RequisitionRefused) and code == CREDENTIAL_EXPIRED:
                raise _CredentialExpired() from None
            return rpc_error(rpc_id, UNAVAILABLE, f"Requisition refused the check ({code}); the call is refused (fail closed)")
        if decision.allowed:
            if not decision.signature_checked:
                return rpc_error(rpc_id, UNAVAILABLE, "Requisition: the allow's signature was not checked; refused (fail closed)")
            if not self.gate.runnable(decision):  # every allow, replayed or not
                return tool_error(rpc_id, "Requisition: the allow's exec_not_after has passed (fail closed)",
                                  {**meta, "statement_id": decision.statement_id})
            # F1: one atomic claim of the statement AND its approval, persisted before the pass-through
            admission = self.gate.claim(decision, {"form": "interceptor", "key": key, "state": "passed"})
            if not admission.admitted:
                return tool_error(rpc_id, f"{USED} ({admission.code})",
                                  {**meta, "statement_id": decision.statement_id, "status": "already_used",
                                   "code": admission.code})
            return _out_request(body)  # unchanged: exactly the arguments that were approved and allowed
        return tool_error(rpc_id, f"Requisition: signed deny {decision.code}",
                          {**meta, "verdict": "deny", "code": decision.code, "decision": decision.decision})


# --- the Lambda entry point --------------------------------------------------------------------

_INTERCEPTOR: Interceptor | None = None


def from_env(env: dict | None = None, credential_source: Callable[[], str] | None = None) -> Interceptor:
    """Build from the Lambda's environment:

    REQUISITION_URL, REQUISITION_CRED, REQUISITION_PRINCIPAL      the /v1 caller
    REQUISITION_GATEWAY_ID                                         this gateway's id (set at deploy)
    REQUISITION_TOOLS     JSON {"<target>___<tool>": "<act type>" | {"act_type", "tool_digest"}}  the registry
    REQUISITION_CALLER_SOURCE   legacy_session (default) | sigv4 | jwt (+ REQUISITION_JWT_*): see caller.py
    REQUISITION_SEED      path to the lab seed file with each act type's display_schema
    REQUISITION_STORE     path of the idempotency store (default /tmp/requisition-aws/store.json)
    REQUISITION_AGENT     the agent member of the arguments object (default "agentcore-gateway")
    REQUISITION_APPROVAL_BASE   the console base URL for links (default REQUISITION_URL)
    REQUISITION_KEYS_FILE REQUIRED: the pinned lab key file; every statement and decision is checked
    REQUISITION_ACCEPT_SIGNERS  default "kms" (comma-separated signer labels, or "any"): KMS custody bounds what verifies
    REQUISITION_KEYS_MAX_AGE_SECONDS  default 300: the key file is re-read when it changes and at least this often
    REQUISITION_ALLOW_CLASSICAL_ONLY  "1": lift the key file's post-quantum policy (explicit; default "0")
    REQUISITION_REQUIRE_PQ      default "1": every record must carry a checked ML-DSA-87 signature
    REQUISITION_ALLOW_PLAINTEXT_PRIVATE  "1": plain http to a private IP literal (the VPC case)
    REQUISITION_CRED_REREAD_SECONDS  default 60: at most one credential re-read per this many seconds
    ``credential_source``: re-reads the caller credential on caller_credential_expired (the deployed entry's)
    """
    env = dict(os.environ if env is None else env)
    client = Client(env["REQUISITION_URL"], env["REQUISITION_CRED"], env["REQUISITION_PRINCIPAL"],
                    timeout=float(env.get("REQUISITION_TIMEOUT", "5")),
                    allow_plaintext_private=env.get("REQUISITION_ALLOW_PLAINTEXT_PRIVATE", "0") == "1")
    keys = KeyRegistry.from_env(env)  # required: KeyError refuses to start; re-read on change; signer kms by default
    store = Store(env.get("REQUISITION_STORE", "/tmp/requisition-aws/store.json"))
    gate = Gate(client, store, approval_base_url=env.get("REQUISITION_APPROVAL_BASE", env["REQUISITION_URL"]), keys=keys,
                require_pq=env.get("REQUISITION_REQUIRE_PQ", "1") == "1",
                allow_classical_only=env.get("REQUISITION_ALLOW_CLASSICAL_ONLY", "0") == "1")
    registry = ToolRegistry.from_seed(env["REQUISITION_SEED"], json.loads(env["REQUISITION_TOOLS"]))
    return Interceptor(gate, registry, gateway_id=env["REQUISITION_GATEWAY_ID"],
                       agent_name=env.get("REQUISITION_AGENT", "agentcore-gateway"), caller=caller_from_env(env),
                       credential_source=credential_source,
                       reread_interval=float(env.get("REQUISITION_CRED_REREAD_SECONDS", "60")))


def caller_from_env(env: dict) -> LegacySessionCaller | SigV4Caller | JwtCaller:
    """``REQUISITION_CALLER_SOURCE``: ``legacy_session`` (default), ``sigv4``, or ``jwt`` with
    ``REQUISITION_JWT_ISSUER``, ``REQUISITION_JWT_JWKS_FILE`` and ``REQUISITION_JWT_AUDIENCE`` and/or
    ``REQUISITION_JWT_CLIENTS`` (comma-separated). Anything else refuses to start."""
    source = env.get("REQUISITION_CALLER_SOURCE", "legacy_session")
    if source == "legacy_session":
        return LegacySessionCaller()
    if source == "sigv4":
        return SigV4Caller()
    if source == "jwt":
        with open(env["REQUISITION_JWT_JWKS_FILE"], "rb") as handle:
            jwks = loads_strict(handle.read())
        split = lambda v: tuple(x for x in (v or "").split(",") if x)  # noqa: E731
        return JwtCaller(env["REQUISITION_JWT_ISSUER"], jwks, audiences=split(env.get("REQUISITION_JWT_AUDIENCE")),
                         clients=split(env.get("REQUISITION_JWT_CLIENTS")))
    raise ValueError(f"REQUISITION_CALLER_SOURCE must be one of {CALLER_SOURCES}")


def lambda_handler(event: Any, context: Any, credential_source: Callable[[], str] | None = None) -> dict:
    global _INTERCEPTOR
    try:
        if _INTERCEPTOR is None:
            _INTERCEPTOR = from_env(credential_source=credential_source)
    except Exception as error:  # noqa: BLE001 - misconfigured: refuse every call
        log.error("requisition interceptor misconfigured: %s", type(error).__name__)
        rpc_id = None
        try:
            rpc_id = event["mcp"]["gatewayRequest"]["body"].get("id")
        except Exception:  # noqa: BLE001
            pass
        return rpc_error(rpc_id, UNAVAILABLE, "Requisition interceptor misconfigured; the call is refused (fail closed)")
    return _INTERCEPTOR.handle(event)
