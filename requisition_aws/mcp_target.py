# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Requisition as the AgentCore Gateway TARGET: an MCP server that owns the tool and runs it only on a
signed allow it has verified itself. Standard library plus ``cryptography`` (Ed25519) and the vendored ML-DSA verifier.

WHY AN MCP SERVER TARGET ON AGENTCORE RUNTIME, NOT A LAMBDA TARGET (AWS docs, fetched 2026-11-09):

* A Gateway Lambda target receives only the tool arguments as the event, plus
  ``context.client_context.custom`` (``bedrockAgentCoreToolName``, gateway, target, message and
  request ids); how a returned error becomes an MCP result is not documented
  (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-add-target-lambda.html).
  An MCP server target returns its own ``CallToolResult``: "awaiting approval <id>", a signed deny
  and "Requisition unavailable" each reach the agent as an ``isError`` result we wrote.
* An MCP server target supports protocol versions 2026-07-28, 2025-11-25, 2025-06-18 and 2025-03-26,
  and IAM (SigV4) outbound auth from the gateway when the server is hosted on AgentCore Runtime, so
  the gateway-to-tool hop holds no stored secret
  (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-target-MCPservers.html).
* Runtime's MCP contract: Streamable HTTP, host 0.0.0.0, port 8000, POST /mcp, ARM64, stateless,
  accept (never reject) ``Mcp-Session-Id`` and ``X-Amzn-Bedrock-AgentCore-Runtime-Session-Id``,
  ``GET /ping`` recommended, ``application/json`` responses allowed
  (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html).
  ``deploy/target/Dockerfile`` builds that image. Not built for ARM64 here, not deployed.

THE PROTOCOL (dual-era, one endpoint; https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning):

* modern 2026-07-28 (a request whose ``params._meta`` carries
  ``io.modelcontextprotocol/protocolVersion``): stateless; ``MCP-Protocol-Version``, ``Mcp-Method``
  and (for ``tools/call``) ``Mcp-Name`` must match the body, else 400 ``-32020 HeaderMismatch``
  (transports/streamable-http#server-validation); an unsupported version is 400 ``-32022`` with
  ``data.supported``; ``server/discover`` is implemented (server/discover); an unknown method is 404
  ``-32601``; results carry ``resultType: "complete"``; ``tools/list`` also carries the required
  ``ttlMs: 0`` and ``cacheScope: "private"`` (CacheableResult, changelog minor 5 and the schema's
  ListToolsResult, https://modelcontextprotocol.io/specification/2026-07-28/changelog, read 2026-11-10:
  0 is "immediately stale", private is never shared across authorization contexts).
* legacy 2025-11-25 / 2025-06-18 / 2025-03-26: ``initialize`` answers the client's version if it is
  one of those, else 2025-11-25; no session is minted (stateless); ``ping``; notifications 202.
* GET or DELETE on the endpoint: 405. An ``Origin`` header not in the allow-list: 403. No SSE.
* A header this target reads (``READ_HEADERS``, the configured session and caller headers) that arrives
  more than once, as case variants or twice on the wire: 400, never "the first" or "the last" one
  (``-32020`` for ``MCP-Protocol-Version``/``Mcp-Method``/``Mcp-Name``, else ``-32600``; the
  interceptor's rule, caller.header). Other headers may repeat.

THE TOOL CALL (the only path to the tool's effect):

  unknown tool, non-object arguments           -> JSON-RPC -32602 (a protocol error, server/tools)
  arguments the intake would refuse            -> isError, nothing proposed (refused, never truncated)
  a retry of a call that already ran           -> the stored result, the tool NOT run again
  file or find the sanction request (gate.py)  -> pending: isError "awaiting approval <id>"
                                                  refused: isError
  execute (idempotent per call key)            -> a signed deny: isError naming the code
  the allow's signature checked HERE (pinned key file; required), before exec_not_after
  claim the statement's single run (store)     -> already claimed: isError, NOT run again
  run the tool -> record its result -> report the outcome (when the server has the route)
  anything else, Requisition unreachable, an internal error -> isError (fail closed)

The call key is ``sha256(target id | transport session | JSON-RPC id | act_hash)``: a Gateway retry
of the same invocation replays the stored execute body and the stored result; the agent's new call
after the approvals (a new JSON-RPC id) executes once. The arguments object's ``session`` member is
a configured value, or a header the gateway forwards (``metadataConfiguration``); it is not the
transport session, which the gateway may vary per call (not measured: only a live call shows it).

THE CALLER HEADER (G1): under stateless MCP the
transport session is absent, so without more the call key is ``(target id, "", JSON-RPC id,
act_hash)`` and two callers sending the same id and arguments would share a stored result. With
``caller_header`` configured (``REQUISITION_CALLER_HEADER``) that header is required (missing or
malformed: ``isError``, fail closed), the call key is ``(target id, caller header, JSON-RPC id,
act_hash)`` and the signed ``session`` is ``caller_session(caller header, session)``. The caller
header is a collision namespace, never an identity: the target form claims one caller. It is
trustworthy only when our interceptor ALWAYS sets it, overwriting any client value (an interceptor's
header takes precedence over a client's, gateway-headers.html) and it is in the target's
``allowedRequestHeaders``; the Gateway cannot propagate ``Authorization``. A target deployed without the
interceptor in front of it sees the header as client text.

LIMITS: the store is one local file (per microVM on Runtime; no durable store is built here). F1 (fence.py): every signed record read enters the store's position
memory (a different record at a held position: ``authority_equivocated``, both kept as evidence) and
the run is claimed on the statement AND the approval it names (``approval_already_used`` for a
re-minted statement). On Runtime that memory is per microVM: the deployed target makes NO rollback
claim until its store is durable; the claim holds for a local run whose store survives. When the server has no
outcome route, the run is recorded only here.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import fcntl
import json
import logging
import os
import re
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from . import canonical, settings
from .caller import caller_session
from .client import MAX_INTEGER, Client, RequisitionError, RequisitionUnavailable, loads_tool_call
from .gate import Decision, Gate, StaleExecute, arguments_object
from .keys import KeyRegistry
from .registry import ToolRegistry
from .store import Store, idempotency_key

log = logging.getLogger(__name__)

MODERN = ("2026-07-28",)
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26")
SUPPORTED = MODERN + LEGACY
META_VERSION = "io.modelcontextprotocol/protocolVersion"
CLIENT_META_DEFAULT = {META_VERSION: "2026-07-28",  # what this repo's own demo client sends
                       "io.modelcontextprotocol/clientInfo": {"name": "requisition-aws-demo-client", "version": "0.0.0"},
                       "io.modelcontextprotocol/clientCapabilities": {}}
SERVER_INFO = {"name": "requisition-aws-target", "version": "0.0.0"}
MAX_BODY = 1 << 20
SESSION_HEADERS = ("x-amzn-bedrock-agentcore-runtime-session-id", "mcp-session-id")
MCP_HEADERS = ("mcp-protocol-version", "mcp-method", "mcp-name")
READ_HEADERS = frozenset(("origin", "content-type") + MCP_HEADERS + SESSION_HEADERS)
TOOLS_LIST_CACHE = {"ttlMs": 0, "cacheScope": "private"}  # CacheableResult (2026-07-28)
SESSION_FORM = re.compile(r"\A[A-Za-z0-9._:-]{1,64}\Z")
CALLER_FORM = re.compile(r"\A[!-~](?:[ -~]{0,510}[!-~])?\Z")  # printable ASCII, no edge spaces, at most 512

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
HEADER_MISMATCH, UNSUPPORTED_VERSION = -32020, -32022

INSTRUCTIONS = ("Each tool here runs only on Requisition's signed allow for its exact arguments. A call that "
                "is not yet approved returns an error naming the approval request; call again once it is "
                "approved. Never retry a refused or denied call.")


class Reply(Exception):
    """An HTTP-level answer decided before the method runs (a header or version refusal)."""

    def __init__(self, status: int, body: dict | None):
        super().__init__(status)
        self.status, self.body = status, body


def rpc_error(rpc_id: Any, code: int, message: str, data: Any = None) -> dict:
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": error}


# --- the tool: a stub refund that writes REFUND SENT to a local ledger -----------------------------


class Ledger:
    """An append-only JSON-lines file; each line is one effect. flock + fsync per append."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def append(self, entry: dict) -> int:
        line = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, line)
            os.fsync(fd)
            with open(self.path, "rb") as handle:
                return sum(1 for _ in handle)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def entries(self) -> list[dict]:
        try:
            with open(self.path, "rb") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except FileNotFoundError:
            return []


@dataclass
class ToolImpl:
    name: str
    description: str
    run: Callable[[dict, dict], str]  # (tool arguments, the allow's facts) -> the result text


def refund_tool(ledger: Ledger, name: str = "payments_refund_send") -> ToolImpl:
    def run(tool_args: dict, allow: dict) -> str:
        n = ledger.append({"event": "REFUND SENT", **tool_args, "statement_id": allow["statement_id"],
                           "decision_receipt_hash": allow["receipt_hash"],
                           "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        return (f"REFUND SENT: {tool_args['amount_minor']} {tool_args['currency']} minor units to "
                f"{tool_args['account']} (ledger entry {n}; a local stub, no money moved)")

    return ToolImpl(name, "Send a refund to a customer account (amount in integer minor units). A local stub: "
                          "it writes REFUND SENT to a ledger. " + INSTRUCTIONS, run)


# --- the inputSchema, derived from the act type's display_schema ---------------------------------


def input_schema(schema: canonical.ArgsSchema, root: str = "args") -> dict:
    """JSON Schema for the tool's own arguments: the ``args.*`` members of the act type's path-form
    display_schema (the seed's), so the agent is told exactly what Requisition will accept."""

    def node(entry: dict, path: str) -> dict:
        kind = entry["type"]
        if kind == "i":
            out = {"type": "integer"}
            out.update({k2: entry[k] for k, k2 in (("min", "minimum"), ("max", "maximum")) if k in entry})
        elif kind == "s":
            out = {"type": "string"}
            out.update({k2: entry[k] for k, k2 in (("min_length", "minLength"), ("max_length", "maxLength")) if k in entry})
        elif kind == "enum":
            out = {"enum": list(entry["values"])}
        elif kind == "b":
            out = {"type": "boolean"}
        elif kind == "obj":
            out = obj(path)
        elif kind == "list":
            out = {"type": "array"}
            out.update({k2: entry[k] for k, k2 in (("min_items", "minItems"), ("max_items", "maxItems")) if k in entry})
            item = schema.by_path.get(path + "[]")
            if item is not None:
                out["items"] = node(item, path + "[]")
        else:  # pragma: no cover - ArgsSchema refuses other types at construction
            raise ValueError(kind)
        return out

    def obj(path: str) -> dict:
        props, required = {}, []
        for name, entry in sorted(schema._members(path).items()):
            props[name] = node(entry, f"{path}.{name}")
            if entry["required"]:
                required.append(name)
        return {"type": "object", "properties": props, "required": required, "additionalProperties": False}

    if root not in schema.by_path or schema.by_path[root]["type"] != "obj":
        raise ValueError("the display_schema has no args object")
    return obj(root)


# --- the target --------------------------------------------------------------------------------


class McpTarget:
    def __init__(self, gate: Gate, registry: ToolRegistry, tools: dict[str, ToolImpl], *, target_id: str,
                 agent_name: str, session: str = "agentcore-gateway", session_header: str | None = None,
                 caller_header: str | None = None, allowed_origins: tuple[str, ...] = (), on_event: Callable[[str, dict], None] | None = None):
        if gate.keys is None:
            raise ValueError("the target runs a tool only on an allow whose signature it checked: a pinned key file is required")
        if not target_id:
            raise ValueError("target_id is required")
        for name in tools:
            binding = registry.get(name)
            if binding is None or binding.schema is None:
                raise ValueError(f"tool {name!r} has no registered act type with a display_schema")
        if not SESSION_FORM.match(session):
            raise ValueError("session must match [A-Za-z0-9._:-]{1,64}")
        self.gate, self.registry, self.tools = gate, registry, tools
        self.target_id, self.agent_name, self.session = target_id, agent_name, session
        self.session_header = session_header.lower() if session_header else None
        self.caller_header = caller_header.lower() if caller_header else None
        self.allowed_origins = tuple(allowed_origins)
        self.read_headers = READ_HEADERS | {h for h in (self.session_header, self.caller_header) if h}
        self.on_event = on_event or (lambda kind, detail: None)

    # --- HTTP ------------------------------------------------------------------------------------

    def handle_http(self, method: str, path: str, headers: dict[str, str] | list[tuple[str, str]], body: bytes,
                    mcp_path: str = "/mcp") -> tuple[int, dict[str, str], bytes]:
        """``headers``: a mapping, or the (name, value) pairs as received (``serve`` passes the pairs, so a
        header sent twice is seen twice)."""
        h: dict[str, str] = {}
        twice: set[str] = set()
        for k, v in (headers.items() if isinstance(headers, dict) else headers):
            if k.lower() in h:
                twice.add(k.lower())
            h[k.lower()] = v
        if path == "/ping":
            return 200, {"content-type": "application/json"}, b'{"status":"Healthy"}'
        if path.split("?", 1)[0] != mcp_path:
            return 404, {"content-type": "application/json"}, b'{"error":"not_found"}'
        ambiguous = sorted(twice & self.read_headers)
        if ambiguous:  # never the first or the last one
            code = HEADER_MISMATCH if set(ambiguous) & set(MCP_HEADERS) else INVALID_REQUEST
            return self._json(400, rpc_error(None, code, f"Ambiguous header: {ambiguous[0]} more than once"))
        origin = h.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            return self._json(403, rpc_error(None, INVALID_REQUEST, "Origin not allowed"))
        if method != "POST":
            return 405, {"allow": "POST", "content-type": "application/json"}, b""
        if "application/json" not in h.get("content-type", ""):
            return self._json(415, rpc_error(None, INVALID_REQUEST, "Content-Type must be application/json"))
        if len(body) > MAX_BODY:
            return self._json(413, rpc_error(None, INVALID_REQUEST, "request too large"))
        try:
            message = loads_tool_call(body)  # intake judges the arguments (an integer outside the bound: malformed_member)
        except (ValueError, UnicodeDecodeError):
            return self._json(400, rpc_error(None, PARSE_ERROR, "Parse error"))
        status, reply = self.handle_message(message, h)
        if reply is None:
            return status, {}, b""
        return self._json(status, reply)

    @staticmethod
    def _json(status: int, obj: dict) -> tuple[int, dict[str, str], bytes]:
        return status, {"content-type": "application/json"}, json.dumps(obj, separators=(",", ":")).encode()

    # --- JSON-RPC --------------------------------------------------------------------------------

    def handle_message(self, msg: Any, headers: dict[str, str]) -> tuple[int, dict | None]:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return 400, rpc_error(msg.get("id") if isinstance(msg, dict) else None, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        rpc_id, method = msg.get("id"), msg["method"]
        is_notification = "id" not in msg
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return 400, rpc_error(rpc_id, INVALID_PARAMS, "params must be an object")
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        modern = method != "initialize" and META_VERSION in meta
        try:
            version = self._check_headers(method, params, meta, headers, modern)
        except Reply as reply:
            if reply.body is not None and isinstance(reply.body.get("error"), dict):
                reply.body["id"] = rpc_id
            return reply.status, reply.body
        if is_notification:
            return 202, None
        try:
            result = self._dispatch(method, params, rpc_id, headers, modern, version)
        except Reply as reply:
            if reply.body is not None:
                reply.body["id"] = rpc_id
            return reply.status, reply.body
        if modern:
            result = {"resultType": "complete", **result}
        return 200, {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    def _check_headers(self, method, params, meta, headers, modern) -> str:
        header_version = headers.get("mcp-protocol-version")
        if not modern:
            if header_version is not None and header_version not in LEGACY and method != "initialize":
                raise Reply(400, rpc_error(None, UNSUPPORTED_VERSION, "Unsupported protocol version",
                                           {"supported": list(SUPPORTED), "requested": header_version}))
            return header_version or "2025-03-26"
        requested = meta.get(META_VERSION)
        if header_version is None or header_version != requested:
            raise Reply(400, rpc_error(None, HEADER_MISMATCH,
                                       f"Header mismatch: MCP-Protocol-Version {header_version!r} vs body {requested!r}"))
        if requested not in MODERN:
            raise Reply(400, rpc_error(None, UNSUPPORTED_VERSION, "Unsupported protocol version",
                                       {"supported": list(SUPPORTED), "requested": requested}))
        if headers.get("mcp-method") != method:
            raise Reply(400, rpc_error(None, HEADER_MISMATCH, f"Header mismatch: Mcp-Method {headers.get('mcp-method')!r} vs body {method!r}"))
        if method in ("tools/call", "prompts/get", "resources/read"):
            want = params.get("name") if method != "resources/read" else params.get("uri")
            got = _decode_header_value(headers.get("mcp-name"))
            if got is None or got != want:
                raise Reply(400, rpc_error(None, HEADER_MISMATCH, "Header mismatch: Mcp-Name does not match the body"))
        return requested

    def _dispatch(self, method, params, rpc_id, headers, modern, version) -> dict:
        if not modern and method == "initialize":
            asked = params.get("protocolVersion")
            return {"protocolVersion": asked if asked in LEGACY else LEGACY[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS}
        if not modern and method == "ping":
            return {}
        if modern and method == "server/discover":
            return {"supportedVersions": list(SUPPORTED), "capabilities": {"tools": {"listChanged": False}},
                    "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO}, "instructions": INSTRUCTIONS}
        if method == "tools/list":
            tools = {"tools": [self._definition(name) for name in sorted(self.tools)]}
            return {**tools, **TOOLS_LIST_CACHE} if modern else tools
        if method == "tools/call":
            return self._tools_call(params, rpc_id, headers)
        raise Reply(404 if modern else 200, rpc_error(None, METHOD_NOT_FOUND, f"Method not found: {method}"))

    def _definition(self, name: str) -> dict:
        binding = self.registry.get(name)
        return {"name": name, "description": self.tools[name].description,
                "inputSchema": input_schema(binding.schema)}

    # --- tools/call ------------------------------------------------------------------------------

    def _tools_call(self, params: dict, rpc_id: Any, headers: dict[str, str]) -> dict:
        name = params.get("name")
        if not isinstance(name, str) or name not in self.tools:
            raise Reply(200, rpc_error(None, INVALID_PARAMS, f"Unknown tool: {name}"))
        tool_args = params.get("arguments", {})
        if not isinstance(tool_args, dict):
            raise Reply(200, rpc_error(None, INVALID_PARAMS, "tools/call arguments must be an object"))
        if (rpc_id is None or isinstance(rpc_id, bool) or not isinstance(rpc_id, (str, int))
                or (isinstance(rpc_id, int) and not -MAX_INTEGER <= rpc_id <= MAX_INTEGER)):  # the id enters the call key
            raise Reply(200, rpc_error(None, INVALID_REQUEST, "tools/call needs a string or integer id"))
        try:
            return self._call(name, tool_args, rpc_id, headers)
        except Exception as error:  # noqa: BLE001 - fail closed: never run on an unexpected error
            log.error("requisition target failed closed: %s", type(error).__name__)
            return self._error(f"internal error ({type(error).__name__}); the tool did not run (fail closed)")

    @staticmethod
    def _error(text: str, meta: dict | None = None) -> dict:
        out: dict = {"content": [{"type": "text", "text": "Requisition: " + text}], "isError": True}
        if meta:
            out["_meta"] = {"requisition": meta}
        return out

    def _session(self, headers: dict[str, str]) -> str | None:
        if self.session_header is None:
            return self.session
        value = headers.get(self.session_header)
        return value if isinstance(value, str) and SESSION_FORM.match(value) else None

    def _call(self, name: str, tool_args: dict, rpc_id: Any, headers: dict[str, str]) -> dict:
        binding = self.registry.get(name)
        session = self._session(headers)
        if session is None:
            return self._error(f"no valid {self.session_header} header; the tool did not run (fail closed)")
        transport = next((headers[h] for h in SESSION_HEADERS if headers.get(h)), "")
        if self.caller_header is not None:
            caller = headers.get(self.caller_header)
            if not isinstance(caller, str) or not CALLER_FORM.match(caller):
                return self._error(f"no valid {self.caller_header} caller header; the tool did not run (fail closed)")
            session, transport = caller_session(caller, session), caller
        args = arguments_object(self.agent_name, session, binding.act_type, tool_args)
        store = self.gate.store
        try:
            canonical.check_arguments(args, self.gate.configured_secrets)
            binding.schema.validate(args, self.gate.configured_secrets)
            act_hash = canonical.act_hash(binding.act_type, args)
            key = idempotency_key("agentcore-mcp-target", self.target_id, transport, rpc_id, act_hash)
            meta: dict = {"act_hash": act_hash}
            done = store.get("target_results", key)
            if done is not None:  # a retry of a call that already ran: its result, never a second run
                self.on_event("retry_replayed", {"key": key, "statement_id": done["statement_id"]})
                return {**done["result"], "_meta": {"requisition": {**done["result"]["_meta"]["requisition"], "replayed": True}}}
            decision = self.gate.replay_stored(key, args)
            if decision is None:
                sanction = self.gate.file_or_find(binding.act_type, args, schema=binding.schema)
                meta["request_id"] = sanction.request_id
                self.on_event(sanction.status, {"request_id": sanction.request_id, "act_hash": act_hash})
                if sanction.status == "pending":
                    return self._error(f"awaiting approval {sanction.request_id} ({sanction.approval_url}); "
                                       "the tool did not run. Call again once it is approved.",
                                       {**meta, "status": "pending", "approval_url": sanction.approval_url})
                if sanction.status == "refused":
                    return self._error(f"sanction request {sanction.request_id} was refused "
                                       f"({sanction.refused_code}); the tool did not run",
                                       {**meta, "status": "refused", "code": sanction.refused_code})
                decision = self.gate.execute(sanction, args, key)
        except (canonical.IntakeRefusal, canonical.CanonicalRefusal) as refusal:
            return self._error(f"arguments refused before sending ({refusal.code}); nothing was proposed")
        except StaleExecute:
            return self._error("the stored execute for this call has expired; the tool did not run (fail closed)")
        except RequisitionUnavailable:
            return self._error("Requisition unavailable; the tool did not run (fail closed)")
        except RequisitionError as error:
            code = getattr(error, "code", None) or type(error).__name__
            return self._error(f"Requisition refused the check ({code}); the tool did not run (fail closed)")
        return self._run(name, tool_args, key, decision, meta)

    def _run(self, name: str, tool_args: dict, key: str, decision: Decision, meta: dict) -> dict:
        facts = {"statement_id": decision.statement_id, "receipt_hash": decision.decision["receipt_hash"],
                 "verdict": decision.verdict}
        meta = {**meta, **facts, "code": decision.code}
        self.on_event("decision", {**facts, "code": decision.code, "replayed": decision.replayed})
        if not decision.allowed:
            return self._error(f"signed deny {decision.code}; the tool did not run", meta)
        if not decision.signature_checked:  # unreachable while keys are required; kept as the rule
            return self._error("the allow's signature was not checked here; the tool did not run")
        if not self.gate.runnable(decision):
            return self._error(f"the allow's exec_not_after ({decision.exec_not_after}) has passed; the tool did not run", meta)
        store = self.gate.store
        # F1: one atomic claim of the statement AND its approval, persisted BEFORE the tool runs
        admission = self.gate.claim(decision, {"state": "running", "key": key, "tool": name, "form": "target"})
        if not admission.admitted:
            current = store.get("ran", decision.statement_id) or {}
            return self._error(f"statement {decision.statement_id[:16]}... is not run: {admission.code} "
                               f"({current.get('state', 'another statement for this approval')}); it is not run again",
                               {**meta, "refused": admission.code})
        try:
            text, succeeded = self.tools[name].run(tool_args, facts), True
        except Exception as error:  # noqa: BLE001 - the tool's failure is an outcome, not a crash
            text, succeeded = f"the tool failed ({type(error).__name__})", False
        # From here the tool HAS RUN: no later failure may tell the agent it did not.
        outcome = "succeeded" if succeeded else "failed"
        result = {"content": [{"type": "text", "text": text}], "isError": not succeeded,
                  "_meta": {"requisition": {**meta, "outcome": outcome}}}
        try:
            self.on_event("tool_ran", {**facts, "succeeded": succeeded, "text": text})
            report = self.gate.report_outcome(decision, succeeded, text, None if succeeded else "tool_error")
            result["_meta"]["requisition"]["outcome_report"] = report
            self.on_event("outcome", {**facts, "outcome": outcome, "report": report})
            claimed = store.get("ran", decision.statement_id)
            store.compare_and_set("ran", decision.statement_id, claimed, {**claimed, "state": "done", "succeeded": succeeded})
            store.create_if_absent("target_results", key, {"statement_id": decision.statement_id, "result": result})
        except Exception as error:  # noqa: BLE001 - after the effect: say it ran, and what failed after
            log.error("requisition target: recording after the run failed: %s", type(error).__name__)
            return {"content": [{"type": "text", "text": f"{text}\nRequisition: the tool RAN under statement "
                                 f"{decision.statement_id}; recording its result failed afterwards "
                                 f"({type(error).__name__}). Do not call it again for this approval."}],
                    "isError": True,
                    "_meta": {"requisition": {**meta, "outcome": outcome, "ran": True,
                                              "recording_failed": type(error).__name__}}}
        return result


def _decode_header_value(value: str | None) -> str | None:
    """The =?base64?...?= sentinel (transports/streamable-http#value-encoding), else the value."""
    if value is None:
        return None
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
    return value


# --- serving -----------------------------------------------------------------------------------


def serve(target: McpTarget, host: str = "127.0.0.1", port: int = 8000, mcp_path: str = "/mcp") -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # never log request bodies or headers
            pass

        def _bare(self, status: int):
            self.send_response(status)
            self.send_header("content-length", "0")
            self.end_headers()

        def _answer(self, method: str):
            raw = self.headers.get("content-length") or "0"
            if not raw.isdigit():  # negative or not an integer: never read(-1)
                self.close_connection = True
                return self._bare(400)
            length = int(raw)
            if length > MAX_BODY:
                self.close_connection = True
                return self._bare(413)
            body = self.rfile.read(length) if length else b""
            status, headers, data = target.handle_http(method, self.path, list(self.headers.items()), body, mcp_path)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self._answer("POST")

        def do_GET(self):
            self._answer("GET")

        def do_DELETE(self):
            self._answer("DELETE")

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def from_env(env: dict | None = None) -> tuple[McpTarget, dict]:
    """REQUISITION_URL, REQUISITION_CRED, REQUISITION_PRINCIPAL   the /v1 caller
    REQUISITION_KEYS_FILE   the pinned lab key file (REQUIRED: the tool runs only on a checked allow)
    REQUISITION_SEED        the lab seed with each act type's display_schema
    REQUISITION_TOOLS       JSON {"<tool name>": "<act type>"} (default the refund tool)
    REQUISITION_STORE, REQUISITION_LEDGER   local files (default under /tmp/requisition-aws/)
    REQUISITION_TARGET_ID   this target's id (part of every call key)
    REQUISITION_AGENT, REQUISITION_SESSION, REQUISITION_SESSION_HEADER   the arguments object
    REQUISITION_CALLER_HEADER   optional: the caller-namespace header (G1; a namespace, never an identity)
    REQUISITION_APPROVAL_BASE   the console base URL for approval links
    REQUISITION_SOCKET      optional: /v1 over Requisition's Unix socket
    REQUISITION_ACCEPT_SIGNERS  default "kms" (comma-separated signer labels, or "any"): KMS custody bounds what verifies
    REQUISITION_KEYS_MAX_AGE_SECONDS  default 300: the key file is re-read when it changes and at least this often
    REQUISITION_ALLOW_CLASSICAL_ONLY  "1": lift the key file's post-quantum policy (explicit; default "0")
    REQUISITION_REQUIRE_PQ  default "1": run only on records whose ML-DSA-87 signature was checked
    REQUISITION_ALLOW_PLAINTEXT_PRIVATE  "1": plain http to a private IP literal (the VPC case)
    REQUISITION_TIMEOUT     default 5: seconds per /v1 call
    MCP_HOST                a host name or an IP literal (default 127.0.0.1; set and empty is refused)
    MCP_PORT, MCP_PATH, MCP_ALLOWED_ORIGINS (comma-separated)

    The switches take exactly "1" or "0", the seconds a finite decimal above zero, a header setting an HTTP header
    name when it is set, REQUISITION_TOOLS strict JSON (settings.py): any other value refuses to start, naming the
    variable, and never weakens a control."""
    env = dict(os.environ if env is None else env)
    require_pq = settings.switch(env, "REQUISITION_REQUIRE_PQ", True)
    allow_classical_only = settings.switch(env, "REQUISITION_ALLOW_CLASSICAL_ONLY", False)
    allow_plaintext_private = settings.switch(env, "REQUISITION_ALLOW_PLAINTEXT_PRIVATE", False)
    timeout = settings.seconds(env, "REQUISITION_TIMEOUT", 5)
    session_header = settings.header_name(env, "REQUISITION_SESSION_HEADER")
    caller_header = settings.header_name(env, "REQUISITION_CALLER_HEADER")
    bind_host = settings.host(env, "MCP_HOST", "127.0.0.1")
    tools_map = settings.json_map(env, "REQUISITION_TOOLS", '{"payments_refund_send": "payments.refund_send"}')
    client = Client(env["REQUISITION_URL"], env["REQUISITION_CRED"], env["REQUISITION_PRINCIPAL"],
                    timeout=timeout, unix_socket=env.get("REQUISITION_SOCKET") or None,
                    allow_plaintext_private=allow_plaintext_private)
    keys = KeyRegistry.from_env(env)  # required: KeyError refuses to start; re-read on change; signer kms by default
    store = Store(env.get("REQUISITION_STORE", "/tmp/requisition-aws/target-store.json"))
    gate = Gate(client, store, approval_base_url=env.get("REQUISITION_APPROVAL_BASE", env["REQUISITION_URL"]), keys=keys,
                require_pq=require_pq, allow_classical_only=allow_classical_only)
    registry = ToolRegistry.from_seed(env["REQUISITION_SEED"], tools_map)
    ledger = Ledger(env.get("REQUISITION_LEDGER", "/tmp/requisition-aws/refund-ledger.jsonl"))
    if set(tools_map) != {"payments_refund_send"}:
        raise ValueError("this demo target implements one tool: payments_refund_send")
    target = McpTarget(gate, registry, {"payments_refund_send": refund_tool(ledger)},
                       target_id=env.get("REQUISITION_TARGET_ID", "requisition-target-local"),
                       agent_name=env.get("REQUISITION_AGENT", "agentcore-gateway"),
                       session=env.get("REQUISITION_SESSION", "agentcore-gateway"),
                       session_header=session_header, caller_header=caller_header,
                       allowed_origins=tuple(o for o in env.get("MCP_ALLOWED_ORIGINS", "").split(",") if o))
    opts = {"host": bind_host, "port": int(env.get("MCP_PORT", "8000")),
            "mcp_path": env.get("MCP_PATH", "/mcp")}
    return target, opts


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    target, opts = from_env()
    server = serve(target, **opts)
    log.info("requisition MCP target on %s:%d%s (POST), /ping", opts["host"], opts["port"], opts["mcp_path"])
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
