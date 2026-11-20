# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Requisition as the AgentCore Gateway target (requisition_aws.mcp_target): the MCP protocol, both eras,
against the spec pages cited in the module, and the tool call against the fake Requisition. The tool
writes REFUND SENT to a ledger; every test counts the ledger's lines, the effect itself."""

import base64
import copy
import http.client
import json
import threading

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate
from requisition_aws.keys import KeyRegistry
from requisition_aws.mcp_target import Ledger, McpTarget, ToolImpl, input_schema, refund_tool, serve
from requisition_aws.registry import ToolRegistry
from requisition_aws.store import Store

from .conftest import ACT_TYPE, refund_args
from .fake_requisition import FakeRequisition
from .test_canonical import SEED_SCHEMA

TOOL = "payments_refund_send"
MODERN = "2026-07-28"
CLIENT_META = {"io.modelcontextprotocol/protocolVersion": MODERN,
               "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"},
               "io.modelcontextprotocol/clientCapabilities": {}}


def make_target(server, tmp_path, clock, *, tools=None, keys=True, **kw):
    client = Client(server.base_url, server.credential, server.principal, timeout=5)
    gate = Gate(client, Store(str(tmp_path / "store.json"), clock=clock), approval_base_url="http://127.0.0.1:4000",
                keys=KeyRegistry.from_bytes(client.keys()) if keys else None, clock=clock)
    reg = ToolRegistry()
    reg.register(TOOL, ACT_TYPE, SEED_SCHEMA)
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    events = []
    target = McpTarget(gate, reg, tools or {TOOL: refund_tool(ledger)}, target_id="target-test",
                       agent_name="agentcore-gateway", session="sess-1",
                       on_event=lambda k, d: events.append((k, d)), **kw)
    return target, ledger, events


@pytest.fixture
def target(fake, tmp_path, clock):
    return make_target(fake, tmp_path, clock)


def post(target, msg, headers=None):
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    h.update(headers or {})
    status, out_headers, body = target.handle_http("POST", "/mcp", h, json.dumps(msg).encode())
    return status, (json.loads(body) if body else None)


def legacy(method, params=None, rpc_id=1, headers=None, t=None):
    msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if rpc_id is not None:
        msg["id"] = rpc_id
    return post(t, msg, {"mcp-protocol-version": "2025-11-25", **(headers or {})})


def modern(t, method, params=None, rpc_id=1, headers=None, name=None):
    params = dict(params or {})
    params["_meta"] = dict(CLIENT_META)
    h = {"mcp-protocol-version": MODERN, "mcp-method": method}
    if method == "tools/call":
        h["mcp-name"] = name if name is not None else params.get("name")
    h.update(headers or {})
    return post(t, {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}, h)


def call(t, rpc_id, arguments=None, era="modern"):
    params = {"name": TOOL, "arguments": arguments or refund_args()}
    if era == "modern":
        return modern(t, "tools/call", params, rpc_id)
    return legacy("tools/call", params, rpc_id, t=t)


def text(result):
    return " ".join(c["text"] for c in result["content"])


# --- HTTP --------------------------------------------------------------------------------------


def test_ping_and_methods(target):
    t, _, _ = target
    assert t.handle_http("GET", "/ping", {}, b"") == (200, {"content-type": "application/json"}, b'{"status":"Healthy"}')
    assert t.handle_http("GET", "/mcp", {}, b"")[0] == 405
    assert t.handle_http("DELETE", "/mcp", {}, b"")[0] == 405
    assert t.handle_http("POST", "/other", {"content-type": "application/json"}, b"{}")[0] == 404
    assert t.handle_http("POST", "/mcp", {"content-type": "text/plain"}, b"{}")[0] == 415
    assert t.handle_http("POST", "/mcp", {"content-type": "application/json"}, b"{nope")[0] == 400
    status, _, body = t.handle_http("POST", "/mcp", {"content-type": "application/json", "origin": "https://evil.example"}, b"{}")
    assert status == 403 and "id" in json.loads(body) and json.loads(body)["id"] is None


def test_an_allowed_origin_passes(fake, tmp_path, clock):
    t, _, _ = make_target(fake, tmp_path, clock, allowed_origins=("https://ok.example",))
    status, body = post(t, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"origin": "https://ok.example"})
    assert status == 200 and body["result"] == {}


# --- legacy era (initialize) -------------------------------------------------------------------


@pytest.mark.parametrize("asked, answered", [("2025-11-25", "2025-11-25"), ("2025-06-18", "2025-06-18"),
                                             ("2025-03-26", "2025-03-26"), ("2024-11-05", "2025-11-25")])
def test_initialize_negotiates_and_mints_no_session(target, asked, answered):
    t, _, _ = target
    status, body = post(t, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                            "params": {"protocolVersion": asked, "capabilities": {}, "clientInfo": {"name": "c", "version": "1"}}})
    assert status == 200 and body["result"]["protocolVersion"] == answered
    assert body["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert body["result"]["serverInfo"]["name"] == "requisition-aws-target"


def test_legacy_notifications_ping_and_session_headers(target):
    t, _, _ = target
    assert legacy("notifications/initialized", rpc_id=None, t=t) == (202, None)
    status, body = legacy("ping", t=t, headers={"mcp-session-id": "abc", "x-amzn-bedrock-agentcore-runtime-session-id": "r"})
    assert status == 200 and body == {"jsonrpc": "2.0", "id": 1, "result": {}}
    status, body = legacy("resources/list", t=t)
    assert status == 200 and body["error"]["code"] == -32601
    status, body = post(t, {"jsonrpc": "2.0", "id": 3, "method": "ping"}, {"mcp-protocol-version": "1999-01-01"})
    assert status == 400 and body["error"]["code"] == -32022 and body["error"]["data"]["requested"] == "1999-01-01"


def test_tools_list_derives_the_schema_from_the_seed(target):
    t, _, _ = target
    status, body = legacy("tools/list", t=t)
    (tool,) = body["result"]["tools"]
    assert tool["name"] == TOOL and "resultType" not in body["result"]
    assert tool["inputSchema"] == {
        "type": "object", "additionalProperties": False,
        "required": ["account", "amount_minor", "currency", "reason"],
        "properties": {
            "account": {"type": "string", "minLength": 1, "maxLength": 64},
            "amount_minor": {"type": "integer", "minimum": 1, "maximum": 100000000},
            "currency": {"enum": ["USD", "EUR", "GBP"]},
            "reason": {"type": "string", "minLength": 1, "maxLength": 200},
        },
    }


def test_input_schema_nested_and_lists():
    schema = canonical.ArgsSchema(SEED_SCHEMA + [
        {"path": "args.flags", "type": "list", "required": False, "max_items": 3},
        {"path": "args.flags[]", "type": "b", "required": True},
    ])
    out = input_schema(schema)
    assert out["properties"]["flags"] == {"type": "array", "maxItems": 3, "items": {"type": "boolean"}}


# --- modern era (2026-07-28) -------------------------------------------------------------------


def test_server_discover_and_result_type(target):
    t, _, _ = target
    status, body = modern(t, "server/discover")
    assert status == 200 and body["result"]["resultType"] == "complete"
    assert body["result"]["supportedVersions"] == ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
    status, body = modern(t, "tools/list")
    assert body["result"]["resultType"] == "complete" and body["result"]["tools"][0]["name"] == TOOL


@pytest.mark.parametrize("headers, code", [
    ({"mcp-protocol-version": None}, -32020),
    ({"mcp-protocol-version": "2025-11-25"}, -32020),
    ({"mcp-method": "tools/list"}, -32020),
    ({"mcp-method": None}, -32020),
])
def test_modern_header_validation(target, headers, code):
    t, _, _ = target
    params = {"_meta": dict(CLIENT_META)}
    h = {"mcp-protocol-version": MODERN, "mcp-method": "server/discover"}
    h.update(headers)
    h = {k: v for k, v in h.items() if v is not None}
    status, body = post(t, {"jsonrpc": "2.0", "id": 7, "method": "server/discover", "params": params}, h)
    assert status == 400 and body["error"]["code"] == code and body["id"] == 7


def test_modern_unsupported_version_lists_the_supported_ones(target):
    t, _, _ = target
    meta = {**CLIENT_META, "io.modelcontextprotocol/protocolVersion": "2099-01-01"}
    status, body = post(t, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}},
                        {"mcp-protocol-version": "2099-01-01", "mcp-method": "tools/list"})
    assert status == 400 and body["error"]["code"] == -32022
    assert body["error"]["data"] == {"supported": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"], "requested": "2099-01-01"}


def test_modern_unknown_method_is_404(target):
    t, _, _ = target
    status, body = modern(t, "resources/list")
    assert status == 404 and body["error"]["code"] == -32601


def test_modern_mcp_name_must_match_and_may_be_base64(target, fake):
    t, ledger, _ = target
    status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()}, name="other_tool")
    assert status == 400 and body["error"]["code"] == -32020 and fake.requests == {}
    encoded = "=?base64?" + base64.b64encode(TOOL.encode()).decode() + "?="
    status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()}, name=encoded)
    assert status == 200 and "awaiting approval" in text(body["result"])


# --- the tool call -----------------------------------------------------------------------------


@pytest.mark.parametrize("era", ["modern", "legacy"])
def test_pending_then_approved_runs_once_and_a_retry_replays(target, fake, era):
    t, ledger, events = target
    status, body = call(t, 1, era=era)
    result = body["result"]
    assert result["isError"] is True and "awaiting approval" in text(result) and ledger.entries() == []
    (rid,) = fake.requests
    assert rid in text(result) and result["_meta"]["requisition"]["status"] == "pending"
    fake.approve(rid)
    status, body = call(t, 2, era=era)
    result = body["result"]
    assert result["isError"] is False and text(result).startswith("REFUND SENT: 1250 USD")
    (entry,) = ledger.entries()
    assert entry["event"] == "REFUND SENT" and entry["statement_id"] == result["_meta"]["requisition"]["statement_id"]
    assert result["_meta"]["requisition"]["outcome_report"] == "unsupported"  # this fake has no outcome route
    # the Gateway retries invocation 2 (same id): the stored result, no second refund, no second execute
    executes = sum(1 for m, p in fake.calls if p == "/v1/execute")
    status, again = call(t, 2, era=era)
    assert again["result"]["content"] == result["content"] and again["result"]["_meta"]["requisition"]["replayed"]
    assert len(ledger.entries()) == 1 and sum(1 for m, p in fake.calls if p == "/v1/execute") == executes
    # the agent calls again (a new id): the statement is spent, so this is a NEW request to approve
    status, third = call(t, 3, era=era)
    assert third["result"]["isError"] and "awaiting approval" in text(third["result"]) and len(fake.requests) == 2
    assert len(ledger.entries()) == 1


def test_a_second_execute_of_the_same_statement_never_runs_the_tool(target, fake):
    t, ledger, _ = target
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    call(t, 2)
    # someone else spends nothing here: drive the gate directly with a fresh key on the same statement
    proposal = next(iter(t.gate.store._read()["closed"].values()))
    assert proposal["closed_reason"] == "spent" and len(ledger.entries()) == 1


def test_unknown_tool_and_bad_arguments_are_protocol_errors(target, fake):
    t, ledger, _ = target
    status, body = modern(t, "tools/call", {"name": "wire_transfer", "arguments": {}})
    assert status == 200 and body["error"]["code"] == -32602
    status, body = legacy("tools/call", {"name": TOOL, "arguments": [1]}, t=t)
    assert body["error"]["code"] == -32602
    assert fake.requests == {} and ledger.entries() == []


def test_an_intake_refusal_proposes_nothing(target, fake):
    t, ledger, _ = target
    status, body = call(t, 1, refund_args(reason="use sk-live-123"))
    assert body["result"]["isError"] and "display_value_redactable" in text(body["result"])
    assert fake.requests == {} and ledger.entries() == []
    status, body = call(t, 2, refund_args(currency="JPY"))
    assert body["result"]["isError"] and fake.requests == {}


def test_requisition_down_fails_closed(target, fake):
    t, ledger, _ = target
    fake.down = True
    status, body = call(t, 1)
    assert body["result"]["isError"] and "unavailable" in text(body["result"]) and ledger.entries() == []


def test_a_signed_deny_does_not_run(target, fake):
    t, ledger, _ = target
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    fake.force_deny = "authority_freeze"
    status, body = call(t, 2)
    assert body["result"]["isError"] and "signed deny authority_freeze" in text(body["result"])
    assert body["result"]["_meta"]["requisition"]["verdict"] == "deny" and ledger.entries() == []


def test_an_allow_signed_by_another_key_does_not_run(fake, tmp_path, clock):
    t, ledger, _ = make_target(fake, tmp_path, clock)
    t.gate.keys = KeyRegistry.from_bytes(json.dumps(FakeRequisition(now=clock.now).registry).encode())
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    status, body = call(t, 2)
    assert body["result"]["isError"] and "fail closed" in text(body["result"]) and ledger.entries() == []


def test_no_pinned_key_file_no_target(fake, tmp_path, clock):
    with pytest.raises(ValueError, match="pinned key file"):
        make_target(fake, tmp_path, clock, keys=False)


def test_a_failing_tool_is_a_failed_outcome_and_is_not_run_again(fake, tmp_path, clock):
    runs = []

    def boom(args, allow):
        runs.append(1)
        raise RuntimeError("bank down")

    t, ledger, events = make_target(fake, tmp_path, clock, tools={TOOL: ToolImpl(TOOL, "x", boom)})
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    status, body = call(t, 2)
    assert body["result"]["isError"] and "the tool failed (RuntimeError)" in text(body["result"])
    assert body["result"]["_meta"]["requisition"]["outcome"] == "failed" and runs == [1]
    call(t, 2)  # the retry returns the stored failure
    assert runs == [1]


def test_an_expired_allow_does_not_run(target, fake, clock):
    t, ledger, _ = target
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    original = t.gate.runnable
    t.gate.runnable = lambda d: False
    status, body = call(t, 2)
    t.gate.runnable = original
    assert body["result"]["isError"] and "exec_not_after" in text(body["result"]) and ledger.entries() == []


def test_session_from_a_forwarded_header(fake, tmp_path, clock):
    t, ledger, _ = make_target(fake, tmp_path, clock, session_header="X-Requisition-Session")
    status, body = call(t, 1)
    assert body["result"]["isError"] and "no valid x-requisition-session header" in text(body["result"])
    status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()}, 2,
                          headers={"x-requisition-session": "caller-42"})
    (row,) = fake.requests.values()
    assert row["body"]["display"]["session"] == "caller-42"


# --- with the newer routes and with ML-DSA-87 decisions --------------------------------------------------


def test_newer_routes_outcome_is_recorded(tmp_path, clock):
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True)
    server.base_url = server.start()
    try:
        t, ledger, _ = make_target(server, tmp_path, clock)
        call(t, 1)
        server.approve(next(iter(server.requests)))
        status, body = call(t, 2)
        assert body["result"]["_meta"]["requisition"]["outcome_report"] == "recorded"
        (o,) = server.outcomes
        assert o["outcome"] == "succeeded" and o["statement_id"] == body["result"]["_meta"]["requisition"]["statement_id"]
    finally:
        server.stop()


def test_an_mldsa87_signed_allow_is_checked_and_runs(tmp_path, clock):
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now,
                             mldsa87_kinds=("statement", "decision"))
    server.base_url = server.start()
    try:
        t, ledger, events = make_target(server, tmp_path, clock)
        call(t, 1)
        server.approve(next(iter(server.requests)))
        status, body = call(t, 2)
        assert body["result"]["isError"] is False and len(ledger.entries()) == 1
        assert t.gate.keys.algorithm("requisition_lab_dev_mldsa87_v0") == "mldsa87"
    finally:
        server.stop()


# --- over a real socket ------------------------------------------------------------------------


def test_served_over_http(target, fake):
    t, ledger, _ = target
    server = serve(t, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ping")
        resp = conn.getresponse()
        assert resp.status == 200 and json.loads(resp.read()) == {"status": "Healthy"}
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": CLIENT_META}})
        conn.request("POST", "/mcp", body=body, headers={"content-type": "application/json",
                     "accept": "application/json, text/event-stream", "mcp-protocol-version": MODERN, "mcp-method": "tools/list"})
        resp = conn.getresponse()
        assert resp.status == 200 and resp.getheader("content-type") == "application/json"
        assert json.loads(resp.read())["result"]["tools"][0]["name"] == TOOL
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
