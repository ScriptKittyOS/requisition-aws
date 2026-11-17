# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The AgentCore Gateway REQUEST interceptor against fixtures built from AWS's documented shape
(tests/fixtures/interceptor/, each labelled "AWS documented shape, fetched 2026-11-09, not a live
Gateway") and the fake Requisition."""

import base64
import copy
import json
import pathlib

import pytest

from requisition_aws import interceptor as icp
from requisition_aws.interceptor import Interceptor
from requisition_aws.registry import ToolRegistry

from .conftest import ACT_TYPE
from .test_canonical import SEED_SCHEMA

FIX = pathlib.Path(__file__).parent / "fixtures" / "interceptor"
GATEWAY_TOOL = "refunds___payments_refund_send"


def event(name):
    data = json.loads((FIX / name).read_text())
    assert data["_comment"].startswith("AWS documented shape, fetched 2026-11-09, not a live Gateway")
    assert all(u.startswith("https://docs.aws.amazon.com/bedrock-agentcore/") for u in data["_source"])
    return data["event"]


def with_id(ev, rpc_id):
    ev = copy.deepcopy(ev)
    ev["mcp"]["gatewayRequest"]["body"]["id"] = rpc_id
    ev["mcp"]["rawGatewayRequest"]["body"] = json.dumps(ev["mcp"]["gatewayRequest"]["body"])
    return ev


@pytest.fixture
def ic(gate):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    return Interceptor(gate, reg, gateway_id="gw-fixture-0001", agent_name="agentcore-gateway")


def body_of(out):
    return out["mcp"]["transformedGatewayResponse"]["body"]


def posts(fake, path):
    return sum(1 for m, p in fake.calls if m == "POST" and p == path)


def requisition_calls(fake):
    return [c for c in fake.calls if c[1] != "/v1/keys"]


@pytest.mark.parametrize("name", ["request_tools_list.json", "request_initialize.json", "request_notification_initialized.json"])
def test_pass_through_untouched(ic, fake, name):
    ev = event(name)
    out = ic.handle(ev)
    assert out == {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": ev["mcp"]["gatewayRequest"]["body"]}}}
    assert requisition_calls(fake) == []


def test_other_methods_are_a_jsonrpc_error(ic, fake):
    out = ic.handle(event("request_resources_read.json"))
    assert body_of(out)["error"]["code"] == -32601 and body_of(out)["id"] == 11
    assert requisition_calls(fake) == []


def test_unregistered_tool_is_an_iserror_result_echoing_a_string_id(ic, fake):
    out = ic.handle(event("request_tools_call_unregistered.json"))
    body = body_of(out)
    assert body["id"] == "call-9" and body["result"]["isError"] is True
    assert "no registered act type" in body["result"]["content"][0]["text"]
    assert requisition_calls(fake) == []


def test_no_headers_fails_closed(ic, fake):
    # G1: no headers (passRequestHeaders false) is caller_identity_absent, fail closed
    out = ic.handle(event("request_tools_call_no_headers.json"))
    error = body_of(out)["error"]
    assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"
    assert "passRequestHeaders" in error["message"]
    assert requisition_calls(fake) == []


def test_awaiting_approval_then_allow_then_gateway_retry_then_new_call(ic, fake):
    ev = event("request_tools_call_refund.json")
    # 1. first call: filed, awaiting approval, the JSON-RPC id echoed
    out = ic.handle(ev)
    body = body_of(out)
    assert body["id"] == 7 and body["result"]["isError"] is True
    request_id = body["result"]["_meta"]["requisition"]["request_id"]
    assert body["result"]["content"][0]["text"].startswith(f"Requisition: awaiting approval {request_id}")
    # 2. a Gateway retry of the same invocation files nothing new
    assert body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"] == request_id
    assert posts(fake, "/v1/sanction-requests") == 1
    # 3. approved; the agent calls again (a new JSON-RPC id): execute, allow, passed through unchanged
    fake.approve(request_id)
    ev2 = with_id(ev, 8)
    out = ic.handle(ev2)
    assert out == {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": ev2["mcp"]["gatewayRequest"]["body"]}}}
    assert posts(fake, "/v1/execute") == 1 and len(fake.spent) == 1
    # 4. the same invocation again (a Gateway retry, or a client reusing its JSON-RPC id): the stored
    #    body is replayed byte for byte, but the statement already passed through once, so it is
    #    REFUSED (at most one pass-through per statement, always)
    out = ic.handle(ev2)
    assert "transformedGatewayRequest" not in out["mcp"]
    assert "already used" in body_of(out)["result"]["content"][0]["text"]
    assert posts(fake, "/v1/execute") == 2 and len(fake.claims) == 1 and len(fake.spent) == 1
    # 5. a genuinely new call with the same arguments: the spent request is never matched; a new one is filed
    out = ic.handle(with_id(ev, 9))
    new_id = body_of(out)["result"]["_meta"]["requisition"]["request_id"]
    assert new_id != request_id and posts(fake, "/v1/sanction-requests") == 2


def test_signed_deny_is_an_iserror_result(ic, fake):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    fake.approve(request_id)
    fake.force_deny = "authority_freeze"
    body = body_of(ic.handle(with_id(ev, 8)))
    assert body["id"] == 8 and body["result"]["isError"] is True
    assert body["result"]["content"][0]["text"] == "Requisition: signed deny authority_freeze"
    assert body["result"]["_meta"]["requisition"]["decision"]["signed_payload"]


def test_refused_request_is_an_iserror_result(ic, fake):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    fake.refuse(request_id)
    body = body_of(ic.handle(with_id(ev, 8)))
    assert body["result"]["isError"] is True and "was refused" in body["result"]["content"][0]["text"]


def test_requisition_unreachable_is_a_jsonrpc_error(ic, fake):
    fake.down = True
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    assert body["id"] == 7 and body["error"]["code"] == icp.FAIL_CLOSED and "fail closed" in body["error"]["message"]


def test_unavailable_at_execute_is_a_jsonrpc_error_and_retry_replays(ic, fake):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    fake.approve(request_id)
    ic.handle(ev)  # mints the statement and executes: allow
    fake.status_override = 503
    assert body_of(ic.handle(with_id(ev, 8)))["error"]["code"] == icp.FAIL_CLOSED


def test_stale_stored_body_fails_closed(ic, fake, clock):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    fake.approve(request_id)
    fake.fail_paths = {"/v1/execute"}
    assert body_of(ic.handle(with_id(ev, 8)))["error"]["code"] == icp.FAIL_CLOSED  # stored BEFORE the call, then it fails
    fake.fail_paths = set()
    clock.advance(121)
    body = body_of(ic.handle(with_id(ev, 8)))
    assert body["result"]["isError"] is True and "expired" in body["result"]["content"][0]["text"]
    assert posts(fake, "/v1/execute") == 1 and fake.spent == set()


def test_bad_arguments_are_refused_locally(ic, fake):
    ev = event("request_tools_call_refund.json")
    ev["mcp"]["gatewayRequest"]["body"]["params"]["arguments"]["amount_minor"] = 12.5
    ev["mcp"]["rawGatewayRequest"]["body"] = json.dumps(ev["mcp"]["gatewayRequest"]["body"])
    body = body_of(ic.handle(ev))
    assert body["result"]["isError"] is True and "(float_refused)" in body["result"]["content"][0]["text"]
    assert requisition_calls(fake) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(interceptorInputVersion="2.0"),
        lambda e: e.pop("mcp"),
        lambda e: e["mcp"]["gatewayRequest"].update(body="not a map"),
        lambda e: e["mcp"]["gatewayRequest"]["body"].update(jsonrpc="1.0"),
        lambda e: e["mcp"]["gatewayRequest"]["body"]["params"].update(arguments=["x"]),
        lambda e: e["mcp"]["gatewayRequest"]["body"]["params"].pop("name"),
        lambda e: e["mcp"]["rawGatewayRequest"].update(body='{"id":7,"id":8}'),
    ],
)
def test_malformed_input_is_a_jsonrpc_error(ic, fake, mutate):
    ev = event("request_tools_call_refund.json")
    mutate(ev)
    body = body_of(ic.handle(ev))
    assert "error" in body and body["error"]["code"] in (-32600, -32602)
    assert requisition_calls(fake) == []


def test_raw_body_differing_from_parsed_is_refused(ic, fake):
    ev = event("request_tools_call_refund.json")
    ev["mcp"]["rawGatewayRequest"]["body"] = ev["mcp"]["rawGatewayRequest"]["body"].replace("1250", "125000")
    assert body_of(ic.handle(ev))["error"]["code"] == -32600


def test_response_phase_passes_the_response_through(ic, fake):
    ev = event("response_phase_tools_list.json")
    out = ic.handle(ev)
    assert out["mcp"]["transformedGatewayResponse"]["body"] == ev["mcp"]["gatewayResponse"]["body"]


def test_http_target_is_refused_in_the_http_shape(ic, fake):
    out = ic.handle(event("request_http_target.json"))
    resp = out["http"]["transformedGatewayResponse"]
    assert resp["statusCode"] == 403
    assert json.loads(base64.b64decode(resp["body"]))["error"]


def test_the_callers_token_never_appears_in_any_output(ic, fake):
    for name in sorted(p.name for p in FIX.glob("*.json")):
        assert "FIXTURE-NOT-A-REAL-TOKEN" not in json.dumps(ic.handle(event(name)))


def test_lambda_handler_from_env(fake, tmp_path, monkeypatch):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"schema": "requisition.lab.seed.v1", "act_types": [
        {"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384", "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    env = {
        "REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
        "REQUISITION_GATEWAY_ID": "gw-1", "REQUISITION_TOOLS": json.dumps({GATEWAY_TOOL: ACT_TYPE}),
        "REQUISITION_SEED": str(seed), "REQUISITION_STORE": str(tmp_path / "store.json"),
        "REQUISITION_KEYS_FILE": str(keys), "REQUISITION_REQUIRE_PQ": "0",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(icp, "_INTERCEPTOR", None)
    body = body_of(icp.lambda_handler(event("request_tools_call_refund.json"), None))
    assert body["result"]["isError"] is True and "awaiting approval" in body["result"]["content"][0]["text"]


def test_lambda_handler_misconfigured_fails_closed(monkeypatch):
    monkeypatch.delenv("REQUISITION_URL", raising=False)
    monkeypatch.setattr(icp, "_INTERCEPTOR", None)
    body = body_of(icp.lambda_handler(event("request_tools_call_refund.json"), None))
    assert body["id"] == 7 and body["error"]["code"] == icp.FAIL_CLOSED
