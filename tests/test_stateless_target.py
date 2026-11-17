# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""G1 in the target form: "The target form gets the same caller-keyed rule."

The caller header is a collision NAMESPACE, never an identity; the
target form claims one caller. It is trustworthy only when our interceptor always sets it (overwriting a
client value) and it is in the target's allowedRequestHeaders; a target deployed without the interceptor has none.

Measured: the target's call key is
``(target id, transport session, JSON-RPC id, act_hash)`` (mcp_target.py:380,386 in the version before stateless MCP); under
stateless MCP the transport session is ``""``, so two callers sending the same JSON-RPC id with the
same arguments share one key and the second gets the first's stored result (``:388-390``).

The caller reaches the target only as a header: ``Authorization`` cannot be allowlisted for
propagation, an interceptor-provided header takes precedence over a client-provided one
(https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html, read
2026-11-10). So the target is told which header names the caller (``caller_header``); with one
configured the header is required (fail closed), the call key is
``(target id, caller key, JSON-RPC id, act_hash)`` and the signed ``session`` is the configured
(or forwarded) session namespaced by the caller key, the interceptor's ``caller_session``. Its trust
is the trust of whatever sets that header (a stated limit).
"""

import json

import pytest

from requisition_aws import interceptor as icp
from requisition_aws import mcp_target
from requisition_aws.store import idempotency_key

from .conftest import ACT_TYPE, refund_args
from .test_mcp_target import TOOL, make_target, modern

HDR = "x-requisition-caller"


def tcall(t, rpc_id, caller=None, arguments=None):
    headers = {HDR: caller} if caller is not None else {}
    return modern(t, "tools/call", {"name": TOOL, "arguments": arguments or refund_args()}, rpc_id, headers=headers)


def rq(body):
    return body["result"]["_meta"]["requisition"]


@pytest.fixture
def keyed(fake, tmp_path, clock):
    def build():
        return make_target(fake, tmp_path, clock, caller_header=HDR)

    return build


def test_with_a_caller_header_configured_a_call_without_it_is_refused(keyed, fake):
    t, ledger, _ = keyed()
    status, body = tcall(t, 1)
    assert status == 200 and body["result"]["isError"] is True
    assert "caller" in body["result"]["content"][0]["text"] and "fail closed" in body["result"]["content"][0]["text"]
    assert [c for c in fake.calls if c[1] != "/v1/keys"] == [] and ledger.entries() == []


def test_the_signed_session_is_the_configured_session_namespaced_by_the_caller(keyed, fake):
    t, _, _ = keyed()
    _, body = tcall(t, 1, caller="caller-a")
    display = fake.requests[rq(body)["request_id"]]["body"]["display"]
    assert display["session"] == icp.caller_session("caller-a", "sess-1")


def test_two_callers_with_the_same_jsonrpc_id_never_share_a_result(keyed, fake):
    t, ledger, _ = keyed()
    _, body = tcall(t, 1, caller="caller-a")
    rid = rq(body)["request_id"]
    fake.approve(rid)
    _, body = tcall(t, 2, caller="caller-a")
    assert body["result"]["isError"] is False and len(ledger.entries()) == 1
    # caller b, the same JSON-RPC id 2, the same arguments, no transport session: never a's stored result
    _, body = tcall(t, 2, caller="caller-b")
    assert body["result"]["isError"] is True and rq(body).get("replayed") is not True
    assert rq(body)["status"] == "pending" and rq(body)["request_id"] != rid
    assert len(ledger.entries()) == 1


def test_one_caller_pending_then_approved_recall_runs_once_and_a_retry_replays(keyed, fake):
    t, ledger, _ = keyed()
    _, body = tcall(t, 1, caller="caller-a")
    rid = rq(body)["request_id"]
    fake.approve(rid)
    _, ran = tcall(t, 2, caller="caller-a")
    assert ran["result"]["isError"] is False
    display = fake.requests[rid]["body"]["display"]
    from requisition_aws import canonical

    key = idempotency_key("agentcore-mcp-target", "target-test", "caller-a", 2, canonical.act_hash(ACT_TYPE, display))
    assert t.gate.store.get("target_results", key) is not None
    _, again = tcall(t, 2, caller="caller-a")
    assert rq(again)["replayed"] is True and len(ledger.entries()) == 1


@pytest.mark.parametrize("value", ["", " caller-a", "caller\na", "x" * 513])
def test_a_malformed_caller_header_is_refused(keyed, fake, value):
    t, ledger, _ = keyed()
    _, body = tcall(t, 1, caller=value)
    assert body["result"]["isError"] is True and "fail closed" in body["result"]["content"][0]["text"]
    assert [c for c in fake.calls if c[1] != "/v1/keys"] == []


def test_from_env_reads_the_caller_header(fake, tmp_path):
    seed = tmp_path / "seed.json"
    from .test_canonical import SEED_SCHEMA

    seed.write_text(json.dumps({"schema": "requisition.lab.seed.v1", "act_types": [
        {"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384", "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    target, _ = mcp_target.from_env({
        "REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
        "REQUISITION_SEED": str(seed), "REQUISITION_KEYS_FILE": str(keys), "REQUISITION_REQUIRE_PQ": "0",
        "REQUISITION_STORE": str(tmp_path / "s.json"), "REQUISITION_LEDGER": str(tmp_path / "l.jsonl"),
        "REQUISITION_CALLER_HEADER": "X-Requisition-Caller"})
    assert target.caller_header == HDR


def test_the_caller_header_is_documented_as_a_namespace_never_an_identity():
    # the header is trustworthy only when our interceptor ALWAYS sets it,
    # overwriting any client value, and it is in the target's allowedRequestHeaders; a target
    # deployed without the interceptor sees it as client text
    doc = " ".join(mcp_target.__doc__.split())
    assert "namespace, never an identity" in doc and "client text" in doc
