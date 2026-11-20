# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The newer routes (idempotency_key on propose, the act_hash lookup, POST /v1/outcomes) used only
when the server answers them; against a server that predates them (the Requisition version of 2026-10-26: the lookup is
405 method_not_allowed, /v1/outcomes 404 route_unknown) everything behaves as before."""

import hashlib
import json

import pytest
from strands import Agent, tool

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate, arguments_object, idempotency_key_for, result_bytes, result_digest
from requisition_aws.keys import KeyRegistry
from requisition_aws.scripted_model import ScriptedModel
from requisition_aws.store import Store
from requisition_aws.strands_hook import RequisitionHook

from .conftest import ACT_TYPE, TOOL, refund_args
from .fake_requisition import FakeRequisition
from .test_canonical import SEED_SCHEMA


@pytest.fixture
def fake1b(clock):
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True)
    server.base_url = server.start()
    yield server
    server.stop()


def make_gate(server, path, clock):
    client = Client(server.base_url, server.credential, server.principal, timeout=5)
    return Gate(client, Store(str(path), clock=clock), approval_base_url="http://x",
                keys=KeyRegistry.from_bytes(client.keys()), clock=clock)


def args(session="s-1", **over):
    return arguments_object("refund-agent", session, ACT_TYPE, refund_args(**over))


def bodies(server, path):
    return [c for c in server.calls if c[1].startswith(path)]


# --- a server without the newer routes: today's behaviour, probed once ------------------------------------


def test_without_newer_routes_the_lookup_is_unsupported_and_propose_has_no_key(gate, fake):
    a = args()
    s = gate.file_or_find(ACT_TYPE, a)
    assert s.filed_now and gate.client.features == {"lookup": False}
    assert [c for c in fake.calls if c[1].startswith("/v1/sanction-requests?")] == [("GET", "/v1/sanction-requests?act_hash=" + s.act_hash)]
    assert "idempotency_key" not in fake.requests[s.request_id]["body"]
    gate.file_or_find(ACT_TYPE, args(session="s-2"))  # the answer is remembered: no second probe
    assert len([c for c in fake.calls if "?act_hash=" in c[1]]) == 1


def test_without_newer_routes_the_outcome_is_unsupported_and_not_retried(gate, fake):
    a = args()
    s = gate.file_or_find(ACT_TYPE, a)
    fake.approve(s.request_id)
    d = gate.execute(gate.read(s, a), a, "n-1")
    assert gate.report_outcome(d, True, "REFUND SENT") == "unsupported"
    assert gate.report_outcome(d, True, "REFUND SENT") == "unsupported"
    assert [c for c in fake.calls if c[1] == "/v1/outcomes"] == [("POST", "/v1/outcomes")]
    assert gate.client.features["outcomes"] is False


def test_the_pre_newer_routes_answers_are_the_routers():
    # the Requisition version of 2026-10-26: GET /v1/sanction-requests (any query) is a known path under
    # another method; /v1/outcomes an unknown path.
    from requisition_aws.client import UNSUPPORTED

    assert UNSUPPORTED == {(404, "route_unknown"), (405, "method_not_allowed")}


# --- a server with the newer routes ----------------------------------------------------------------------


def test_propose_carries_the_idempotency_key(fake1b, tmp_path, clock):
    gate = make_gate(fake1b, tmp_path / "s.json", clock)
    s = gate.file_or_find(ACT_TYPE, args())
    assert gate.client.features["lookup"] is True
    (key,) = fake1b.idempotency
    assert fake1b.idempotency[key] == s.request_id and len(key) == 64


def test_a_lost_local_store_finds_the_pending_request_instead_of_filing_again(fake1b, tmp_path, clock):
    a = args()
    first = make_gate(fake1b, tmp_path / "one.json", clock).file_or_find(ACT_TYPE, a)
    again = make_gate(fake1b, tmp_path / "two.json", clock).file_or_find(ACT_TYPE, a)  # a fresh store
    assert again.request_id == first.request_id and again.filed_now is False
    assert len(fake1b.requests) == 1


def test_a_lost_store_adopts_a_sanctioned_unspent_request_but_never_a_spent_one(fake1b, tmp_path, clock):
    a = args()
    g1 = make_gate(fake1b, tmp_path / "one.json", clock)
    s = g1.file_or_find(ACT_TYPE, a)
    fake1b.approve(s.request_id)
    g1.read(s, a)
    adopted = make_gate(fake1b, tmp_path / "two.json", clock).file_or_find(ACT_TYPE, a)
    assert adopted.request_id == s.request_id and adopted.status == "sanctioned"
    assert g1.execute(adopted, a, "n-1").allowed
    fresh = make_gate(fake1b, tmp_path / "three.json", clock).file_or_find(ACT_TYPE, a)
    assert fresh.request_id != s.request_id and fresh.filed_now and fresh.status == "pending"


def test_a_taken_over_reservation_files_under_the_same_key(fake1b, tmp_path, clock):
    a = args()
    gate = make_gate(fake1b, tmp_path / "s.json", clock)
    act_hash = canonical.act_hash(ACT_TYPE, a)
    reserved, record = gate.store.reserve_proposal(act_hash, ACT_TYPE)
    assert reserved
    # a filer whose propose reached the server, then crashed before writing the store
    gate.client.features["lookup"] = True
    crashed = gate.client.propose(ACT_TYPE, a, idempotency_key=idempotency_key_for(act_hash, record["token"]))
    clock.advance(61)  # past store.FILING_STALE_SECONDS: the reservation may be taken over
    gate._lookup_open = lambda h: None  # without the lookup, the key alone must dedupe
    s = gate.file_or_find(ACT_TYPE, a)
    assert s.request_id == crashed["request_id"] and len(fake1b.requests) == 1


def test_the_outcome_is_recorded_once_and_a_different_one_conflicts(fake1b, tmp_path, clock):
    gate = make_gate(fake1b, tmp_path / "s.json", clock)
    a = args()
    s = gate.file_or_find(ACT_TYPE, a)
    fake1b.approve(s.request_id)
    d = gate.execute(gate.read(s, a), a, "n-1")
    assert gate.report_outcome(d, True, "REFUND SENT") == "recorded"
    assert gate.report_outcome(d, True, "REFUND SENT") == "recorded"  # the exact retry: the stored record
    assert gate.report_outcome(d, False, "boom", "tool_error") == "not recorded: outcome_already_recorded (HTTP 409)"
    (o,) = fake1b.outcomes
    assert {k: o[k] for k in ("principal", "statement_id", "decision_receipt_hash", "outcome", "result_digest")} == {
        "principal": fake1b.principal, "statement_id": d.statement_id,
        "decision_receipt_hash": d.decision["receipt_hash"], "outcome": "succeeded",
        "result_digest": hashlib.sha256(b"REFUND SENT").hexdigest()}
    assert len(gate.outcome_records) == 2 and gate.outcome_records[0]["record"] == gate.outcome_records[1]["record"]
    signed = json.loads(gate.outcome_records[0]["record"]["signed_payload"])
    assert signed["receipt_type"] == "requisition.lab.outcome.v0" and "verdict" not in signed["metadata"]


def test_a_deny_is_never_reported_as_an_outcome(fake1b, tmp_path, clock):
    gate = make_gate(fake1b, tmp_path / "s.json", clock)
    a = args()
    s = gate.file_or_find(ACT_TYPE, a)
    fake1b.approve(s.request_id)
    s = gate.read(s, a)
    gate.execute(s, a, "n-1")
    spent = gate.execute(s, a, "n-2")
    assert spent.code == "statement_spent"
    assert gate.report_outcome(spent, True, "x") == "not recorded: not an allow" and fake1b.outcomes == []


def test_result_bytes():
    assert result_bytes(b"\x00") == b"\x00" and result_bytes("é") == "é".encode()
    assert result_bytes([{"text": "REFUND SENT"}]) == canonical.encode([{"text": "REFUND SENT"}])
    assert result_bytes({"x": 1.5}) == b'{"x":1.5}'
    assert result_digest("REFUND SENT") == hashlib.sha256(b"REFUND SENT").hexdigest()


# --- the Strands hook reports after the tool ran ---------------------------------------------------

RAN = []


@tool
def payments_refund_send(amount_minor: int, currency: str, account: str, reason: str) -> str:
    """Stub."""
    RAN.append(amount_minor)
    return "REFUND SENT"


def test_the_hook_reports_the_outcome_after_the_tool_ran(fake1b, tmp_path, clock):
    from requisition_aws.registry import ToolRegistry

    RAN.clear()
    gate = make_gate(fake1b, tmp_path / "s.json", clock)
    reg = ToolRegistry()
    reg.register(TOOL, ACT_TYPE, SEED_SCHEMA)
    events = []
    hook = RequisitionHook(gate, reg, agent_name="refund-agent", session_id="demo-1b", on_event=events.append)
    agent = Agent(model=ScriptedModel([{"tool": TOOL, "input": refund_args()}, {"text": "Done."}]),
                  tools=[payments_refund_send], hooks=[hook], callback_handler=None)
    result = agent("refund it")
    assert result.stop_reason == "interrupt"
    for rid in list(fake1b.requests):
        fake1b.approve(rid)
    agent([{"interruptResponse": {"interruptId": i.id, "response": "approved"}} for i in result.interrupts])
    assert RAN == [1250]
    (outcome,) = [e for e in events if e.kind == "outcome"]
    assert outcome.detail["outcome"] == "succeeded" and outcome.detail["report"] == "recorded"
    (o,) = fake1b.outcomes
    assert o["outcome"] == "succeeded" and o["result_digest"] == result_digest([{"text": "REFUND SENT"}])
