# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The Strands hook, driven through a real strands.Agent with a scripted (no-network) model."""

import pytest
from strands import Agent, tool

from requisition_aws import canonical

from requisition_aws.scripted_model import ScriptedModel
from requisition_aws.strands_hook import INTERRUPT_NAME, RequisitionHook

from .conftest import ACT_TYPE, TOOL, refund_args

RAN: list[dict] = []


@tool
def payments_refund_send(amount_minor: int, currency: str, account: str, reason: str) -> str:
    """Send a refund (test stub)."""
    RAN.append({"amount_minor": amount_minor, "currency": currency, "account": account, "reason": reason})
    return "REFUND SENT"


@tool
def unregistered_tool(x: int) -> str:
    """A tool with no act type."""
    RAN.append({"unregistered": x})
    return "RAN"


@pytest.fixture(autouse=True)
def _reset():
    RAN.clear()


def make_agent(gate, registry, turns, events=None):
    hook = RequisitionHook(gate, registry, agent_name="refund-agent", session_id="s-1",
                           on_event=(events.append if events is not None else None))
    agent = Agent(model=ScriptedModel(turns), tools=[payments_refund_send, unregistered_tool],
                  hooks=[hook], callback_handler=None)
    return agent, hook


def tool_results(agent):
    out = []
    for message in agent.messages:
        for block in message.get("content", []):
            if "toolResult" in block:
                out.append(block["toolResult"])
    return out


def resume(agent, result, response="look again"):
    return agent([{"interruptResponse": {"interruptId": i.id, "response": response}} for i in result.interrupts])


def test_unregistered_tool_is_cancelled(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": "unregistered_tool", "input": {"x": 1}}, {"text": "done"}])
    agent("go")
    assert RAN == []
    assert "no registered act type" in str(tool_results(agent)[-1])
    assert [c for c in fake.calls if c[1] != "/v1/keys"] == []


def test_full_flow_interrupt_approve_resume_allow_then_ran_mark(gate, registry, fake):
    events = []
    agent, hook = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-1"}, {"text": "done"}], events)
    result = agent("refund it")
    assert result.stop_reason == "interrupt" and RAN == []
    [interrupt] = result.interrupts
    assert interrupt.name == INTERRUPT_NAME
    request_id = interrupt.reason["request_id"]
    assert interrupt.reason["approval_url"] == "http://127.0.0.1:4103/approvals"

    fake.approve(request_id)
    result = resume(agent, result)
    assert result.stop_reason == "end_turn"
    assert RAN == [refund_args()]
    kinds = [e.kind for e in events]
    # on resume the callback runs from the top; the dedupe GET already answers sanctioned
    assert kinds == ["proposed", "found", "sanctioned", "decision", "allowed", "tool_ran", "outcome"]
    assert events[-1].detail["report"] == "unsupported"  # the fake without the outcome route: nothing recorded
    statement = next(r for r in hook.records if r["kind"] == "statement")
    decision = next(r for r in hook.records if r["kind"] == "decision")
    assert decision["verdict"] == "allow"
    assert gate.store.has_run(statement["record"]["receipt_hash"])


def test_resume_without_approval_cancels(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args()}, {"text": "done"}])
    result = agent("refund it")
    result = resume(agent, result, response="approved (the app's word is not trusted)")
    assert RAN == []
    assert "still pending" in str(tool_results(agent)[-1])


def test_refused_request_cancels(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args()}, {"text": "done"}])
    result = agent("refund it")
    fake.refuse(result.interrupts[0].reason["request_id"])
    resume(agent, result)
    assert RAN == []
    assert "refused" in str(tool_results(agent)[-1])


def test_second_identical_call_after_spend_files_anew_and_does_not_reuse(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [
        {"tool": TOOL, "input": refund_args(), "id": "tu-1"}, {"text": "one"},
        {"tool": TOOL, "input": refund_args(), "id": "tu-2"}, {"text": "two"},
    ])
    r = agent("refund")
    first = r.interrupts[0].reason["request_id"]
    fake.approve(first)
    resume(agent, r)
    assert len(RAN) == 1
    r = agent("refund again")
    assert r.stop_reason == "interrupt"
    assert r.interrupts[0].reason["request_id"] != first  # a spent statement is never matched again
    assert len(RAN) == 1


def test_replayed_allow_after_ran_mark_is_refused(gate, registry, fake):
    agent, hook = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-1"}, {"text": "done"}])
    r = agent("refund")
    request_id = r.interrupts[0].reason["request_id"]
    fake.approve(request_id)
    resume(agent, r)
    assert len(RAN) == 1
    # Force the replay path: the request back in dedupe (as if its close had been lost) and the same
    # toolUseId, so the same idempotency key replays the stored allow. The "tool ran" mark refuses it.
    act_hash = canonical.act_hash(ACT_TYPE, hook.records[0]["arguments"])
    gate.store.create_if_absent("proposals", act_hash, {"state": "filed", "act_type": ACT_TYPE, "request_id": request_id})
    agent2, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-1"}, {"text": "done"}])
    agent2("refund")
    assert len(RAN) == 1
    assert "was already used; a new call needs a new approval" in str(tool_results(agent2)[-1])


def test_requisition_unreachable_fails_closed(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args()}, {"text": "done"}])
    fake.down = True
    agent("refund")
    assert RAN == []
    assert "fail closed" in str(tool_results(agent)[-1])


def test_unreachable_at_execute_fails_closed(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args()}, {"text": "done"}])
    r = agent("refund")
    fake.approve(r.interrupts[0].reason["request_id"])
    fake.status_override = 503
    resume(agent, r)
    assert RAN == []
    assert "fail closed" in str(tool_results(agent)[-1])


def test_argument_refusal_is_local_and_never_truncated(gate, registry, fake):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args(reason="x" * 201)}, {"text": "done"}])
    agent("refund")
    assert RAN == []
    assert "display_member_out_of_range" in str(tool_results(agent)[-1])
    assert [c for c in fake.calls if c[1] != "/v1/keys"] == []


def test_exec_not_after_passed_cancels(gate, registry, fake, clock, monkeypatch):
    agent, _ = make_agent(gate, registry, [{"tool": TOOL, "input": refund_args()}, {"text": "done"}])
    r = agent("refund")
    fake.approve(r.interrupts[0].reason["request_id"])
    monkeypatch.setattr(gate, "runnable", lambda decision: False)
    resume(agent, r)
    assert RAN == []
    assert "exec_not_after" in str(tool_results(agent)[-1])
