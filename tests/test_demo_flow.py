# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The demo's loop (requisition_aws.demo_flow) against the fake Requisition, with a scripted model and
an approver that approves while the app polls. demo/run_demo.py itself is not run here (it needs the
live lab); it is only compiled."""

import json
import py_compile
import pathlib

from strands import Agent, tool

from requisition_aws.demo_flow import Transcript, replay_attempt, run_agent, verify_all
from requisition_aws.scripted_model import ScriptedModel
from requisition_aws.strands_hook import RequisitionHook

from .conftest import TOOL, refund_args
from .test_verify_offline import LAB_VERIFY

ROOT = pathlib.Path(__file__).resolve().parent.parent
SENT = []


@tool
def payments_refund_send(amount_minor: int, currency: str, account: str, reason: str) -> str:
    """Stub."""
    SENT.append(amount_minor)
    return "REFUND SENT"


def test_run_demo_compiles():
    py_compile.compile(str(ROOT / "demo" / "run_demo.py"), doraise=True)


def test_the_whole_demo_flow(gate, registry, fake, tmp_path):
    SENT.clear()
    t = Transcript(secrets_to_elide=(fake.credential,))
    hook = RequisitionHook(gate, registry, agent_name="refund-agent", session_id="demo-1",
                           on_event=lambda e: t.say(f"hook: {e.kind} {e.detail}"))
    agent = Agent(model=ScriptedModel([{"tool": TOOL, "input": refund_args()}, {"text": "Done."}]),
                  tools=[payments_refund_send], hooks=[hook], callback_handler=None)
    polls = []

    def approver_sleep(_seconds):
        polls.append(1)
        if len(polls) == 2:  # the two approvals land while the app polls
            for rid, row in fake.requests.items():
                fake.approve(rid)

    result = run_agent(agent, hook, gate, "refund it", t, poll=0, timeout=30, sleep=approver_sleep)
    assert result.stop_reason == "end_turn" and SENT == [1250]
    spent = replay_attempt(gate, hook, t)
    assert spent["verdict"] == "deny" and spent["code"] == "statement_spent"
    registry_path = tmp_path / "keys.json"
    registry_path.write_text(json.dumps(fake.registry))
    assert verify_all(hook.records, str(tmp_path / "records"), lab_verify=str(LAB_VERIFY),
                      registry_path=str(registry_path), t=t)
    transcript = tmp_path / "transcript.txt"
    t.write(str(transcript))
    text = transcript.read_text()
    assert fake.credential not in text
    assert "APPROVE AT   http://127.0.0.1:4000/approvals" in text
    assert "signed verdict: deny statement_spent" in text
    assert text.count("verdict_code: lab_dev_key") == 3  # the statement, the allow, the spent deny


def test_timeout_resumes_and_the_hook_refuses(gate, registry, fake, tmp_path):
    SENT.clear()
    t = Transcript()
    hook = RequisitionHook(gate, registry, agent_name="refund-agent", session_id="demo-2")
    agent = Agent(model=ScriptedModel([{"tool": TOOL, "input": refund_args()}, {"text": "Held."}]),
                  tools=[payments_refund_send], hooks=[hook], callback_handler=None)
    run_agent(agent, hook, gate, "refund it", t, poll=0, timeout=0, sleep=lambda s: None)
    assert SENT == []
    assert any("timed out" in line for line in t.lines)


# --- with the newer routes (planned shapes): co-signatures required, the outcome record checked ---


def test_the_whole_demo_flow_with_newer_routes_and_pq_required(tmp_path, clock):
    from requisition_aws import canonical
    from requisition_aws.client import Client
    from requisition_aws.gate import Gate
    from requisition_aws.keys import KeyRegistry
    from requisition_aws.registry import ToolRegistry
    from requisition_aws.store import Store

    from .conftest import ACT_TYPE
    from .fake_requisition import FakeRequisition
    from .test_canonical import SEED_SCHEMA

    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True, cosign="signed")
    server.base_url = server.start()
    try:
        client = Client(server.base_url, server.credential, server.principal, timeout=5)
        gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://127.0.0.1:4000",
                    keys=KeyRegistry.from_bytes(client.keys()), clock=clock, require_pq=True)
        reg = ToolRegistry()
        reg.register(TOOL, ACT_TYPE, SEED_SCHEMA)
        SENT.clear()
        t = Transcript(secrets_to_elide=(server.credential,))
        hook = RequisitionHook(gate, reg, agent_name="refund-agent", session_id="demo-pq")
        agent = Agent(model=ScriptedModel([{"tool": TOOL, "input": refund_args()}, {"text": "Done."}]),
                      tools=[payments_refund_send], hooks=[hook], callback_handler=None)
        run_agent(agent, hook, gate, "refund it", t, poll=0, timeout=30,
                  sleep=lambda s: [server.approve(r) for r in list(server.requests)])
        assert SENT == [1250]
        replay_attempt(gate, hook, t)
        assert [r["kind"] for r in hook.records] == ["statement", "decision", "outcome", "decision"]
        keys = tmp_path / "keys.json"
        keys.write_text(json.dumps(server.registry))
        assert verify_all(hook.records, str(tmp_path / "records"), lab_verify=str(LAB_VERIFY),
                          registry_path=str(keys), t=t, require_pq=True), "\n".join(t.lines)
        text = "\n".join(t.lines)
        assert text.count("post-quantum REQUIRED (--require-pq): met") == 4
        assert "outcome reported by the caller (not proof the effect happened): succeeded" in text
    finally:
        server.stop()


def test_the_target_flow(tmp_path, clock):
    from requisition_aws import canonical
    from requisition_aws.client import Client
    from requisition_aws.gate import Gate
    from requisition_aws.keys import KeyRegistry
    from requisition_aws.mcp_target import Ledger, McpTarget, refund_tool
    from requisition_aws.registry import ToolRegistry
    from requisition_aws.store import Store
    from requisition_aws.target_flow import capture_records, run_target_flow

    from .conftest import ACT_TYPE
    from .fake_requisition import FakeRequisition
    from .test_canonical import SEED_SCHEMA

    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True, cosign="signed")
    server.base_url = server.start()
    try:
        client = Client(server.base_url, server.credential, server.principal, timeout=5)
        gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://127.0.0.1:4000",
                    keys=KeyRegistry.from_bytes(client.keys()), clock=clock)
        reg = ToolRegistry()
        reg.register("payments_refund_send", ACT_TYPE, SEED_SCHEMA)
        ledger = Ledger(str(tmp_path / "ledger.jsonl"))
        target = McpTarget(gate, reg, {"payments_refund_send": refund_tool(ledger)}, target_id="t-1",
                           agent_name="agentcore-gateway-demo", session="demo-target")
        records = capture_records(gate, ACT_TYPE)
        t = Transcript()
        out = run_target_flow(target, ledger, refund_args(amount_minor=4200), t, approval_url="http://127.0.0.1:4000/approvals",
                              poll=0, timeout=30, sleep=lambda s: [server.approve(r) for r in list(server.requests)][:0])
        text = "\n".join(t.lines)
        assert out["ran"] and out["after_retry"] == 1 and out["final_ledger"] == 1, text
        assert out["outcome_report"] == "recorded"
        assert "TOOL ERROR, the refund did NOT run: Requisition: awaiting approval" in text
        assert "the stored result returned (replayed); ledger: 1 refund(s)" in text
        assert [r["kind"] for r in records] == ["statement", "decision", "outcome"]
        keys = tmp_path / "keys.json"
        keys.write_text(json.dumps(server.registry))
        assert verify_all(records, str(tmp_path / "records"), lab_verify=str(LAB_VERIFY), registry_path=str(keys),
                          t=t, require_pq=True), "\n".join(t.lines)
    finally:
        server.stop()
