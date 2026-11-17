# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""F1: the relying party's own memory, kept outside
Requisition's rollback domain. The interfaces below:

INTERFACE (requisition_aws/store.py; requisition_aws/fence.py holds the codes and helpers):

* ``Store.admit(record, *, spend=None) -> Admission``: ONE ``_transaction`` (flock, re-read, fsync,
  replace). ``record`` is a four-field envelope whose signature the gate has already checked.
  1. position memory: ``(chain_scope, sequence)`` from the SIGNED payload -> ``receipt_hash``. Unknown
     position: remember it. Same hash: known, no change. Different hash: ``authority_equivocated``;
     both records are saved as one evidence entry IN THE SAME TRANSACTION; nothing else is written.
     No ordering rule: an older or unseen-older position is not evidence; gaps are normal.
  2. only with ``spend`` (the claim before acting on an allow): ``spend`` =
     ``{"statement_id", "approval_request_id", **info}``. The approval already spent ->
     ``approval_already_used``; the statement already run -> refused (the existing ``ran``);
     otherwise both are written, in the same transaction, before the effect.
  ``Admission``: ``.code`` (None = admitted), ``.known`` (this exact record was already held),
  ``.evidence`` (the entries this call wrote).
* new Store namespaces ``positions``, ``approvals`` and ``evidence`` (beside ``ran``);
* ``Store.position(chain_scope, sequence) -> receipt_hash | None``;
  ``Store.evidence() -> [{"code", "chain_scope", "sequence", "held", "presented"}]``;
  ``Store.approval_spent(approval_request_id) -> bool``; ``Store.has_run`` as today.
* The gate feeds EVERY signed record it reads to the position memory: the statement (``_read``), the
  decision (``_check_decision``), the outcome record (``report_outcome``, after its signature check).
  A refusal raises a ``RequisitionError`` whose ``.code`` is the refusal code.
* The three forms claim through ``Store.admit(decision, spend=...)`` where each calls
  ``create_if_absent("ran")``/``mark_ran`` today.

ORDER OF CHECKS: signatures -> position memory (``authority_equivocated`` at that read, both
records saved) -> at execute the approval-keyed spend (``approval_already_used``) -> ``ran``.

THE ROLLBACK: snapshot after the two approvals and BEFORE the caller's first GET of the request;
the restored request is un-minted with the same ``approval_request_id``; with the act_hash lookup the
adapter adopts it and the restored service re-mints S' at S's position (its head is back to h0):
``authority_equivocated`` at the statement read. With other traffic between (pumped denies), S' lands
at a position the relying party never held: no evidence, and ``approval_already_used`` refuses alone.

Which mechanism refuses, per form : all three forms refuse the held-
position re-mint with ``authority_equivocated`` at the statement read (no execute needed), and the
unheld-position re-mint with ``approval_already_used``; the statement-keyed ``ran`` cannot match a
re-mint (a new statement id). An exact retry is refused or replayed exactly as today.
"""

import json
import threading

import pytest
from strands import Agent, tool

from requisition_aws import canonical
from requisition_aws.client import Client, RequisitionError
from requisition_aws.gate import Gate, arguments_object
from requisition_aws.interceptor import Interceptor
from requisition_aws.keys import KeyRegistry
from requisition_aws.registry import ToolRegistry
from requisition_aws.scripted_model import ScriptedModel
from requisition_aws.store import Store
from requisition_aws.strands_hook import RequisitionHook

from . import test_strands_hook as sh
from .conftest import ACT_TYPE, TOOL, refund_args
from .fake_requisition import FakeRequisition
from .test_canonical import SEED_SCHEMA
from .test_interceptor import GATEWAY_TOOL, body_of, event, with_id
from .test_mcp_target import call as target_call
from .test_mcp_target import make_target

EQUIVOCATED = "authority_equivocated"
APPROVAL_USED = "approval_already_used"


# --- helpers ------------------------------------------------------------------------------------


@pytest.fixture
def lab(clock):
    """The fake with the act_hash lookup (the adapter adopts the restored, un-minted request through it)."""
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True)
    server.base_url = server.start()
    yield server
    server.stop()


def gate_for(server, path, clock):
    client = Client(server.base_url, server.credential, server.principal, timeout=5)
    return Gate(client, Store(str(path), clock=clock), approval_base_url="http://127.0.0.1:4103",
                keys=KeyRegistry.from_bytes(client.keys()), clock=clock)


def signed(envelope):
    return json.loads(envelope["signed_payload"])


def pos(envelope):
    s = signed(envelope)
    return s["chain_scope"], s["sequence"]


def statement_of(server, request_id):
    return server.requests[request_id]["statement"]


def assert_equivocation_evidence(store, keys, held, presented):
    """One evidence entry: both records validly signed, one position, different hashes."""
    entries = [e for e in store.evidence() if e["code"] == EQUIVOCATED]
    assert len(entries) == 1, store.evidence()
    e = entries[0]
    assert e["held"]["receipt_hash"] == held["receipt_hash"]
    assert e["presented"]["receipt_hash"] == presented["receipt_hash"]
    assert pos(e["held"]) == pos(e["presented"]) == (e["chain_scope"], e["sequence"])
    assert e["held"]["receipt_hash"] != e["presented"]["receipt_hash"]
    assert keys.verify(e["held"]) and keys.verify(e["presented"])


def remint(server, clock, snap, h0, *, other_traffic=0):
    """The rollback: the database back to the snapshot (the keys stay), time moves on (S' differs from S
    by occurred_at only), optional other traffic so the re-mint lands at a position never held."""
    clock.advance(5)
    server.restore(snap)
    assert server.head() == h0  # nothing was appended between the snapshot and the original mint
    if other_traffic:
        server.pump_denies(other_traffic)


# --- Store.admit: the position memory -----------------------------------------------------------


def test_admit_remembers_every_position_and_a_second_read_is_known(lab, tmp_path, clock):
    store = Store(str(tmp_path / "s.json"), clock=clock)
    d1, d2 = lab.pump_denies(2)
    a = store.admit(d1)
    assert a.code is None and a.known is False and a.evidence == []
    assert store.position(*pos(d1)) == d1["receipt_hash"]
    again = store.admit(d1)
    assert again.code is None and again.known is True
    assert store.admit(d2).code is None and store.position(*pos(d2)) == d2["receipt_hash"]
    assert store.evidence() == []


def test_two_records_at_one_position_are_equivocation_with_both_saved(lab, tmp_path, clock):
    keys = KeyRegistry.from_bytes(json.dumps(lab.registry).encode())
    store = Store(str(tmp_path / "s.json"), clock=clock)
    (d0,) = lab.pump_denies(1)
    snap = lab.snapshot()
    (d1,) = lab.pump_denies(1)
    assert store.admit(d1).code is None
    lab.restore(snap)
    clock.advance(1)
    (d1x,) = lab.pump_denies(1)  # the restored service signs another record at d1's position
    assert pos(d1x) == pos(d1) and d1x["receipt_hash"] != d1["receipt_hash"]
    a = store.admit(d1x)
    assert a.code == EQUIVOCATED and len(a.evidence) == 1
    assert store.position(*pos(d1)) == d1["receipt_hash"]  # the held record stays
    assert_equivocation_evidence(store, keys, d1, d1x)
    # the evidence was written in the same durable transaction: a fresh Store on the same file has it
    assert_equivocation_evidence(Store(str(tmp_path / "s.json")), keys, d1, d1x)


def test_no_ordering_rule_older_unseen_and_gapped_positions_are_not_evidence(lab, tmp_path, clock):
    store = Store(str(tmp_path / "s.json"), clock=clock)
    r = lab.pump_denies(9)
    for i in (4, 2, 8, 0, 4):  # out of order, gaps, an older unseen one, a repeat
        assert store.admit(r[i]).code is None
    assert store.evidence() == []


def test_the_approval_keyed_spend_refuses_a_second_statement_for_one_approval(lab, tmp_path, clock):
    store = Store(str(tmp_path / "s.json"), clock=clock)
    d1, d2 = lab.pump_denies(2)  # stand-ins for two allows: the spend is keyed on what the caller names
    first = store.admit(d1, spend={"statement_id": "s" * 64, "approval_request_id": "appr-1", "form": "test"})
    assert first.code is None and store.has_run("s" * 64) and store.approval_spent("appr-1")
    second = store.admit(d2, spend={"statement_id": "t" * 64, "approval_request_id": "appr-1", "form": "test"})
    assert second.code == APPROVAL_USED
    assert not store.has_run("t" * 64)
    # the same statement under another approval id is still refused by ran (a re-presentation)
    third = store.admit(d2, spend={"statement_id": "s" * 64, "approval_request_id": "appr-2", "form": "test"})
    assert third.code is not None and not store.approval_spent("appr-2")


def test_equivocation_is_checked_before_the_spend_and_spends_nothing(lab, tmp_path, clock):
    store = Store(str(tmp_path / "s.json"), clock=clock)
    snap = lab.snapshot()
    (d1,) = lab.pump_denies(1)
    store.admit(d1)
    lab.restore(snap)
    clock.advance(1)
    (d1x,) = lab.pump_denies(1)
    a = store.admit(d1x, spend={"statement_id": "u" * 64, "approval_request_id": "appr-9", "form": "test"})
    assert a.code == EQUIVOCATED
    assert not store.has_run("u" * 64) and not store.approval_spent("appr-9")


def test_concurrent_claims_on_one_approval_admit_exactly_one(lab, tmp_path, clock):
    path = str(tmp_path / "s.json")
    records = lab.pump_denies(8)
    results = [None] * 8

    def claim(i):
        results[i] = Store(path, clock=clock).admit(
            records[i], spend={"statement_id": f"{i:064x}", "approval_request_id": "appr-shared", "form": "test"}).code

    threads = [threading.Thread(target=claim, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(None) == 1 and results.count(APPROVAL_USED) == 7


# --- the gate feeds every record it reads ------------------------------------------------------


def _sanctioned_and_snapshot(gate, server, args):
    s = gate.file_or_find(ACT_TYPE, args)
    server.approve(s.request_id)  # the two approvals
    h0 = server.head()
    snap = server.snapshot()  # after the approvals, before the caller's first GET
    return s, snap, h0


def test_gate_statement_decision_and_outcome_enter_the_position_memory(lab, tmp_path, clock):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s, _, _ = _sanctioned_and_snapshot(gate, lab, args)
    s = gate.read(s, args)
    assert gate.store.position(*pos(s.statement)) == s.statement_id
    allow = gate.execute(s, args, "nonce-1")
    assert gate.store.position(*pos(allow.decision)) == allow.decision["receipt_hash"]
    deny = gate.execute_fresh(s, args, "nonce-2")  # the demo's replay attempt: a signed deny is remembered too
    assert deny.code == "statement_spent" and gate.store.position(*pos(deny.decision)) == deny.decision["receipt_hash"]
    assert gate.report_outcome(allow, True, "REFUND SENT") == "recorded"
    (o,) = gate.outcome_records
    assert gate.store.position(*pos(o["record"])) == o["record"]["receipt_hash"]
    assert gate.store.evidence() == []


def test_gate_remint_at_a_held_position_is_refused_at_the_statement_read(lab, tmp_path, clock):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    keys = gate.keys
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s, snap, h0 = _sanctioned_and_snapshot(gate, lab, args)
    s = gate.read(s, args)
    allow = gate.execute(s, args, "nonce-1")
    assert allow.allowed
    gate.store.admit(allow.decision, spend={"statement_id": s.statement_id, "approval_request_id": s.approval_id,
                                            "form": "test"})
    remint(lab, clock, snap, h0)
    with pytest.raises(RequisitionError) as refused:
        gate.file_or_find(ACT_TYPE, args)  # lookup adopts the restored request; the GET re-mints S'
    assert refused.value.code == EQUIVOCATED
    s_prime = statement_of(lab, s.request_id)
    assert s_prime is not None and s_prime["receipt_hash"] != s.statement_id  # the restored service DID re-mint
    assert signed(s_prime)["metadata"]["approval_request_id"] == s.approval_id
    assert_equivocation_evidence(gate.store, keys, s.statement, s_prime)


def test_gate_remint_at_an_unheld_position_is_refused_by_the_approval_spend(lab, tmp_path, clock):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s, snap, h0 = _sanctioned_and_snapshot(gate, lab, args)
    s = gate.read(s, args)
    allow = gate.execute(s, args, "nonce-1")
    assert gate.store.admit(allow.decision, spend={"statement_id": s.statement_id, "approval_request_id": s.approval_id,
                                                   "form": "test"}).code is None
    remint(lab, clock, snap, h0, other_traffic=5)
    s2 = gate.file_or_find(ACT_TYPE, args)  # S' at a position never held: no evidence, no refusal yet
    assert s2.status == "sanctioned" and s2.statement_id != s.statement_id and s2.approval_id == s.approval_id
    again = gate.execute(s2, args, "nonce-3")
    assert again.allowed  # the old weakness, shown honestly: the restored service allows the same approval
    claim = gate.store.admit(again.decision, spend={"statement_id": s2.statement_id,
                                                    "approval_request_id": s2.approval_id, "form": "test"})
    assert claim.code == APPROVAL_USED and not gate.store.has_run(s2.statement_id)
    assert gate.store.evidence() == []


# --- the Gateway interceptor -------------------------------------------------------------------


def interceptor_for(server, tmp_path, clock):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    return Interceptor(gate_for(server, tmp_path / "icp.json", clock), reg, gateway_id="gw-fence", agent_name="agentcore-gateway")


def _interceptor_used_once(lab, ic):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    lab.approve(request_id)
    h0, snap = lab.head(), lab.snapshot()
    ev2 = with_id(ev, 8)
    out = ic.handle(ev2)
    assert "transformedGatewayRequest" in out["mcp"]  # passed through once
    return ev, ev2, request_id, statement_of(lab, request_id), snap, h0


def test_interceptor_remint_at_a_held_position_is_refused_equivocated(lab, tmp_path, clock):
    ic = interceptor_for(lab, tmp_path, clock)
    ev, _, request_id, s, snap, h0 = _interceptor_used_once(lab, ic)
    remint(lab, clock, snap, h0)
    out = ic.handle(with_id(ev, 9))
    assert "transformedGatewayRequest" not in out["mcp"]
    # a tool error naming the code, not JSON-RPC -32000 (retryable)
    result = body_of(out)["result"]
    assert result["isError"] is True and result["_meta"]["requisition"]["code"] == EQUIVOCATED
    assert_equivocation_evidence(ic.gate.store, ic.gate.keys, s, statement_of(lab, request_id))


def test_interceptor_remint_at_an_unheld_position_is_refused_approval_used(lab, tmp_path, clock):
    ic = interceptor_for(lab, tmp_path, clock)
    ev, _, _, _, snap, h0 = _interceptor_used_once(lab, ic)
    remint(lab, clock, snap, h0, other_traffic=5)
    out = ic.handle(with_id(ev, 9))
    assert "transformedGatewayRequest" not in out["mcp"]
    assert APPROVAL_USED in json.dumps(out)
    assert ic.gate.store.evidence() == []


def test_interceptor_exact_retry_unchanged_and_writes_no_evidence(lab, tmp_path, clock):
    ic = interceptor_for(lab, tmp_path, clock)
    _, ev2, request_id, s, _, _ = _interceptor_used_once(lab, ic)
    before = ic.gate.store._read()
    out = ic.handle(ev2)  # a Gateway retry: the stored allow, refused as already used (as before the fence)
    assert "transformedGatewayRequest" not in out["mcp"] and "already used" in json.dumps(out)
    assert ic.gate.store.evidence() == []
    after = ic.gate.store._read()
    assert after.get("positions") == before.get("positions")  # nothing new was remembered
    assert ic.gate.store.position(*pos(s)) == s["receipt_hash"]


def test_interceptor_a_signed_deny_is_remembered(lab, tmp_path, clock):
    ic = interceptor_for(lab, tmp_path, clock)
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    lab.approve(request_id)
    lab.force_deny = "authority_freeze"
    body = body_of(ic.handle(with_id(ev, 8)))
    deny = body["result"]["_meta"]["requisition"]["decision"]
    assert ic.gate.store.position(*pos(deny)) == deny["receipt_hash"]


# --- the Gateway target ------------------------------------------------------------------------


def _target_used_once(lab, tmp_path, clock, tools=None):
    t, ledger, _ = make_target(lab, tmp_path, clock, tools=tools)
    target_call(t, 1)
    (request_id,) = lab.requests
    lab.approve(request_id)
    h0, snap = lab.head(), lab.snapshot()
    _, body = target_call(t, 2)
    return t, ledger, body["result"], request_id, snap, h0


def test_target_remint_at_a_held_position_is_refused_equivocated(lab, tmp_path, clock):
    t, ledger, first, request_id, snap, h0 = _target_used_once(lab, tmp_path, clock)
    assert first["isError"] is False and len(ledger.entries()) == 1
    s = statement_of(lab, request_id)
    remint(lab, clock, snap, h0)
    _, body = target_call(t, 3)
    assert body["result"]["isError"] is True and EQUIVOCATED in json.dumps(body["result"])
    assert len(ledger.entries()) == 1  # the refund did not run again
    assert_equivocation_evidence(t.gate.store, t.gate.keys, s, statement_of(lab, request_id))


def test_target_remint_at_an_unheld_position_is_refused_approval_used(lab, tmp_path, clock):
    t, ledger, _, _, snap, h0 = _target_used_once(lab, tmp_path, clock)
    remint(lab, clock, snap, h0, other_traffic=5)
    _, body = target_call(t, 3)
    assert body["result"]["isError"] is True and APPROVAL_USED in json.dumps(body["result"])
    assert len(ledger.entries()) == 1
    assert t.gate.store.evidence() == []


def test_target_exact_retry_replays_the_stored_result_and_writes_no_evidence(lab, tmp_path, clock):
    t, ledger, first, request_id, _, _ = _target_used_once(lab, tmp_path, clock)
    o = first["_meta"]["requisition"]
    assert o["outcome_report"] == "recorded"
    s = statement_of(lab, request_id)
    assert t.gate.store.position(*pos(s)) == s["receipt_hash"]
    positions = t.gate.store._read().get("positions")
    assert positions  # the statement, the allow and the outcome record are held
    _, again = target_call(t, 2)
    assert again["result"]["content"] == first["content"] and again["result"]["_meta"]["requisition"]["replayed"]
    assert len(ledger.entries()) == 1 and t.gate.store.evidence() == []
    assert t.gate.store._read().get("positions") == positions


class Crash(BaseException):
    """The process dies here (not an Exception: nothing in the target may catch it)."""


def test_target_persists_the_spend_before_the_effect_and_a_crash_never_runs_twice(lab, tmp_path, clock):
    from requisition_aws.mcp_target import ToolImpl

    store_path = str(tmp_path / "store.json")
    seen = []

    def crashing(tool_args, allow):
        disk = Store(store_path)  # what a restarted process would read
        st = statement_of(lab, rid)
        seen.append({"ran": disk.has_run(allow["statement_id"]), "statement_position": disk.position(*pos(st)),
                     "approval_spent": disk.approval_spent(signed(st)["metadata"]["approval_request_id"])})
        raise Crash()

    t, ledger, _ = make_target(lab, tmp_path, clock, tools={"payments_refund_send": ToolImpl("payments_refund_send", "x", crashing)})
    target_call(t, 1)
    (rid,) = lab.requests
    lab.approve(rid)
    with pytest.raises(Crash):
        target_call(t, 2)
    assert seen == [{"ran": True, "statement_position": statement_of(lab, rid)["receipt_hash"], "approval_spent": True}]
    # restarted: a new target over the same store and ledger files; the Gateway retries the same call
    ran_again = []
    t2, ledger2, _ = make_target(lab, tmp_path, clock, tools={"payments_refund_send": ToolImpl(
        "payments_refund_send", "x", lambda a, f: ran_again.append(a) or "REFUND SENT")})
    _, retry = target_call(t2, 2)
    _, fresh = target_call(t2, 3)
    assert ran_again == [] and ledger2.entries() == []
    assert retry["result"]["isError"] is True


# --- the Strands hook --------------------------------------------------------------------------


STRANDS_STORE = {}
STRANDS_RAN: list[dict] = []


@tool
def payments_refund_send(amount_minor: int, currency: str, account: str, reason: str) -> str:
    """Send a refund (test stub that checks what is on disk at the moment of the effect)."""
    path = STRANDS_STORE.get("path")
    if path:
        disk = Store(path)
        STRANDS_STORE["at_effect"] = {"ran": list(disk._read().get("ran", {})),
                                      "approvals": [a for a in STRANDS_STORE.get("approvals", []) if disk.approval_spent(a)]}
    STRANDS_RAN.append({"amount_minor": amount_minor})
    return "REFUND SENT"


def strands_agent(gate, registry, turns):
    hook = RequisitionHook(gate, registry, agent_name="refund-agent", session_id="s-1")
    return Agent(model=ScriptedModel(turns), tools=[payments_refund_send], hooks=[hook], callback_handler=None)


@pytest.fixture(autouse=True)
def _reset_strands():
    STRANDS_RAN.clear()
    STRANDS_STORE.clear()


def _strands_used_once(lab, tmp_path, clock, registry):
    gate = gate_for(lab, tmp_path / "strands.json", clock)
    agent = strands_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-1"}, {"text": "done"}])
    result = agent("refund it")
    request_id = result.interrupts[0].reason["request_id"]
    lab.approve(request_id)
    h0, snap = lab.head(), lab.snapshot()  # while the agent is interrupted, before its first GET
    STRANDS_STORE["path"] = str(tmp_path / "strands.json")
    STRANDS_STORE["approvals"] = [lab.requests[request_id]["approval_id"]]
    sh.resume(agent, result)
    assert len(STRANDS_RAN) == 1
    return gate, request_id, snap, h0


def test_strands_persists_the_spend_before_the_tool_runs(lab, tmp_path, clock, registry):
    gate, request_id, _, _ = _strands_used_once(lab, tmp_path, clock, registry)
    s = statement_of(lab, request_id)
    assert STRANDS_STORE["at_effect"] == {"ran": [s["receipt_hash"]], "approvals": STRANDS_STORE["approvals"]}


def test_strands_remint_at_a_held_position_is_refused_equivocated(lab, tmp_path, clock, registry):
    gate, request_id, snap, h0 = _strands_used_once(lab, tmp_path, clock, registry)
    s = statement_of(lab, request_id)
    remint(lab, clock, snap, h0)
    agent = strands_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-2"}, {"text": "done"}])
    agent("refund it again")
    assert len(STRANDS_RAN) == 1
    assert EQUIVOCATED in str(sh.tool_results(agent)[-1])
    assert_equivocation_evidence(gate.store, gate.keys, s, statement_of(lab, request_id))


def test_strands_remint_at_an_unheld_position_is_refused_approval_used(lab, tmp_path, clock, registry):
    gate, request_id, snap, h0 = _strands_used_once(lab, tmp_path, clock, registry)
    remint(lab, clock, snap, h0, other_traffic=5)
    agent = strands_agent(gate, registry, [{"tool": TOOL, "input": refund_args(), "id": "tu-2"}, {"text": "done"}])
    agent("refund it again")
    assert len(STRANDS_RAN) == 1
    assert APPROVAL_USED in str(sh.tool_results(agent)[-1])
    assert gate.store.evidence() == []
