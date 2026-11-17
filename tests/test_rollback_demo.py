# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""demo/run_rollback_local.py: its flow (steps 3-10) driven against the fake through a FakeLab with the
ScratchLab interface (the fake's snapshot/restore stand in for pg_dump/pg_restore; its export for
bin/export_chain.sh), and its refusals. The real run (Postgres, a second server) is not run here."""

import importlib.util
import json
import pathlib

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.demo_flow import Transcript
from requisition_aws.gate import Gate
from requisition_aws.keys import KeyRegistry
from requisition_aws.mcp_target import Ledger, McpTarget, refund_tool
from requisition_aws.registry import ToolRegistry
from requisition_aws.store import Store

from .conftest import ACT_TYPE
from .fake_requisition import FakeRequisition
from .test_canonical import SEED_SCHEMA

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _demo():
    spec = importlib.util.spec_from_file_location("run_rollback_local", ROOT / "demo" / "run_rollback_local.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


demo = _demo()


class FakeLab:
    def __init__(self, fake, clock):
        self.fake, self.clock, self.approved = fake, clock, []

    def wait_approved(self, request_id, approved_file):
        assert self.fake.requests[request_id]["statement"] is None  # nothing minted before the snapshot
        self.fake.approve(request_id)
        self.approved.append(request_id)

    def snapshot(self):
        return self.fake.snapshot()

    def restore(self, snap):
        self.clock.advance(5)  # time moves on: the re-mint differs from S by occurred_at
        self.fake.restore(snap)

    def export(self, scope, path):
        path = path.with_suffix(".json")
        path.write_text(json.dumps(self.fake.export(scope)))
        return path


@pytest.mark.parametrize("cosign", [None, "signed"])
def test_the_demo_flow_refuses_the_reminted_approval_and_the_stranger_check_fails(tmp_path, clock, cosign):
    fake = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True,
                           cosign=cosign)
    fake.base_url = fake.start()
    try:
        fake.pump_denies(3)  # other records already on the account chain
        client = Client(fake.base_url, fake.credential, fake.principal, timeout=5)
        keys_bytes = client.keys()
        registry_path = tmp_path / "lab-keys.json"
        registry_path.write_bytes(keys_bytes)
        gate = Gate(client, Store(str(tmp_path / "store.json"), clock=clock), approval_base_url=fake.base_url,
                    keys=KeyRegistry.from_bytes(keys_bytes), clock=clock, require_pq=cosign == "signed")
        reg = ToolRegistry()
        reg.register(demo.TOOL, ACT_TYPE, SEED_SCHEMA)
        ledger = Ledger(str(tmp_path / "ledger.jsonl"))
        target = McpTarget(gate, reg, {demo.TOOL: refund_tool(ledger)}, target_id="t-rollback",
                           agent_name="agentcore-gateway-demo", session="rollback-test")
        t = Transcript()
        out = demo.run_rollback(FakeLab(fake, clock), gate, target, ledger, registry_path, tmp_path, t)
        text = "\n".join(t.lines)
        assert out["ok"], text
        assert out["restored_status"] == "sanctioned" and out["new_statement"] and out["refused"]
        assert out["final_ledger"] == 1 and len(ledger.entries()) == 1
        assert {"held_record_differs", "equivocation", "export_short"} <= set(out["verify_codes"])
        assert "the old weakness" in text and "EVIDENCE authority_equivocated" in text
    finally:
        fake.stop()


def test_the_flow_stops_when_records_were_appended_between_snapshot_and_mint(tmp_path, clock):
    fake = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True)
    fake.base_url = fake.start()
    try:
        client = Client(fake.base_url, fake.credential, fake.principal, timeout=5)
        keys_bytes = client.keys()
        (tmp_path / "k.json").write_bytes(keys_bytes)
        gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url=fake.base_url,
                    keys=KeyRegistry.from_bytes(keys_bytes), clock=clock)
        reg = ToolRegistry()
        reg.register(demo.TOOL, ACT_TYPE, SEED_SCHEMA)
        ledger = Ledger(str(tmp_path / "l.jsonl"))
        target = McpTarget(gate, reg, {demo.TOOL: refund_tool(ledger)}, target_id="t", agent_name="a", session="s")

        class Interleaved(FakeLab):
            def snapshot(self):
                snap = super().snapshot()
                self.fake.pump_denies(1)  # someone else appends after the snapshot, before the mint
                return snap

        t = Transcript()
        out = demo.run_rollback(Interleaved(fake, clock), gate, target, ledger, tmp_path / "k.json", tmp_path, t)
        assert out["ok"] is False and "records were appended between the snapshot and S; the demo stops here" in "\n".join(t.lines)
    finally:
        fake.stop()


@pytest.mark.parametrize("env", [
    {},
    {"SCRATCH_DB": "autonomous_agency_dev", "PGDATABASE": "autonomous_agency_dev"},
    {"SCRATCH_DB": "scratch_20261110120000_1_2", "PGDATABASE": "autonomous_agency_aws_demo2"},
])
def test_the_scratch_lab_refuses_anything_but_a_scratch_db_database(env, monkeypatch, tmp_path):
    for k in ("SCRATCH_DB", "PGDATABASE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(demo.Refused):
        demo.ScratchLab(source_db="autonomous_agency_aws_demo2", port=4113, server_cmd="true", out_dir=tmp_path,
                        t=Transcript())


def test_the_scratch_lab_refuses_the_scratch_db_as_its_own_source(monkeypatch, tmp_path):
    monkeypatch.setenv("SCRATCH_DB", "scratch_20261110120000_1_2")
    monkeypatch.setenv("PGDATABASE", "scratch_20261110120000_1_2")
    with pytest.raises(demo.Refused):
        demo.ScratchLab(source_db="scratch_20261110120000_1_2", port=4113, server_cmd="true", out_dir=tmp_path, t=Transcript())
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    monkeypatch.setenv("REQUISITION_LOAD_WRAPPER", str(tmp_path / "limit.sh"))
    lab = demo.ScratchLab(source_db="autonomous_agency_aws_demo2", port=4113, server_cmd=demo.DEFAULT_SERVER_CMD,
                          out_dir=tmp_path, t=Transcript())
    assert "4103" not in lab.server_cmd and "REQ_E2E_DB_NAME=\"$SCRATCH_DB\"" in lab.server_cmd
    assert lab.server_cmd.startswith(str(tmp_path / "limit.sh") + " bash -c ")
    assert "source " + str(tmp_path) + "/env.sh" in lab.server_cmd


def test_main_refuses_outside_scratch_db(monkeypatch, tmp_path):
    for k in ("SCRATCH_DB", "PGDATABASE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in {"REQUISITION_CRED": "c", "REQUISITION_PRINCIPAL": "p", "REQUISITION_LAB_KEY_FILE": "/nonexistent"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    assert demo.main(["--transcript", str(tmp_path / "t.txt")]) == 2
    assert "REFUSED" in (tmp_path / "t.txt").read_text()
