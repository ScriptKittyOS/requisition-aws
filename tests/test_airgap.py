# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The --airgap step (demo_flow.airgap_check). The command and script are checked here; the container
run itself is opt-in (RUN_DOCKER_TESTS=1), since it needs docker and the
local image nikolaik/python-nodejs:python3.11-nodejs20."""

import json
import os
import pathlib
import shutil
import subprocess

import pytest

from requisition_aws.demo_flow import AIRGAP_IMAGE, Transcript, airgap_check, airgap_command, airgap_script, verify_all
from requisition_aws.gate import arguments_object

from .conftest import ACT_TYPE, refund_args
from .test_canonical import REQ_TREE
from .test_verify_offline import LAB_VERIFY

HEAVY = pathlib.Path(os.environ.get("REQUISITION_LOAD_WRAPPER") or "/nonexistent-no-wrapper")


def records_for(gate, fake):
    args = arguments_object("refund-agent", "s-air", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    allow = gate.execute(s, args, "nonce-air")
    spent = gate.execute(s, args, "nonce-air-2")
    return [{"kind": "statement", "arguments": args, "act_type": ACT_TYPE, "record": s.statement},
            {"kind": "decision", "arguments": args, "act_type": ACT_TYPE, "record": allow.decision, "verdict": "allow"},
            {"kind": "decision", "arguments": args, "act_type": ACT_TYPE, "record": spent.decision, "verdict": "deny",
             "code": "statement_spent"}]


def test_the_command_has_no_network_and_mounts_read_only(tmp_path):
    keys = tmp_path / "k.json"
    keys.write_text("{}")
    cmd = airgap_command(str(tmp_path), str(keys), str(REQ_TREE))
    assert cmd[:4] == ["docker", "run", "--rm", "--network"] and cmd[4] == "none"
    assert "--read-only" in cmd and cmd[-3:] == [AIRGAP_IMAGE, "sh", "/in/airgap/run.sh"]
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts and all(m.endswith(":ro") for m in mounts)
    assert any(m.endswith(":/req/bin/lab-verify:ro") for m in mounts)


def test_the_script_verifies_each_record_then_a_tampered_copy():
    recs = [{"kind": "statement", "act_type": ACT_TYPE}, {"kind": "decision", "act_type": ACT_TYPE}]
    script = airgap_script(recs)
    assert script.index("probe.py") < script.index("01-statement") < script.index("tamper.py")
    assert "AIRGAP-RESULT 01-statement" in script and "AIRGAP-RESULT tampered-02-decision" in script
    assert "--record /tmp/tampered.record.json" in script


def test_the_verdict_needs_no_network_every_pass_and_the_tamper_failing(tmp_path):
    recs = [{"kind": "statement", "act_type": ACT_TYPE}, {"kind": "decision", "act_type": ACT_TYPE}]
    keys = tmp_path / "k.json"
    keys.write_text("{}")

    def fake_run(output):
        return lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, output, "")

    good = ("network probe: interfaces ['lo']\nAIRGAP-PROBE no-network\nAIRGAP-RESULT 01-statement 0\n"
            "AIRGAP-RESULT 02-decision 0\ntampered copy: x\nAIRGAP-RESULT tampered-02-decision 3\n")
    common = dict(registry_path=str(keys), req_tree=str(REQ_TREE))
    assert airgap_check(recs, str(tmp_path), t=Transcript(), run=fake_run(good), **common)
    assert not airgap_check(recs, str(tmp_path), t=Transcript(), run=fake_run(good.replace("no-network", "NETWORK-PRESENT")), **common)
    assert not airgap_check(recs, str(tmp_path), t=Transcript(), run=fake_run(good.replace("tampered-02-decision 3", "tampered-02-decision 0")), **common)
    assert not airgap_check(recs, str(tmp_path), t=Transcript(), run=fake_run(good.replace("01-statement 0", "01-statement 1")), **common)


@pytest.mark.skipif(os.environ.get("RUN_DOCKER_TESTS") != "1" or not shutil.which("docker"),
                    reason="opt-in: docker (RUN_DOCKER_TESTS=1 and docker on PATH)")
def test_airgap_in_docker(gate, fake, tmp_path):
    recs = records_for(gate, fake)
    keys = tmp_path / "lab-keys.json"
    keys.write_text(json.dumps(fake.registry))
    t = Transcript()
    assert verify_all(recs, str(tmp_path), lab_verify=str(LAB_VERIFY), registry_path=str(keys), t=t)
    ok = airgap_check(recs, str(tmp_path), registry_path=str(keys), req_tree=str(REQ_TREE), t=t,
                      wrapper=(str(HEAVY),) if HEAVY.exists() else ())
    text = "\n".join(t.lines)
    assert ok, (tmp_path / "airgap" / "output.txt").read_text()
    assert "no network: confirmed" in text and "FAIL, as it must" in text
