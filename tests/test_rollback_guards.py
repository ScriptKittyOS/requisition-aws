# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The relying party's memory and the rollback demo: what each guard pins.

1. no record whose signature was not checked here ever reaches the position memory or the evidence
   (remembering before verifying is refused); a Gate without its key file refuses at the read;
2. the rollback demo talks only to its own scratch server: port 4103 refused, a port already in use refused
   before anything starts, "up" only on the server's own UP line naming the scratch database;
3. the scratch server runs no Oban queues or plugins;
4. one CLAIM, with its precondition (nothing appended between the snapshot and the mint), in the docstring, the transcript and the README;
6. verify_chain.py: an export with no positioned row is exit 2 (input), never 1 (FAIL);
7. the position is read with the strict loader;
9. the default server command runs under the load wrapper; the 4113/4103 cookie note; --dry-run stops before the
   server (the copy and the pg_dump/pg_restore round trip only).
(5, the interceptor's tool error, is asserted in test_fence.py.)
"""

import base64
import hashlib
import json
import pathlib
import socket
import subprocess
import sys

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.demo_flow import Transcript
from requisition_aws.gate import Gate, RecordInvalid, arguments_object
from requisition_aws.store import Store

from .conftest import ACT_TYPE, refund_args
from .test_fence import gate_for, lab, pos  # noqa: F401  (lab is a fixture)
from .test_rollback_demo import demo

ROOT = pathlib.Path(__file__).resolve().parent.parent
D3 = ("If Requisition's database is rolled back, the same executor, with its own records intact, refuses to act "
      "again, and the rollback leaves two different records signed by the service's key at one chain position, "
      "which anyone can check offline. Lab profile, lab key.")


def _flat(text):
    return " ".join(text.split())


def _memory(store):
    data = store._read()
    return data["positions"], data["evidence"]


# --- 1. nothing unchecked is remembered ---------------------------------------------------------


def test_a_forged_statement_signature_is_never_remembered(lab, tmp_path, clock, monkeypatch):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    lab.approve(s.request_id)
    real = gate.client.get_request

    def forged(request_id):
        answer = real(request_id)
        env = dict(answer["statement"])  # the genuine bytes and hash, a signature that is not the key's
        env["signature"] = base64.b64encode(bytes(len(base64.b64decode(env["signature"])))).decode()
        answer["statement"] = env
        return answer

    monkeypatch.setattr(gate.client, "get_request", forged)
    with pytest.raises(RecordInvalid, match="signature"):
        gate.read(s, args)
    assert _memory(gate.store) == ({}, {})
    monkeypatch.setattr(gate.client, "get_request", real)
    s = gate.read(s, args)  # the genuine record at that position: admitted, no evidence
    assert gate.store.position(*pos(s.statement)) == s.statement_id and gate.store.evidence() == []


def test_a_tampered_decision_is_never_remembered(lab, tmp_path, clock, monkeypatch):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    lab.approve(s.request_id)
    s = gate.read(s, args)
    before = _memory(gate.store)
    real = gate.client.execute

    def tamper(body):  # test_client_store_gate.py's: decided_at changed, receipt_hash recomputed
        answer = real(body)
        env = answer["decision"]
        signed = json.loads(env["signed_payload"])
        signed["metadata"]["decided_at"] = "2026-11-09T11:59:59Z"
        env["signed_payload"] = canonical.encode(signed).decode()
        env["receipt_hash"] = answer["receipt_hash"] = hashlib.sha256(env["signed_payload"].encode()).hexdigest()
        return answer

    monkeypatch.setattr(gate.client, "execute", tamper)
    with pytest.raises(RecordInvalid, match="signature"):
        gate.execute(s, args, "k1")
    assert _memory(gate.store) == before
    monkeypatch.setattr(gate.client, "execute", real)
    allow = gate.execute(s, args, "k1")  # the exact retry: the genuine allow at that position
    assert allow.allowed and gate.store.position(*pos(allow.decision)) == allow.decision["receipt_hash"]
    assert gate.store.evidence() == []


def test_a_tampered_outcome_is_never_remembered(lab, tmp_path, clock, monkeypatch):
    gate = gate_for(lab, tmp_path / "s.json", clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    lab.approve(s.request_id)
    s = gate.read(s, args)
    allow = gate.execute(s, args, "k1")
    before = _memory(gate.store)
    real = gate.client.report_outcome

    def tamper(*a, **k):
        answer = real(*a, **k)
        env = dict(answer["record"])
        signed = json.loads(env["signed_payload"])
        signed["metadata"]["reported_at"] = "2026-11-09T11:59:59Z"
        env["signed_payload"] = canonical.encode(signed).decode()
        env["receipt_hash"] = hashlib.sha256(env["signed_payload"].encode()).hexdigest()
        answer["record"] = env
        return answer

    monkeypatch.setattr(gate.client, "report_outcome", tamper)
    assert "signature" in gate.report_outcome(allow, True, "REFUND SENT")
    assert _memory(gate.store) == before
    monkeypatch.setattr(gate.client, "report_outcome", real)
    assert gate.report_outcome(allow, True, "REFUND SENT") == "recorded"  # the same report: the genuine record
    (o,) = gate.outcome_records
    assert gate.store.position(*pos(o["record"])) == o["record"]["receipt_hash"] and gate.store.evidence() == []


def test_a_gate_without_its_key_file_refuses_at_the_read_and_remembers_nothing(lab, tmp_path, clock):
    client = Client(lab.base_url, lab.credential, lab.principal, timeout=5)
    gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://x", clock=clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    lab.approve(s.request_id)
    with pytest.raises(RecordInvalid, match="no pinned key file"):
        gate.read(s, args)
    assert _memory(gate.store) == ({}, {})


# --- 7. the strict loader -----------------------------------------------------------------------


def test_admit_refuses_a_payload_with_duplicate_members(tmp_path):
    payload = '{"chain_scope":"requisition-lab:account:x","sequence":1,"sequence":2}'
    env = {"signature": "", "key_id": "k", "signed_payload": payload,
           "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}
    with pytest.raises(ValueError):
        Store(str(tmp_path / "s.json")).admit(env)


# --- 6. verify_chain: nothing positioned is an input error -------------------------------------


def test_verify_chain_an_export_with_no_positioned_row_is_exit_2(tmp_path):
    payload = json.dumps({"chain_scope": "requisition-lab:account:x", "metadata": {}})
    env = {"signature": "AA==", "key_id": "k", "signed_payload": payload,
           "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}
    (tmp_path / "e.json").write_text(json.dumps({"records": [env]}))
    (tmp_path / "k.json").write_text(json.dumps({"entries": []}))
    proc = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "verify_chain.py"), "--registry",
                           str(tmp_path / "k.json"), "--export", str(tmp_path / "e.json")],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and "Traceback" not in proc.stderr and "position" in proc.stderr


# --- 2. the demo talks only to its own server ---------------------------------------------------


@pytest.fixture
def scratch_env(monkeypatch):
    monkeypatch.setenv("SCRATCH_DB", "scratch_20261110120000_1_2")
    monkeypatch.setenv("PGDATABASE", "scratch_20261110120000_1_2")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _lab(tmp_path, port, cmd, **kw):
    return demo.ScratchLab(source_db="autonomous_agency_aws_demo2", port=port, server_cmd=cmd, out_dir=tmp_path,
                           t=Transcript(), **kw)


def test_port_4103_is_refused(scratch_env, tmp_path):
    with pytest.raises(demo.Refused, match="4103"):
        _lab(tmp_path, 4103, "true")


def test_a_port_already_in_use_is_refused_before_anything_starts(scratch_env, tmp_path):
    marker = tmp_path / "started"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        lab_ = _lab(tmp_path, port, f"touch {marker}")
        with pytest.raises(demo.Refused, match="in use"):
            lab_.start()
    assert not marker.exists()


def _sleeper(line):
    return f"{sys.executable} -c \"print({line!r}, flush=True); import time; time.sleep(30)\""


def test_up_only_on_the_servers_own_up_line_naming_the_scratch_database(scratch_env, tmp_path):
    port = _free_port()
    good = f"ROLLBACK SCRATCH SERVER UP on 127.0.0.1:{port}, database scratch_20261110120000_1_2, Oban queues and plugins off, pid 1"
    lab_ = _lab(tmp_path, port, _sleeper(good), start_timeout=20)
    try:
        lab_.start()
        assert lab_.proc is not None and lab_.proc.poll() is None
    finally:
        lab_.stop()
    other = good.replace("scratch_20261110120000_1_2", "autonomous_agency_aws_demo2")
    lab_ = _lab(tmp_path / "x", _free_port(), _sleeper(other), start_timeout=3)
    (tmp_path / "x").mkdir()
    try:
        with pytest.raises(RuntimeError, match="UP line"):
            lab_.start()
    finally:
        lab_.stop()


# --- 3. no Oban on the copy ---------------------------------------------------------------------


def test_the_scratch_server_runs_no_oban_queues_or_plugins():
    text = (ROOT / "demo" / "rollback" / "serve_scratch.exs").read_text()
    oban = text.index("Oban")
    assert "queues: false" in text and "plugins: false" in text
    assert oban < text.index("ensure_all_started") and "Oban queues and plugins off" in text


# --- 4 and 9. the claim, the server command, the note, the dry run ------------------------------


def test_one_claim_d3_verbatim_with_the_d2_precondition_in_all_three_places():
    assert demo.CLAIM.startswith(D3) and "nothing was appended between the snapshot and the mint" in demo.CLAIM
    assert _flat(demo.CLAIM) in _flat(demo.__doc__)
    assert _flat(demo.CLAIM) in _flat((ROOT / "README.md").read_text())
    text = (ROOT / "demo" / "run_rollback_local.py").read_text()
    assert "would allow (not executed here" in text


def test_the_default_server_command_runs_under_the_load_wrapper(monkeypatch, tmp_path):
    assert demo.DEFAULT_SERVER_CMD.startswith("{wrapper} ")
    monkeypatch.setenv("SCRATCH_DB", "scratch_20261110120000_1_2")
    monkeypatch.setenv("PGDATABASE", "scratch_20261110120000_1_2")
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    monkeypatch.setenv("REQUISITION_LOAD_WRAPPER", "/opt/limit.sh")
    lab = demo.ScratchLab(source_db="autonomous_agency_aws_demo2", port=4113, server_cmd=demo.DEFAULT_SERVER_CMD,
                          out_dir=tmp_path, t=Transcript())
    assert lab.server_cmd.startswith("/opt/limit.sh bash -c ")
    monkeypatch.delenv("REQUISITION_LOAD_WRAPPER")
    lab = demo.ScratchLab(source_db="autonomous_agency_aws_demo2", port=4113, server_cmd=demo.DEFAULT_SERVER_CMD,
                          out_dir=tmp_path, t=Transcript())
    assert lab.server_cmd.startswith("bash -c ")


class Recorder:
    calls: list = []

    def __init__(self, **kw):
        Recorder.calls = []
        self.url = f"http://127.0.0.1:{kw['port']}"

    def __getattr__(self, name):
        def record(*a, **k):
            Recorder.calls.append((name, k))
            return "snap" if name == "snapshot" else None
        return record


def test_dry_run_copies_and_round_trips_the_dump_then_stops_before_the_server(monkeypatch, tmp_path):
    for k, v in {"REQUISITION_CRED": "rqc_dry_run_credential_0001", "REQUISITION_PRINCIPAL": "rqp_dry_run", "REQUISITION_LAB_KEY_FILE": "/nonexistent"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    monkeypatch.setattr(demo, "ScratchLab", Recorder)
    assert demo.main(["--transcript", str(tmp_path / "t.txt"), "--dry-run"]) == 0
    names = [c[0] for c in Recorder.calls]
    assert names[:3] == ["copy_baseline", "snapshot", "restore"] and Recorder.calls[2][1] == {"restart": False}
    assert "start" not in names and "wait_approved" not in names
    text = (tmp_path / "t.txt").read_text()
    assert _flat(demo.CLAIM) in _flat(text) and "DRY RUN" in text


def test_the_transcript_says_logging_in_on_4113_logs_the_browser_out_of_4103(monkeypatch, tmp_path):
    for k, v in {"REQUISITION_CRED": "rqc_dry_run_credential_0001", "REQUISITION_PRINCIPAL": "rqp_dry_run", "REQUISITION_LAB_KEY_FILE": "/nonexistent"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    monkeypatch.setattr(demo, "ScratchLab", Recorder)
    demo.main(["--transcript", str(tmp_path / "t.txt"), "--dry-run"])
    assert "4103" in (tmp_path / "t.txt").read_text() and "logs" in (tmp_path / "t.txt").read_text()
