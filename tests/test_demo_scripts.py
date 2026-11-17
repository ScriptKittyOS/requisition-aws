# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The demo scripts that run against the live lab are compiled and their pure parts tested here; the whole
rehearsal was dry-run against tests/fake_server_main.py (REHEARSE_DRY=1), never against the live lab."""

import importlib.util
import json
import os
import pathlib
import py_compile
import subprocess
import sys

import pytest

from requisition_aws import mcp_target

from .test_canonical import SEED_SCHEMA

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("name", ["run_target_local.py", "run_airgap.py", "present.py", "run_demo.py"])
def test_demo_scripts_compile(name):
    py_compile.compile(str(ROOT / "demo" / name), doraise=True)


def test_rehearse_sh_parses():
    assert subprocess.run(["bash", "-n", str(ROOT / "demo" / "rehearse.sh")]).returncode == 0


def test_present_elides_credentials_and_drops_raw_lab_verify(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("present", ROOT / "demo" / "present.py")
    present = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(present)
    lines = ["[12:00:00] principal rqp_1 credential rqc_abcDEF_123", "      | verify_receipt.py raw",
             "    == 2. the record: bin/lab-verify, unchanged", "Authorization: Bearer abc.def",
             "key AKIAABCDEFGHIJKLMNOP here", "the secret s3cr3t-value", "act_hash " + "a" * 96,
             "    verdict: PASS -- fine"]
    out = present.present(lines, ["s3cr3t-value"])
    text = "\n".join(out)
    assert "rqc_" not in text and "abc.def" not in text and "AKIA" not in text and "s3cr3t" not in text
    assert "raw" not in text and "== 2." not in text and "[12:00:00]" not in text
    assert "act_hash aaaaaaaaaaaaaaaa..." in text and "    verdict: PASS -- fine" in text


def test_dockerfile_copies_what_exists():
    text = (ROOT / "deploy" / "target" / "Dockerfile").read_text()
    for src in ("requisition_aws/", "bin/vendor/"):
        assert f"COPY {src}" in text and (ROOT / src).is_dir()
    assert "--platform=linux/arm64" in text and "MCP_HOST=0.0.0.0 MCP_PORT=8000 MCP_PATH=/mcp" in text
    assert 'CMD ["python", "-m", "requisition_aws.mcp_target"]' in text


def test_the_target_never_imports_strands():
    text = (ROOT / "requisition_aws" / "mcp_target.py").read_text() + (ROOT / "requisition_aws" / "gate.py").read_text()
    assert "strands" not in text


def test_from_env_requires_the_key_file_and_builds(fake, tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"act_types": [{"registration": {"name": "payments.refund_send",
                                                                "act_hash_derivation": "args_sha384",
                                                                "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    env = {"REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
           "REQUISITION_SEED": str(seed), "REQUISITION_STORE": str(tmp_path / "s.json"),
           "REQUISITION_LEDGER": str(tmp_path / "l.jsonl"), "MCP_PORT": "8123"}
    with pytest.raises(KeyError):
        mcp_target.from_env(env)
    target, opts = mcp_target.from_env({**env, "REQUISITION_KEYS_FILE": str(keys), "REQUISITION_REQUIRE_PQ": "1"})
    assert opts == {"host": "127.0.0.1", "port": 8123, "mcp_path": "/mcp"} and target.gate.require_pq


def _rehearse_with_a_recording_uv(tmp_path, **extra_env):
    """Runs the REAL demo/rehearse.sh with a stub `uv` first on PATH. The stub runs nothing: it appends one line per
    call, `<REQUISITION_DEMO_DIR as the demo process would see it, or UNSET>|<the arguments>`. Returns the calls
    and the finished process."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "uv-calls.txt"
    stub = bindir / "uv"
    stub.write_text('#!/usr/bin/env bash\nprintf "%s|%s\\n" "${REQUISITION_DEMO_DIR-UNSET}" "$*" >> "' + str(log) + '"\n')
    stub.chmod(0o755)
    out = tmp_path / "out"
    (out / "1-strands-records").mkdir(parents=True)
    (out / "1-strands-records" / "manifest.json").write_text("{}")  # so step 4 reaches its demo call
    env = {k: v for k, v in os.environ.items() if k not in ("REQUISITION_DEMO_DIR", "REQUISITION_LOAD_WRAPPER", "REHEARSE_DRY")}
    env.update(PATH=f"{bindir}:{env['PATH']}", OUT=str(out), STEPS="1 2 3 4", STRANDS_MODE="scripted",
               REQUISITION_URL="http://127.0.0.1:9", REQUISITION_CRED="x", REQUISITION_PRINCIPAL="y",
               REQUISITION_LAB_KEY_FILE=str(tmp_path / "keys.json"), **extra_env)
    proc = subprocess.run(["bash", str(ROOT / "demo" / "rehearse.sh")], capture_output=True, text=True, env=env, timeout=120)
    calls = [line.split("|", 1) for line in log.read_text().splitlines()] if log.exists() else []
    return calls, proc


REHEARSED = ["run_demo.py", "run_interceptor_local.py", "run_target_local.py", "run_airgap.py"]


def test_rehearse_sh_without_a_scratch_folder_stops_before_any_demo(tmp_path):
    # no default folder: the script stops, names the variable, and runs no demo
    calls, proc = _rehearse_with_a_recording_uv(tmp_path)
    assert proc.returncode != 0 and calls == [], (proc.returncode, calls)
    assert "REQUISITION_DEMO_DIR" in proc.stderr, proc.stderr[-300:]


def test_rehearse_sh_gives_every_demo_the_scratch_folder_the_caller_set(tmp_path):
    mine = str(tmp_path / "mine")
    calls, _ = _rehearse_with_a_recording_uv(tmp_path, REQUISITION_DEMO_DIR=mine)
    assert [name for name in REHEARSED for _, args in calls if f"demo/{name}" in args] == REHEARSED, calls
    assert len(calls) == 4 and {folder for folder, _ in calls} == {mine}, calls


def test_the_dry_run_fake_needs_a_seed_or_the_scratch_folder(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "REQUISITION_DEMO_DIR"}
    proc = subprocess.run([sys.executable, "-m", "tests.fake_server_main", "--env-out", str(tmp_path / "env.sh"),
                           "--keys-out", str(tmp_path / "keys.json")], capture_output=True, text=True, env=env,
                          cwd=ROOT, timeout=120)
    assert proc.returncode == 2 and "REQUISITION_DEMO_DIR" in proc.stderr, (proc.returncode, proc.stderr[-300:])
    assert not (tmp_path / "env.sh").exists()


@pytest.mark.parametrize("name", REHEARSED + ["run_rollback_local.py"])
def test_a_demo_prints_its_help_without_the_scratch_folder(name):
    env = {k: v for k, v in os.environ.items() if k != "REQUISITION_DEMO_DIR"}
    proc = subprocess.run([sys.executable, str(ROOT / "demo" / name), "--help"], capture_output=True, text=True,
                          env=env, cwd=ROOT, timeout=120)
    assert proc.returncode == 0 and "usage" in proc.stdout.lower(), (proc.returncode, proc.stderr[-300:])


def test_run_airgap_keeps_an_empty_wrapper_and_defaults_an_absent_one(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("run_airgap", ROOT / "demo" / "run_airgap.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    seen = []
    monkeypatch.setattr(mod, "airgap_check", lambda *args, **kwargs: seen.append(kwargs) or True)
    monkeypatch.setattr(mod, "records_from_manifest", lambda path: [])
    monkeypatch.setenv("REQUISITION_DEMO_DIR", str(tmp_path))
    monkeypatch.delenv("REQUISITION_LOAD_WRAPPER", raising=False)
    base = ["--records", str(tmp_path), "--transcript", str(tmp_path / "t.txt")]
    mod.main(base + ["--wrapper", ""])      # '' means no wrapper, and must stay none
    mod.main(base)                          # absent, REQUISITION_LOAD_WRAPPER unset: none
    monkeypatch.setenv("REQUISITION_LOAD_WRAPPER", str(tmp_path / "limit.sh"))
    mod.main(base)                          # absent: REQUISITION_LOAD_WRAPPER
    assert seen[0]["wrapper"] == () and seen[0]["req_tree"] == str(tmp_path / "req")
    assert seen[1]["wrapper"] == ()
    assert seen[2]["wrapper"] == (str(tmp_path / "limit.sh"),)
