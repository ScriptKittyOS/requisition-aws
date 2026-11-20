# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The demo's application loop, kept in the package so it is tested against the
fake Requisition; ``demo/run_demo.py`` only wires configuration, the model and the tool to it.

  1. the agent runs; the hook proposes and interrupts with {request_id, approval_url};
  2. the app prints the link and polls GET /v1/sanction-requests/<id> until sanctioned, refused or
     timeout (the first GET after the second approval mints the statement),
     then resumes the agent;
  3. the hook executes; the tool runs only on a signed allow;
  4. a second execute of the same statement under a fresh nonce: the signed deny statement_spent;
  5. every statement and decision is checked offline (bin/verify_offline.py, which runs
     bin/lab-verify) and the transcript is written. No credential is ever written.
  6. ``--airgap``: the same check again inside ``docker run --rm --network none`` (a network probe
     first), then one character of a copy's signed payload is changed and the check FAILS.
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import shlex
import subprocess
import sys
import time
from typing import Any, Callable

from . import canonical
from .client import RequisitionError
from .gate import Gate, Sanction
from .strands_hook import INTERRUPT_NAME, RequisitionHook

REPO = pathlib.Path(__file__).resolve().parent.parent
VERIFY_OFFLINE = REPO / "bin" / "verify_offline.py"
AIRGAP_IMAGE = "nikolaik/python-nodejs:python3.11-nodejs20"  # must already be present locally; never pulled here


DEMO_DIR_MESSAGE = "set REQUISITION_DEMO_DIR to the demo folder (req/ is a Requisition checkout; transcripts go to log/)"


def demo_dir() -> pathlib.Path:
    """The demo folder: REQUISITION_DEMO_DIR, no default (req/ a Requisition checkout, env.sh, log/). Called when a
    demo runs, never at import."""
    value = os.environ.get("REQUISITION_DEMO_DIR", "")
    if not value:
        print(DEMO_DIR_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    return pathlib.Path(value)


SEED_MESSAGE = ("name the seed file (--seed, or REQUISITION_SEED): the file the Requisition server registered the "
                "act type from")


def demo_seed(given: str | None = None) -> str:
    """The seed file a demo reads each act type's display_schema from: ``given`` (--seed), else REQUISITION_SEED.
    No default: the file belongs to the Requisition installation the demo talks to. Called when a demo runs."""
    value = given or os.environ.get("REQUISITION_SEED", "")
    if not value:
        print(SEED_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    return value


def load_wrapper() -> str:
    """REQUISITION_LOAD_WRAPPER: a command placed before docker and the rollback server (a resource-limit script, say);
    unset or empty means none."""
    return os.environ.get("REQUISITION_LOAD_WRAPPER", "")


class Transcript:
    def __init__(self, secrets_to_elide: tuple[str, ...] = ()):
        self.lines: list[str] = []
        self._elide = tuple(s for s in secrets_to_elide if s)

    def say(self, text: str = "") -> None:
        for secret in self._elide:
            text = text.replace(secret, "<elided>")
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {text}" if text else ""
        self.lines.append(line)
        print(line, flush=True)

    def write(self, path: str) -> None:
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as handle:
            handle.write("\n".join(self.lines) + "\n")


def wait_for_decision(gate: Gate, request_id: str, *, poll: float, timeout: float,
                      say: Callable[[str], None], sleep: Callable[[float], None] = time.sleep) -> str:
    deadline = time.monotonic() + timeout
    last = None
    while True:
        try:
            status = gate.client.get_request(request_id)["status"]
        except RequisitionError as error:
            status = f"unreachable ({error})"
        if status != last:
            say(f"  sanction request {request_id}: {status}")
            last = status
        if status in ("sanctioned", "refused"):
            return status
        if time.monotonic() >= deadline:
            say(f"  timed out after {timeout:.0f} s; resuming (the hook will refuse)")
            return "timeout"
        sleep(poll)


def run_agent(agent: Any, hook: RequisitionHook, gate: Gate, prompt: str, t: Transcript, *,
              poll: float = 3.0, timeout: float = 600.0, sleep: Callable[[float], None] = time.sleep) -> Any:
    t.say(f"USER: {prompt}")
    result = agent(prompt)
    while getattr(result, "stop_reason", None) == "interrupt":
        responses = []
        for interrupt in result.interrupts or []:
            if interrupt.name != INTERRUPT_NAME:
                responses.append({"interruptResponse": {"interruptId": interrupt.id, "response": "unknown interrupt"}})
                continue
            reason = interrupt.reason or {}
            t.say("INTERRUPT: the tool call is held by Requisition")
            t.say(f"  request_id   {reason.get('request_id')}")
            t.say(f"  act_type     {reason.get('act_type')}")
            t.say(f"  act_hash     {reason.get('act_hash')}")
            t.say(f"  arguments    {json.dumps(reason.get('arguments'), sort_keys=True)}")
            t.say(f"  APPROVE AT   {reason.get('approval_url')}  (two approver accounts, recorded one-person)")
            status = wait_for_decision(gate, reason["request_id"], poll=poll, timeout=timeout, say=t.say, sleep=sleep)
            responses.append({"interruptResponse": {"interruptId": interrupt.id, "response": {"observed": status}}})
        t.say("RESUME: the hook re-reads the request itself (the app's word is not trusted)")
        result = agent(responses)
    t.say(f"AGENT ({getattr(result, 'stop_reason', '?')}): {str(result).strip()}")
    return result


def replay_attempt(gate: Gate, hook: RequisitionHook, t: Transcript) -> dict | None:
    """Execute the statement the tool ran on once more, under a fresh nonce."""
    statement = next((r for r in hook.records if r["kind"] == "statement"), None)
    if statement is None:
        t.say("REPLAY: no statement was issued in this run; nothing to replay")
        return None
    args, act_type = statement["arguments"], statement["act_type"]
    sanction = gate.read(Sanction(statement["request_id"], act_type, canonical.act_hash(act_type, args), "pending", ""), args)
    nonce = secrets.token_hex(16)
    t.say(f"REPLAY: the same statement {sanction.statement_id[:16]}... again, fresh nonce {nonce}")
    decision = gate.execute_fresh(sanction, args, nonce)
    t.say(f"  signed verdict: {decision.verdict} {decision.code or ''} (signature checked here: {decision.signature_checked})")
    record = {"kind": "decision", "arguments": args, "act_type": act_type, "record": decision.decision,
              "verdict": decision.verdict, "code": decision.code, "cosignature": decision.response.get("cosignature")}
    hook.records.append(record)
    return record


def record_file_body(rec: dict) -> dict:
    """What verify_all writes as <stem>.record.json: the envelope, or the envelope beside its
    ML-DSA-87 co-signature, as the /v1 answer carried them."""
    if rec.get("cosignature"):
        return {"record": rec["record"], "cosignature": rec["cosignature"]}
    return rec["record"]


def verify_all(records: list[dict], out_dir: str, *, lab_verify: str, registry_path: str, t: Transcript,
               require_pq: bool = False) -> bool:
    """Every record through bin/verify_offline.py. ``require_pq``: each must carry a valid ML-DSA-87
    signature over its bytes (its own, or its co-signature), else it FAILS, saying why."""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.json"), "w") as handle:  # for a later run_airgap.py
        json.dump([{"stem": stem, "kind": rec["kind"], "act_type": rec["act_type"]} for stem, rec in _stems(records)],
                  handle, indent=1)
    all_ok = True
    if require_pq:
        t.say("OFFLINE CHECK with post-quantum REQUIRED: each record must carry a valid ML-DSA-87 signature")
    for i, rec in enumerate(records, 1):
        stem = os.path.join(out_dir, f"{i:02d}-{rec['kind']}")
        with open(stem + ".arguments.json", "w") as handle:
            json.dump(rec["arguments"], handle, sort_keys=True, indent=1)
        with open(stem + ".record.json", "w") as handle:
            json.dump(record_file_body(rec), handle, indent=1)
        proc = subprocess.run(
            [sys.executable, "-I", str(VERIFY_OFFLINE), "--arguments", stem + ".arguments.json",
             "--act-type", rec["act_type"], "--record", stem + ".record.json",
             "--lab-verify", lab_verify, "--registry", registry_path] + (["--require-pq"] if require_pq else []),
            capture_output=True, text=True, timeout=120,
        )
        label = rec["kind"]
        if rec["kind"] == "decision":
            label += f" ({rec.get('verdict')}{' ' + rec['code'] if rec.get('code') else ''})"
        t.say(f"VERIFY {i:02d} {label}: exit {proc.returncode}")
        for line in (proc.stdout + proc.stderr).splitlines():
            t.say("    " + line)
        all_ok = all_ok and proc.returncode == 0
    return all_ok


def _stems(records: list[dict]) -> list[tuple[str, dict]]:
    """The file stems verify_all writes, in its order."""
    return [(f"{i:02d}-{rec['kind']}", rec) for i, rec in enumerate(records, 1)]


def airgap_command(out_dir: str, registry_path: str, req_tree: str, *, image: str = AIRGAP_IMAGE,
                   docker: str = "docker") -> list[str]:
    """``docker run --rm --network none`` with every input mounted read-only and a read-only root.
    Inside: /v/bin (verify_offline + the vendored verifier), /airgap (probe, tamper), /in (the
    records verify_all wrote), /keys/lab-keys.json, and Requisition's unchanged bin/lab-verify with
    the verifier it runs, at their places under /req."""
    req = pathlib.Path(req_tree)
    mounts = [
        (REPO / "bin", "/v/bin"),
        (REPO / "demo" / "airgap", "/airgap"),
        (pathlib.Path(out_dir), "/in"),
        (pathlib.Path(registry_path), "/keys/lab-keys.json"),
        (req / "bin" / "lab-verify", "/req/bin/lab-verify"),
        (req / "bench" / "holytrinity-v2" / "verifier", "/req/bench/holytrinity-v2/verifier"),
    ]
    cmd = [docker, "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
           "--user", f"{os.getuid()}:{os.getgid()}", "--security-opt", "no-new-privileges"]
    for host, inside in mounts:
        cmd += ["-v", f"{pathlib.Path(host).resolve()}:{inside}:ro"]
    return cmd + [image, "sh", "/in/airgap/run.sh"]


def airgap_script(records: list[dict], require_pq: bool = False) -> str:
    """The shell script run inside the container (all paths fixed, nothing from the records' text)."""
    verify = ("python3 -I /v/bin/verify_offline.py --arguments /in/{stem}.arguments.json --act-type {act} "
              "--record {record} --lab-verify /req/bin/lab-verify --registry /keys/lab-keys.json"
              + (" --require-pq" if require_pq else ""))
    lines = ["set -u", "python3 --version", "python3 -I /airgap/probe.py"]
    for stem, rec in _stems(records):
        lines.append(verify.format(stem=stem, act=shlex.quote(rec["act_type"]), record=f"/in/{stem}.record.json"))
        lines.append(f'echo "AIRGAP-RESULT {stem} $?"')
    target = next((stem for stem, rec in _stems(records) if rec["kind"] == "decision"), None)
    target = target or _stems(records)[0][0]
    rec = dict(_stems(records))[target]
    lines.append(f"python3 -I /airgap/tamper.py /in/{target}.record.json /tmp/tampered.record.json")
    lines.append(verify.format(stem=target, act=shlex.quote(rec["act_type"]), record="/tmp/tampered.record.json"))
    lines.append(f'echo "AIRGAP-RESULT tampered-{target} $?"')
    return "\n".join(lines) + "\n"


def records_from_manifest(out_dir: str) -> list[dict]:
    with open(os.path.join(out_dir, "manifest.json")) as handle:
        return [{"kind": m["kind"], "act_type": m["act_type"]} for m in json.load(handle)]


def airgap_check(records: list[dict], out_dir: str, *, registry_path: str, req_tree: str, t: Transcript,
                 image: str = AIRGAP_IMAGE, wrapper: tuple[str, ...] = (), docker: str = "docker",
                 run: Callable[..., Any] = subprocess.run, require_pq: bool = False) -> bool:
    """Re-run the offline check with no network at all, then show a one-character change FAIL.
    True only if the probe found no network, every record passed and the tampered copy failed.
    ``records`` and ``out_dir`` are what ``verify_all`` was given (its files are the inputs)."""
    if not records:
        t.say("AIRGAP: no records to check")
        return False
    workdir = pathlib.Path(out_dir) / "airgap"
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "run.sh").write_text(airgap_script(records, require_pq))
    cmd = list(wrapper) + airgap_command(out_dir, registry_path, req_tree, image=image, docker=docker)
    t.say(f"AIRGAP: docker run --rm --network none --read-only {image} (inputs mounted read-only)")
    proc = run(cmd, capture_output=True, text=True, timeout=600)
    output = (proc.stdout or "") + (proc.stderr or "")
    (workdir / "output.txt").write_text(output)
    results: dict[str, int] = {}
    probe_ok = False
    for line in output.splitlines():
        if line.startswith("network probe:") or line.startswith("tampered copy:") or line.startswith("Python "):
            t.say("  " + line)
        elif line.startswith("AIRGAP-PROBE "):
            probe_ok = line.strip() == "AIRGAP-PROBE no-network"
            t.say("  " + ("no network: confirmed" if probe_ok else "NETWORK PRESENT: the airgap claim does not hold"))
        elif line.startswith("verdict:"):
            t.say("    " + line)
        elif line.startswith("AIRGAP-RESULT "):
            _, label, code = line.split()
            results[label] = int(code)
            shown = "FAIL, as it must" if label.startswith("tampered-") and code != "0" else (
                "PASS" if code == "0" else "FAIL")
            t.say(f"  {label}: exit {code} ({shown})")
    tampered = [k for k in results if k.startswith("tampered-")]
    passed = [k for k in results if not k.startswith("tampered-") and results[k] == 0]
    ok = (proc.returncode == 0 and probe_ok and len(passed) == len(records)
          and len(tampered) == 1 and results[tampered[0]] != 0)
    t.say(f"AIRGAP: {'every record passed with no network; the one-character change failed' if ok else 'NOT as expected (see ' + str(workdir / 'output.txt') + ')'}")
    return ok
