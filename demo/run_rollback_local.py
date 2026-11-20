#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The rollback demo, local only (F1).

Run it only inside Requisition's scratch-database wrapper, which creates a database for the demonstration and
drops it after it:

    cd <requisition> && <its scratch-database wrapper> -- \
      <requisition-aws>/.venv/bin/python <requisition-aws>/demo/run_rollback_local.py \
        --transcript <dir>/rollback.txt --source-db <the demo database> --live-port <the live server's port> \
        --server-cmd '<the command that starts Requisition's scratch server>' --seed <the demo seed file> \
        [--serve-script <Requisition's scratch-server script>] [--approved-file <dir>/approved] [--port 4113] [--dry-run]

    env: REQUISITION_CRED, REQUISITION_PRINCIPAL   the demo caller (it exists in the copied demo database)
         REQUISITION_LAB_KEY_FILE                  compared byte for byte with the scratch server's /v1/keys
         ROLLBACK_SOURCE_DB, ROLLBACK_SERVER_CMD, ROLLBACK_SERVE_SCRIPT, REQUISITION_SEED
                                                   stand in for --source-db, --server-cmd, --serve-script and --seed
         REQUISITION_URL                           its port is a live port too, as if given with --live-port

This file holds no name of a database, a server or a port of any installation, no command that starts the server
and no place inside its checkout: the operator gives them. The command that starts the scratch server runs
Requisition's own application, so Requisition's repository states it (at the head of its scratch-server script),
not this one; the demo refuses to start a server until it is given the command. In the command, {port} stands for
--port, {wrapper} for $REQUISITION_LOAD_WRAPPER (a memory cap, say; nothing when unset), {demo} for
$REQUISITION_DEMO_DIR and {serve} for --serve-script.

--dry-run: steps 1, 5 and 7's database half only (the copy, then a pg_dump snapshot and its pg_restore into
the copy), no server: check the restore round trip first.

Log in to the scratch console at http://localhost:<port> or in a separate browser profile: cookies ignore
the port and both servers share the cookie name, so logging in on 127.0.0.1:<port> logs that browser out of
the live server.

What it does, in order (every database write lands in $SCRATCH_DB, which the scratch-database wrapper drops on exit):

 1. copies the demo database (--source-db) into $SCRATCH_DB:
    pg_dump of the source (read only) -> pg_restore into the scratch database. The source is never
    written. It refuses to run unless $SCRATCH_DB has the shape of the wrapper's names and $PGDATABASE equals it;
 2. starts a SECOND Requisition server on 127.0.0.1:--port against $SCRATCH_DB, with the operator's --server-cmd.
    The live demo server and its database are not touched. The port must be free before it starts (a live port is refused
    outright, and with no live port named nothing starts), and the server counts as up only on its OWN line in scratch-server.log ("ROLLBACK SCRATCH
    SERVER UP on 127.0.0.1:<port>, database $SCRATCH_DB"), so nothing else answering is ever talked to.
    The command Requisition's scratch-server script states never compiles (the demo checkout's build, shared with
    the live server, is never written: build it once beforehand) and runs with the server's background job queues
    off; stopping waits until the server's port is closed;
 3. the agent's refund through the local Gateway TARGET form (requisition_aws.mcp_target, in process):
    call 1 files the request -> "awaiting approval";
 4. two approver accounts approve it in the scratch server's console; the operator then presses Enter
    (or touches --approved-file). NOTHING reads the request meanwhile: the caller's first GET mints the
    statement, and the snapshot must come before it;
 5. SNAPSHOT: pg_dump of $SCRATCH_DB (after the approvals, before the first GET);
 6. call 2: the GET mints S, the execute allows, the refund RUNS once (ledger 1);
 7. ROLLBACK: the server stops, the snapshot is restored into $SCRATCH_DB, the server starts again;
    the chain head is checked to be S's sequence - 1 (nothing appended between the snapshot and S);
 8. the restored service's own answer, printed BEFORE the relying party sees it: GET says sanctioned,
    under a NEW statement id S', for the same approval_request_id (the old weakness, shown honestly);
 9. call 3 (a new call, same arguments): the relying party's own memory REFUSES (authority_equivocated:
    S' sits at S's position) and keeps both signed records as evidence; the ledger stays at 1;
10. bin/export_chain.sh exports the restored chain (read only) and bin/verify_chain.py checks it against
    the relying party's held records and evidence: FAIL, held_record_differs + equivocation (+ export_short
    for the allow and the outcome the restored chain no longer has).

CLAIM (with its precondition; the CLAIM constant below, the transcript and the
README carry the same text):

    If Requisition's database is rolled back, the same executor, with its own records intact, refuses to act
    again, and the rollback leaves two different records signed by the service's key at one chain position,
    which anyone can check offline. Lab profile, lab key. (when nothing was appended between the snapshot and
    the mint; step 7 checks this and stops otherwise).

Never "proves rollback" in general; never "any executor". No AWS step.

EXIT 0: every step as expected; 1: a step was not as expected (the transcript says which); 2: refused.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from requisition_aws.client import Client  # noqa: E402
from requisition_aws.demo_flow import Transcript, demo_dir, demo_seed, load_wrapper  # noqa: E402
from requisition_aws.gate import Gate  # noqa: E402
from requisition_aws.keys import KeyRegistry  # noqa: E402
from requisition_aws.mcp_target import Ledger, McpTarget, refund_tool  # noqa: E402
from requisition_aws.registry import ToolRegistry  # noqa: E402
from requisition_aws.store import Store  # noqa: E402

ACT_TYPE = "payments.refund_send"
TOOL = "payments_refund_send"
TOOL_ARGS = {"amount_minor": 4200, "currency": "EUR", "account": "acct-7310", "reason": "rollback demo: duplicate charge"}
SCRATCH_NAME = re.compile(r"\Ascratch_[0-9]{14}_[0-9]+_[0-9]+\Z")  # the shape of the scratch-database wrapper's names
# No list of databases to protect is kept: the one database this demo writes is $SCRATCH_DB, only when its name has
# the shape above and $PGDATABASE equals it, so a database of any other name can never be the target.
# No command that starts a server is kept either: it runs Requisition's own application, so Requisition's repository
# states it, and the operator gives it (--server-cmd, or $ROLLBACK_SERVER_CMD).
CLAIM = ("If Requisition's database is rolled back, the same executor, with its own records intact, refuses to act "
         "again, and the rollback leaves two different records signed by the service's key at one chain position, "
         "which anyone can check offline. Lab profile, lab key. (when nothing was appended between the snapshot and "
         "the mint; step 7 checks this and stops otherwise).")
COOKIE_NOTE = ("note: log in to the scratch console at http://localhost:{port} or in a separate browser profile: cookies "
               "ignore the port, so logging in on 127.0.0.1:{port} logs that browser out of the live server (port {live})")


class Refused(Exception):
    pass


def live_ports(given: list[int], url: str) -> frozenset:
    """The ports the scratch server must never take: each --live-port, and the port of REQUISITION_URL when it has
    one (its scheme's default port otherwise)."""
    ports = set(given)
    if url:
        parts = urllib.parse.urlsplit(url)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        if port:
            ports.add(port)
    return frozenset(ports)


# --- the database and the server: one interface, so the flow is testable against the fake ----------


class ScratchLab:
    """The real thing: $SCRATCH_DB (the scratch-database wrapper's), pg_dump/pg_restore, a second server."""

    def __init__(self, *, source_db: str, port: int, server_cmd: str, out_dir: pathlib.Path, t: Transcript,
                 start_timeout: float = 240.0, stop_timeout: float = 30.0, live_ports: frozenset = frozenset(),
                 serve: str | None = None, needs_server: bool = True):
        if port in live_ports:
            raise Refused(f"port {port} is the live demo server's; the scratch server needs its own port")
        scratch, pgdatabase = os.environ.get("SCRATCH_DB", ""), os.environ.get("PGDATABASE", "")
        if not SCRATCH_NAME.match(scratch) or pgdatabase != scratch:
            raise Refused("run me inside Requisition's scratch-database wrapper: $SCRATCH_DB must be its generated name "
                          "and $PGDATABASE equal to it")
        if source_db == scratch or not source_db:
            raise Refused("name the source database (--source-db); it must not be the scratch database")
        if needs_server and not server_cmd:
            raise Refused("name the command that starts Requisition's scratch server (--server-cmd, or "
                          "$ROLLBACK_SERVER_CMD): Requisition's scratch-server script states it")
        if "{serve}" in server_cmd and not serve:
            raise Refused("name Requisition's scratch-server script (--serve-script, or $ROLLBACK_SERVE_SCRIPT): "
                          "it is a file of Requisition's repository")
        self.scratch, self.source_db, self.port, self.out_dir, self.t = scratch, source_db, port, out_dir, t
        folder = demo_dir() if "{demo}" in server_cmd else pathlib.Path()
        self.server_cmd = server_cmd.format(demo=folder, wrapper=load_wrapper(), port=port, serve=serve).lstrip()
        self.url = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None
        self.start_timeout = start_timeout
        self.stop_timeout = stop_timeout

    def _run(self, args: list[str], what: str) -> None:
        proc = subprocess.run(args, capture_output=True, text=True)
        errors = [line for line in proc.stderr.splitlines() if "ERROR" in line or "FATAL" in line]
        if proc.returncode != 0 or errors:  # the ERROR lines are read, never assumed away
            raise RuntimeError(f"{what} failed (exit {proc.returncode}): " + "; ".join(errors[:5] or [proc.stderr[-300:]]))

    def copy_baseline(self) -> None:
        dump = self.out_dir / "baseline.dump"
        self._run(["pg_dump", "-Fc", "--no-owner", "-d", self.source_db, "-f", str(dump)], "pg_dump of the source (read only)")
        self._run(["pg_restore", "--no-owner", "--single-transaction", "-d", self.scratch, str(dump)], "pg_restore into the scratch database")
        self.t.say(f"   the demo database {self.source_db} copied into {self.scratch} (the source is only read)")

    def _port_in_use(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                return True
        except OSError:
            return False

    def start(self) -> None:
        """Start the scratch server and wait for ITS OWN up line (never for whatever answers on the port)."""
        if self._port_in_use():
            raise Refused(f"port {self.port} is already in use (another server?); nothing was started")
        log_path = self.out_dir / "scratch-server.log"
        log = open(log_path, "ab")
        offset = log.tell()  # only lines written by THIS start count (the log is appended across restarts)
        up = f"ROLLBACK SCRATCH SERVER UP on 127.0.0.1:{self.port}, database {self.scratch},"
        self.proc = subprocess.Popen(self.server_cmd, shell=True, stdout=log, stderr=subprocess.STDOUT,
                                     env={**os.environ, "SCRATCH_DB": self.scratch}, start_new_session=True)
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the scratch server exited ({self.proc.returncode}); see scratch-server.log")
            with open(log_path, "rb") as handle:
                handle.seek(offset)
                if any(line.startswith(up) for line in handle.read().decode("utf-8", "replace").splitlines()):
                    self.t.say(f"   scratch server up on {self.url} (database {self.scratch}; its own UP line)")
                    return
            time.sleep(0.5)
        raise RuntimeError(f"no UP line naming database {self.scratch} on port {self.port} within "
                           f"{self.start_timeout:.0f} s; see scratch-server.log")

    def _group_alive(self, pgid: int) -> bool:
        if self.proc is not None:
            self.proc.poll()  # reap the leader, so a zombie does not count
        try:
            os.killpg(pgid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def stop(self) -> None:
        """Stop the scratch server and return only once its process group is gone AND its port is closed
        (under a load wrapper the process waited on may be the wrapper, such as flock, which dies at once
        while the BEAM shuts down gracefully). SIGTERM, a bounded wait, SIGKILL, a short wait; a port still open after that
        is a loud failure, never a silent return."""
        if self.proc is None:
            return
        pgid = self.proc.pid  # start_new_session: the leader's pid is the group id
        for sig, wait in ((signal.SIGTERM, self.stop_timeout), (signal.SIGKILL, 10.0)):
            if not (self._group_alive(pgid) or self._port_in_use()):
                break
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + wait
            while (self._group_alive(pgid) or self._port_in_use()) and time.monotonic() < deadline:
                time.sleep(0.2)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self.proc = None
        if self._port_in_use():
            raise RuntimeError(f"port {self.port} is still accepting connections after SIGTERM and SIGKILL to the "
                               "scratch server's process group: something else holds it; check before going on")
        if self._group_alive(pgid):
            raise RuntimeError(f"the scratch server's process group {pgid} is still alive after SIGKILL")

    def wait_approved(self, request_id: str, approved_file: str | None) -> None:
        self.t.say(f"   -> approve it with two approver accounts in {self.url}/approvals (request {request_id});")
        if approved_file:
            self.t.say(f"      then touch {approved_file}. Nothing reads the request meanwhile (its first GET mints).")
            while not os.path.exists(approved_file):
                time.sleep(1)
        else:
            input("      then press Enter. Nothing reads the request meanwhile (its first GET mints). ")

    def snapshot(self) -> str:
        path = self.out_dir / "snapshot.dump"
        self._run(["pg_dump", "-Fc", "--no-owner", "-d", self.scratch, "-f", str(path)], "pg_dump snapshot")
        return str(path)

    def restore(self, snap: str, restart: bool = True) -> None:
        self.stop()
        self._run(["pg_restore", "--clean", "--if-exists", "--no-owner", "--single-transaction", "-d", self.scratch, snap],
                  "pg_restore of the snapshot")
        if restart:
            self.start()

    def summary(self) -> str:
        """Read only: the lab-record count and the highest sequence, in the copy and in the source."""
        sql = "SELECT count(*), coalesce(max(sequence), 0) FROM authority_lab_receipts"
        out = []
        for db in (self.scratch, self.source_db):
            proc = subprocess.run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql], capture_output=True,
                                  text=True, env={**os.environ, "PGOPTIONS": "-c default_transaction_read_only=on"})
            out.append(f"{db}: {proc.stdout.strip() or proc.stderr.strip()[-200:]}")
        return "; ".join(out)

    def export(self, scope: str, path: pathlib.Path) -> pathlib.Path:
        path = path.with_suffix(".csv")
        with open(path, "wb") as handle:
            proc = subprocess.run(["bash", str(ROOT / "bin" / "export_chain.sh"), scope], stdout=handle,
                                  stderr=subprocess.PIPE, env={**os.environ, "PGDATABASE": self.scratch})
        if proc.returncode != 0:
            raise RuntimeError("export_chain.sh failed: " + proc.stderr.decode()[-300:])
        return path


# --- the flow ----------------------------------------------------------------------------------------


def _call(target: McpTarget, rpc_id: int) -> dict:
    msg = {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
           "params": {"name": TOOL, "arguments": TOOL_ARGS,
                      "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}
    headers = {"mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": TOOL}
    _, body = target.handle_message(msg, headers)
    return body["result"]


def _text(result: dict) -> str:
    return " ".join(c.get("text", "") for c in result.get("content", []))


def _signed(record: dict) -> dict:
    return json.loads(record["signed_payload"])


def run_rollback(lab, gate: Gate, target: McpTarget, ledger: Ledger, registry_path: pathlib.Path,
                 out_dir: pathlib.Path, t: Transcript, *, approved_file: str | None = None) -> dict:
    """The demo's steps 3-10 against ``lab`` (ScratchLab, or a fake in tests). Returns the facts."""
    out: dict = {"ok": False}
    store = gate.store
    t.say(f"3. the agent calls {TOOL} {json.dumps(TOOL_ARGS, sort_keys=True)} through the local Gateway TARGET")
    first = _call(target, 1)
    request_id = first.get("_meta", {}).get("requisition", {}).get("request_id")
    t.say(f"   -> TOOL ERROR, did not run: {_text(first)}")
    if not request_id:
        t.say("   NOT as expected: no request filed")
        return out
    t.say("4. the approvals")
    lab.wait_approved(request_id, approved_file)
    t.say("5. SNAPSHOT of the database (after the two approvals, before the caller's first GET)")
    snap = lab.snapshot()
    t.say("6. the agent calls again")
    second = _call(target, 2)
    meta = second.get("_meta", {}).get("requisition", {})
    t.say(f"   -> {'RAN' if not second.get('isError') else 'did not run'}: {_text(second)}")
    t.say(f"   ledger: {len(ledger.entries())} refund(s)")
    statement = gate.client.get_request(request_id)["statement"]  # a GET of a minted request mints nothing
    s_signed = _signed(statement)
    scope, s_seq = s_signed["chain_scope"], s_signed["sequence"]
    approval = s_signed["metadata"].get("approval_request_id")
    t.say(f"   statement S {statement['receipt_hash'][:16]}... at {scope} #{s_seq}, approval_request_id {approval}")
    if second.get("isError") or len(ledger.entries()) != 1:
        t.say("   NOT as expected: the first use did not run once")
        return out
    held_path = out_dir / "held-records.json"
    held = store.held_records()
    held_path.write_text(json.dumps({"records": held}, indent=1))
    t.say(f"   the relying party holds {len(held)} signed records it read (its position memory) -> {held_path.name}")

    t.say("7. ROLLBACK: the database restored to the snapshot")
    lab.restore(snap)
    restored = lab.export(scope, out_dir / "export-restored-before-remint")
    head = _export_head(restored)
    t.say(f"   restored chain head #{head}; S was #{s_seq}")
    if head != s_seq - 1:
        t.say("   NOT as expected: records were appended between the snapshot and S; the demo stops here")
        return out

    t.say("8. the restored service's own answer (a GET, as the agent's next call would make)")
    answer = gate.client.get_request(request_id)
    s_prime = answer.get("statement") or {}
    sp = _signed(s_prime) if s_prime else {}
    t.say(f"   status {answer.get('status')}, statement id {answer.get('statement_id', '')[:16]}... at #{sp.get('sequence')}, "
          f"approval_request_id {sp.get('metadata', {}).get('approval_request_id')}")
    t.say("   -> the restored service would allow (not executed here: a sanctioned statement is what /v1/execute allows "
          "on; tests/test_fence.py::test_gate_remint_at_an_unheld_position_is_refused_by_the_approval_spend shows the "
          "allow) the same approval again under a NEW statement id: the old weakness")
    out["restored_status"] = answer.get("status")
    out["new_statement"] = bool(s_prime) and s_prime["receipt_hash"] != statement["receipt_hash"]

    t.say("9. the agent calls again (a new call, the same arguments)")
    third = _call(target, 3)
    t.say(f"   -> {'did not run' if third.get('isError') else 'RAN'}: {_text(third)}")
    t.say(f"   ledger: {len(ledger.entries())} refund(s)")
    evidence = store.evidence()
    evidence_path = out_dir / "evidence.json"
    evidence_path.write_text(json.dumps({"evidence": evidence}, indent=1))
    for e in evidence:
        t.say(f"   EVIDENCE {e['code']} at #{e['sequence']}: held {e['held']['receipt_hash'][:16]}... vs presented "
              f"{e['presented']['receipt_hash'][:16]}... (both signed by the lab key) -> {evidence_path.name}")
    out["refused"] = bool(third.get("isError")) and "authority_equivocated" in _text(third)
    out["evidence"] = len(evidence)
    out["final_ledger"] = len(ledger.entries())

    t.say("10. a stranger's offline check: the restored chain's export against the relying party's held records")
    export = lab.export(scope, out_dir / "export-restored")
    proc = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "verify_chain.py"), "--registry", str(registry_path),
                           "--export", str(export), "--held", str(held_path), "--held", str(evidence_path), "--json"],
                          capture_output=True, text=True, timeout=300)
    report = json.loads(proc.stdout) if proc.returncode in (0, 1) else {"result": "error", "failures": []}
    codes = sorted({f["code"] for f in report["failures"]})
    (out_dir / "verify-chain.json").write_text(proc.stdout or proc.stderr)
    t.say(f"   bin/verify_chain.py: exit {proc.returncode}, {report['result']}: {', '.join(codes) or 'no failures'}")
    out["verify_codes"] = codes
    out["ok"] = (out["restored_status"] == "sanctioned" and out["new_statement"] and out["refused"]
                 and out["evidence"] >= 1 and out["final_ledger"] == 1 and proc.returncode == 1
                 and {"held_record_differs", "equivocation"} <= set(codes))
    return out


def _export_head(path: pathlib.Path) -> int:
    """The highest signed sequence in an export (0 for an empty chain), read as verify_chain.py reads it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_chain", ROOT / "bin" / "verify_chain.py")
    vc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vc)
    sequences = [json.loads(r["record"]["signed_payload"])["sequence"] for r in vc.read_export(str(path))]
    return max(sequences) if sequences else 0


def _stop(lab, t: Transcript) -> bool:
    try:
        lab.stop()
        return True
    except RuntimeError as error:  # loud: the transcript says it, the exit is 1
        t.say(f"NOT as expected: stopping the scratch server: {error}")
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--source-db", default=os.environ.get("ROLLBACK_SOURCE_DB"),
                    help="the demo database to copy (read only); or ROLLBACK_SOURCE_DB")
    ap.add_argument("--port", type=int, default=4113)
    ap.add_argument("--live-port", type=int, action="append", default=[],
                    help="a port the scratch server must never take (the live server's); the port of REQUISITION_URL "
                         "is one too")
    ap.add_argument("--serve-script", default=os.environ.get("ROLLBACK_SERVE_SCRIPT"),
                    help="Requisition's scratch-server script, put where --server-cmd says {serve}; or "
                         "ROLLBACK_SERVE_SCRIPT")
    ap.add_argument("--server-cmd", default=os.environ.get("ROLLBACK_SERVER_CMD"),
                    help="the command that starts Requisition's scratch server (no default; not needed with "
                         "--dry-run); or ROLLBACK_SERVER_CMD")
    ap.add_argument("--seed", default=None, help="the seed file; or REQUISITION_SEED (no default; not needed with "
                                                 "--dry-run)")
    ap.add_argument("--approved-file")
    ap.add_argument("--require-pq", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--dry-run", action="store_true",
                    help="the copy and the pg_dump/pg_restore round trip only; stops before the server")
    a = ap.parse_args(argv)
    demo_dir()
    if not a.dry_run:
        a.seed = demo_seed(a.seed)
    missing = [k for k in ("REQUISITION_CRED", "REQUISITION_PRINCIPAL", "REQUISITION_LAB_KEY_FILE") if not os.environ.get(k)]
    if missing:
        ap.error("set " + ", ".join(missing))
    cred, principal = os.environ["REQUISITION_CRED"], os.environ["REQUISITION_PRINCIPAL"]
    tpath = pathlib.Path(a.transcript)
    out_dir = tpath.with_name(tpath.stem + "-records")
    out_dir.mkdir(parents=True, exist_ok=True)
    t = Transcript((cred,))
    live = live_ports(a.live_port, os.environ.get("REQUISITION_URL", ""))
    try:
        if not live:
            raise Refused("name the live server's port (--live-port, or REQUISITION_URL), so that the scratch server "
                          "can never take it")
        lab = ScratchLab(source_db=a.source_db or "", port=a.port, server_cmd=a.server_cmd or "", out_dir=out_dir, t=t,
                         live_ports=live, serve=a.serve_script, needs_server=not a.dry_run)
    except Refused as refusal:
        t.say(f"REFUSED: {refusal}")
        t.write(str(tpath))
        return 2
    t.say("ROLLBACK DEMO (local; no AWS). Claim: " + CLAIM)
    t.say(COOKIE_NOTE.format(port=a.port, live=", ".join(map(str, sorted(live)))))
    out: dict = {}
    if a.dry_run:
        try:
            t.say("DRY RUN: 1. the scratch copy")
            lab.copy_baseline()
            t.say("DRY RUN: 5. a pg_dump snapshot of the copy")
            snap = lab.snapshot()
            t.say("DRY RUN: 7. its pg_restore into the copy (no server)")
            lab.restore(snap, restart=False)
            t.say(f"DRY RUN: read only: {lab.summary()}")
            t.say("DRY RUN: the copy and the restore round trip completed; no server was started")
            return 0
        except Exception as error:  # noqa: BLE001
            t.say(f"DRY RUN: NOT as expected: {type(error).__name__}: {error}")
            return 1
        finally:
            _stop(lab, t)
            t.write(str(tpath))
    try:
        t.say("1. the scratch copy")
        lab.copy_baseline()
        t.say("2. a second Requisition server on the scratch copy")
        lab.start()
        client = Client(lab.url, cred, principal)
        keys_bytes = client.keys()
        if pathlib.Path(os.environ["REQUISITION_LAB_KEY_FILE"]).read_bytes() != keys_bytes:
            t.say("REFUSED: the scratch server's GET /v1/keys is not byte-equal to REQUISITION_LAB_KEY_FILE")
            return 1
        registry_path = out_dir / "lab-keys.json"
        registry_path.write_bytes(keys_bytes)
        gate = Gate(client, Store(str(out_dir / "store.json")), approval_base_url=lab.url,
                    keys=KeyRegistry.from_bytes(keys_bytes), require_pq=a.require_pq)
        ledger = Ledger(str(out_dir / "refund-ledger.jsonl"))
        target = McpTarget(gate, ToolRegistry.from_seed(a.seed, {TOOL: ACT_TYPE}), {TOOL: refund_tool(ledger)},
                           target_id="requisition-target-rollback", agent_name="agentcore-gateway-demo",
                           session=f"rollback-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
        out = run_rollback(lab, gate, target, ledger, registry_path, out_dir, t, approved_file=a.approved_file)
    except Exception as error:  # noqa: BLE001 - a demo step failed: say which, stop the server, exit 1
        t.say(f"NOT as expected: {type(error).__name__}: {error}")
    finally:
        if not _stop(lab, t):
            out["ok"] = False
        t.say(f"ROLLBACK DEMO: {'as expected' if out.get('ok') else 'NOT as expected (see above)'}; records in {out_dir}")
        t.write(str(tpath))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
