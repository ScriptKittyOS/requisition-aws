#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Requisition as the AgentCore Gateway TARGET, run locally against the lab (not deployed).

It runs against the live lab. It serves requisition_aws.mcp_target on
127.0.0.1 (a random port) and speaks MCP 2026-07-28 to it over HTTP, as a Gateway would. No Gateway, no
Lambda, no AWS call. The refund tool writes REFUND SENT to a local ledger beside the transcript.

    export REQUISITION_URL=http://127.0.0.1:4000 REQUISITION_CRED=... REQUISITION_PRINCIPAL=...
    export REQUISITION_LAB_KEY_FILE=...        # required; compared byte for byte with GET /v1/keys
    export REQUISITION_SEED=/path/to/seed.json # required (or --seed): the file the server registered the act type from
    uv run python demo/run_target_local.py --transcript <dir>/target.txt [--no-require-pq]
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from requisition_aws.client import Client  # noqa: E402
from requisition_aws.demo_flow import Transcript, demo_dir, demo_seed, verify_all  # noqa: E402
from requisition_aws.gate import Gate  # noqa: E402
from requisition_aws.keys import KeyRegistry  # noqa: E402
from requisition_aws.mcp_target import Ledger, McpTarget, refund_tool  # noqa: E402
from requisition_aws.registry import ToolRegistry  # noqa: E402
from requisition_aws.store import Store  # noqa: E402
from requisition_aws.target_flow import capture_records, run_target_flow  # noqa: E402

ACT_TYPE = "payments.refund_send"
TOOL_ARGS = {"amount_minor": 3100, "currency": "EUR", "account": "acct-6604", "reason": "late delivery credit on order 6120"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--seed", default=None, help="the seed file; or REQUISITION_SEED (no default)")
    ap.add_argument("--lab-verify", default=None, help="default: under REQUISITION_DEMO_DIR")
    ap.add_argument("--poll", type=float, default=3.0)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--require-pq", action=argparse.BooleanOptionalAction, default=True,
                    help="require each record's ML-DSA-87 co-signature at run time and offline")
    a = ap.parse_args(argv)
    DEMO = demo_dir()
    a.seed = demo_seed(a.seed)
    if a.lab_verify is None:
        a.lab_verify = str(DEMO / "req" / "bin" / "lab-verify")
    missing = [k for k in ("REQUISITION_URL", "REQUISITION_CRED", "REQUISITION_PRINCIPAL", "REQUISITION_LAB_KEY_FILE")
               if not os.environ.get(k)]
    if missing:
        ap.error("set " + ", ".join(missing))
    url, cred, principal = (os.environ[k] for k in ("REQUISITION_URL", "REQUISITION_CRED", "REQUISITION_PRINCIPAL"))
    run = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tpath = pathlib.Path(a.transcript)
    out_dir = tpath.with_name(tpath.stem + "-records")
    out_dir.mkdir(parents=True, exist_ok=True)
    t = Transcript((cred,))

    client = Client(url, cred, principal, unix_socket=os.environ.get("REQUISITION_SOCKET") or None)
    keys_bytes = client.keys()
    if pathlib.Path(os.environ["REQUISITION_LAB_KEY_FILE"]).read_bytes() != keys_bytes:
        t.say("REFUSED: GET /v1/keys is not byte-equal to REQUISITION_LAB_KEY_FILE")
        t.write(str(tpath))
        return 1
    registry_path = out_dir / "lab-keys.json"
    registry_path.write_bytes(keys_bytes)
    gate = Gate(client, Store(str(out_dir / "store.json")), approval_base_url=url, keys=KeyRegistry.from_bytes(keys_bytes),
                require_pq=a.require_pq)  # at RUN time: the target runs the tool only on a checked ML-DSA-87 record
    tools = ToolRegistry.from_seed(a.seed, {"payments_refund_send": ACT_TYPE})
    ledger = Ledger(str(out_dir / "refund-ledger.jsonl"))
    target = McpTarget(gate, tools, {"payments_refund_send": refund_tool(ledger)}, target_id="requisition-target-local",
                       agent_name="agentcore-gateway-demo", session=f"target-{run}")
    records = capture_records(gate, ACT_TYPE)
    t.say(f"run {run}; Requisition {url} (lab profile, dev-only); credential <elided>")
    out = run_target_flow(target, ledger, TOOL_ARGS, t, approval_url=f"{url}/approvals", poll=a.poll, timeout=a.timeout)
    ok = verify_all(records, str(out_dir), lab_verify=a.lab_verify, registry_path=str(registry_path), t=t,
                    require_pq=a.require_pq) if records else False
    ok = ok and out.get("ran") and out.get("after_retry") == 1 and out.get("final_ledger") == 1
    t.say(f"TARGET FORM: {'the refund ran once, on a checked allow; every record passed offline' if ok else 'NOT as expected (see above)'}; records in {out_dir}")
    t.write(str(tpath))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
