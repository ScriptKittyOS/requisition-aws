# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The AgentCore Gateway REQUEST interceptor, run locally against the live lab (not deployed).

Each step builds an event in AWS's documented interceptor input shape (gateway-interceptors-types.html,
fetched 2026-11-09; see tests/fixtures/interceptor/) and hands it to the same `Interceptor.handle` the
Lambda entry point calls. No Gateway, no Lambda, no AWS call: this shows what the handler returns to
the Gateway at each step. What a live Gateway does with it is AWS's documented contract, not tested here.

    export REQUISITION_URL=http://127.0.0.1:4000 REQUISITION_CRED=... REQUISITION_PRINCIPAL=...
    export REQUISITION_SEED=/path/to/seed.json # required: the file the server registered the act type from
    uv run python demo/run_interceptor_local.py --transcript <dir>/interceptor.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import time
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from requisition_aws import interceptor as icp
from requisition_aws.demo_flow import Transcript, demo_dir, demo_seed, verify_all

TOOL = "refunds___payments_refund_send"
# A labelled placeholder (G1): the SigV4 Authorization shape a Gateway forwards under
# AWS_IAM, with a fixture access-key id and no real signature. Nothing here is authenticated.
PLACEHOLDER_AUTHORIZATION = ("AWS4-HMAC-SHA256 Credential=AKIAPLACEHOLDERLOCAL/20261110/us-west-2/bedrock-agentcore/"
                             "aws4_request, SignedHeaders=host, Signature=PLACEHOLDER-NOT-A-SIGNATURE")
PLACEHOLDER_NOTE = "caller key from a placeholder header — local run, not authenticated (no Gateway)"


def approvals_link(env) -> str:
    """The console page the two approvers open: the base the interceptor builds its own links from
    (REQUISITION_APPROVAL_BASE when set, REQUISITION_URL otherwise)."""
    return env.get("REQUISITION_APPROVAL_BASE", env["REQUISITION_URL"]).rstrip("/") + "/approvals"


def event(rpc_id, method, params=None, session="mcp-session-local"):
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        body["params"] = params
    if rpc_id is None:
        body.pop("id")
    return {"interceptorInputVersion": "1.0", "mcp": {
        "rawGatewayRequest": {"body": json.dumps(body)},
        "gatewayRequest": {"path": "/mcp", "httpMethod": "POST",
                           "headers": {"Accept": "application/json", "Authorization": PLACEHOLDER_AUTHORIZATION,
                                       "Mcp-Session-Id": session},
                           "body": body}}}


def summarize(out: dict) -> str:
    mcp = out.get("mcp", {})
    passed = mcp.get("transformedGatewayRequest", {}).get("body", {})
    if isinstance(passed, dict) and passed.get("method") and passed.get("method") != "tools/call":
        return f"PASSED THROUGH UNCHANGED ({passed['method']} needs no approval)"
    if "transformedGatewayResponse" in mcp:
        body = mcp["transformedGatewayResponse"].get("body", {})
        result = body.get("result") if isinstance(body, dict) else None
        if result and result.get("isError"):
            text = " ".join(c.get("text", "") for c in result.get("content", []))
            return f"GATEWAY ANSWERS THE AGENT (tool not called): isError -- {text}"
        if isinstance(body, dict) and "error" in body:
            return f"GATEWAY ANSWERS THE AGENT (tool not called): JSON-RPC error -- {body['error'].get('message')}"
        return f"GATEWAY ANSWERS THE AGENT: {json.dumps(body)[:200]}"
    if "transformedGatewayRequest" in mcp:
        return "PASSED THROUGH UNCHANGED to the target (the tool runs with exactly these arguments)"
    return json.dumps(out)[:200]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--poll", type=float, default=3.0)
    ap.add_argument("--timeout", type=float, default=600.0)
    a = ap.parse_args()
    DEMO = demo_dir()
    run = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tpath = pathlib.Path(a.transcript)
    store = tpath.with_suffix(".store.json")
    env = {**os.environ,
           "REQUISITION_GATEWAY_ID": "local-gateway-demo",
           "REQUISITION_TOOLS": json.dumps({TOOL: "payments.refund_send"}),
           "REQUISITION_SEED": demo_seed(),
           "REQUISITION_STORE": str(store),
           "REQUISITION_AGENT": "agentcore-gateway-demo",
           "REQUISITION_KEYS_FILE": os.environ["REQUISITION_LAB_KEY_FILE"]}
    it = icp.from_env(env)
    # keep a copy of every signed record the gate receives (the handler itself returns only the verdict)
    records: list[dict] = []
    orig_execute = it.gate.execute
    def execute(*args, **kw):
        d = orig_execute(*args, **kw)
        records.append({"kind": "decision", "record": d.decision, "arguments": args[1],
                        "act_type": "payments.refund_send", "verdict": d.verdict, "code": d.code,
                        "cosignature": d.response.get("cosignature")})
        return d
    it.gate.execute = execute
    orig_replay = it.gate.replay_stored
    def replay(*args, **kw):
        d = orig_replay(*args, **kw)
        if d is not None:
            records.append({"kind": "decision", "record": d.decision, "arguments": args[1],
                            "act_type": "payments.refund_send", "verdict": d.verdict, "code": (d.code or "") + " (stored, replayed on retry)",
                            "cosignature": d.response.get("cosignature")})
        return d
    it.gate.replay_stored = replay

    t = Transcript((os.environ.get("REQUISITION_CRED", ""),))
    session = f"mcp-session-{run}"
    refund = {"name": TOOL, "arguments": {"amount_minor": 4200, "currency": "USD", "account": "acct-9120",
                                          "reason": "order 5530 cancelled before shipping"}}
    t.say(f"AgentCore Gateway REQUEST interceptor, run locally against the live lab (not deployed), run {run}")
    t.say("  events: AWS's documented interceptor input shape; handler: requisition_aws.interceptor.Interceptor.handle")
    t.say(f"  {PLACEHOLDER_NOTE} (caller source: {os.environ.get('REQUISITION_CALLER_SOURCE', 'legacy_session')})")
    steps = [
        ("1. the agent lists tools", event(1, "tools/list", session=session)),
        ("2. the agent calls a tool with no registered act type", event(2, "tools/call",
            {"name": "refunds___payments_wire_transfer", "arguments": {"amount_minor": 999999}}, session)),
        ("3. the agent calls the refund tool", event(3, "tools/call", refund, session)),
    ]
    for label, ev in steps:
        t.say(label); t.say("   " + summarize(it.handle(ev)))

    t.say("   -> two approver accounts approve it in the console: " + approvals_link(env))
    deadline = time.time() + a.timeout
    while time.time() < deadline:
        out = it.handle(event(4, "tools/call", refund, session))
        s = summarize(out)
        if "awaiting approval" not in s:
            break
        time.sleep(a.poll)
    t.say("4. the agent calls the refund tool again after the approvals")
    t.say("   " + s)
    t.say("5. the same invocation again (same JSON-RPC id: a Gateway retry, or a client reusing its id) -> REFUSED:")
    t.say("   one approval, one pass-through, always")
    t.say("   " + summarize(it.handle(event(4, "tools/call", refund, session))))
    t.say("6. the agent calls again with a new JSON-RPC id (a second refund needs a new approval)")
    t.say("   " + summarize(it.handle(event(5, "tools/call", refund, session))))

    out_dir = str(tpath.with_suffix("")) + "-records"
    ok = verify_all(records, out_dir,
                    lab_verify=str(DEMO / "req" / "bin" / "lab-verify"),
                    registry_path=os.environ["REQUISITION_LAB_KEY_FILE"], t=t) if records else False
    t.say(f"OFFLINE CHECK: {'every record passed' if ok else 'FAILED or no records'}; records in {out_dir}")
    t.write(str(tpath))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
