# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The target form's demo loop (``demo/run_target_local.py`` wires configuration to it; tests run it
against the fake Requisition). Requisition as the AgentCore Gateway target, run locally: the MCP
server (``mcp_target``) is served on 127.0.0.1 and this loop speaks MCP 2026-07-28 to it over HTTP,
as the Gateway would. No Gateway, no AWS call: what a live Gateway does is AWS's documented
contract, not tested here.

  1. server/discover, tools/list (the inputSchema derived from the seed);
  2. tools/call: not yet approved -> an isError result naming the request; nothing ran;
  3. the app polls (calling again with a new id) while two approver accounts approve;
  4. tools/call after the approvals -> the target executes, checks the signed allow, runs the tool
     ONCE (REFUND SENT in the ledger) and reports the outcome (when the server has the route);
  5. the Gateway retries that invocation (same JSON-RPC id): the stored result, no second refund;
  6. the agent calls again (new id): the statement is spent, so a NEW approval is needed;
  7. every statement and decision checked offline.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Any, Callable

from .demo_flow import Transcript
from .gate import Gate
from .mcp_target import CLIENT_META_DEFAULT, Ledger, McpTarget, serve

MODERN = "2026-07-28"


class McpHttpClient:
    """A minimal MCP 2026-07-28 client over Streamable HTTP (application/json answers only)."""

    def __init__(self, host: str, port: int, path: str = "/mcp"):
        self.host, self.port, self.path = host, port, path

    def request(self, method: str, params: dict | None = None, rpc_id: Any = 1) -> tuple[int, dict]:
        params = dict(params or {})
        params["_meta"] = dict(CLIENT_META_DEFAULT)
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
                   "mcp-protocol-version": MODERN, "mcp-method": method}
        if method == "tools/call":
            headers["mcp-name"] = params["name"]
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            conn.request("POST", self.path, body=json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": method,
                                                             "params": params}), headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read() or b"{}")
        finally:
            conn.close()


def _text(result: dict) -> str:
    return " ".join(c.get("text", "") for c in result.get("content", []))


def capture_records(gate: Gate, act_type: str) -> list[dict]:
    """Keep a copy of every signed statement and decision the gate accepts (the target returns only
    facts about them), for the offline check."""
    records: list[dict] = []
    seen: set[str] = set()
    orig_read, orig_send = gate._read, gate._send

    def _read(request_id, act_type_, act_hash, args):
        sanction = orig_read(request_id, act_type_, act_hash, args)
        if sanction.statement and sanction.statement["receipt_hash"] not in seen:
            seen.add(sanction.statement["receipt_hash"])
            records.append({"kind": "statement", "record": sanction.statement, "arguments": args, "act_type": act_type,
                            "cosignature": sanction.cosignature})
        return sanction

    def _send(key, stored, args, *, replayed):
        decision = orig_send(key, stored, args, replayed=replayed)
        if decision.decision["receipt_hash"] not in seen:
            seen.add(decision.decision["receipt_hash"])
            records.append({"kind": "decision", "record": decision.decision, "arguments": args, "act_type": act_type,
                            "verdict": decision.verdict, "code": decision.code,
                            "cosignature": decision.response.get("cosignature")})
        return decision

    orig_report = gate.report_outcome

    def report_outcome(decision, succeeded, result, detail_code=None):
        before = len(gate.outcome_records)
        status = orig_report(decision, succeeded, result, detail_code)
        args = next((r["arguments"] for r in records if r["kind"] == "decision"
                     and r["record"]["receipt_hash"] == decision.decision["receipt_hash"]), None)
        for rec in gate.outcome_records[before:]:
            if rec["record"]["receipt_hash"] not in seen and args is not None:
                seen.add(rec["record"]["receipt_hash"])
                records.append({"kind": "outcome", "record": rec["record"], "cosignature": rec["cosignature"],
                                "arguments": args, "act_type": act_type})
        return status

    gate._read, gate._send, gate.report_outcome = _read, _send, report_outcome
    return records


def run_target_flow(target: McpTarget, ledger: Ledger, tool_args: dict, t: Transcript, *,
                    approval_url: str, poll: float = 3.0, timeout: float = 600.0,
                    sleep: Callable[[float], None] = time.sleep) -> dict:
    server = serve(target, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    mcp = McpHttpClient("127.0.0.1", server.server_address[1])
    tool = "payments_refund_send"
    out: dict = {"ran": False}
    try:
        t.say(f"Requisition as the AgentCore Gateway TARGET: an MCP server on 127.0.0.1:{server.server_address[1]}/mcp "
              "(run locally; not deployed). It owns the refund tool and runs it only on a signed allow it checked.")
        _, body = mcp.request("server/discover", rpc_id="d-1")
        t.say(f"1. server/discover -> MCP versions {', '.join(body['result']['supportedVersions'])}")
        _, body = mcp.request("tools/list", rpc_id="l-1")
        schema = body["result"]["tools"][0]["inputSchema"]
        t.say(f"   tools/list -> {tool}({', '.join(sorted(schema['properties']))}); unknown members refused")
        t.say(f"2. tools/call {tool} {json.dumps(tool_args, sort_keys=True)}")
        _, body = mcp.request("tools/call", {"name": tool, "arguments": tool_args}, rpc_id=1)
        result = body["result"]
        t.say(f"   -> TOOL ERROR, the refund did NOT run: {_text(result)}")
        out["request_id"] = result.get("_meta", {}).get("requisition", {}).get("request_id")
        t.say(f"   ledger: {len(ledger.entries())} refunds")
        t.say(f"   -> two approver accounts approve it in the console: {approval_url}")
        deadline, rpc, status = time.monotonic() + timeout, 1, None
        while True:
            rpc += 1
            _, body = mcp.request("tools/call", {"name": tool, "arguments": tool_args}, rpc_id=rpc)
            result = body["result"]
            if "awaiting approval" not in _text(result) or time.monotonic() >= deadline:
                break
            sleep(poll)
        t.say(f"3. tools/call again after the approvals (id {rpc})")
        meta = result.get("_meta", {}).get("requisition", {})
        if result.get("isError"):
            t.say(f"   -> TOOL ERROR, the refund did NOT run: {_text(result)}")
            return out
        out.update(ran=True, statement_id=meta.get("statement_id"), outcome_report=meta.get("outcome_report"))
        t.say(f"   -> RAN: {_text(result)}")
        t.say(f"   signed allow {meta.get('receipt_hash', '')[:16]}... checked here; statement {meta.get('statement_id', '')[:16]}...")
        t.say(f"   outcome reported to Requisition: {meta.get('outcome_report')}")
        t.say(f"   ledger: {len(ledger.entries())} refund(s)")
        t.say(f"4. the Gateway retries invocation {rpc} (same JSON-RPC id; AWS: 'the gateway may retry')")
        _, body = mcp.request("tools/call", {"name": tool, "arguments": tool_args}, rpc_id=rpc)
        again = body["result"]
        replayed = again.get("_meta", {}).get("requisition", {}).get("replayed")
        t.say(f"   -> the stored result returned{' (replayed)' if replayed else ''}; ledger: {len(ledger.entries())} refund(s)")
        out["after_retry"] = len(ledger.entries())
        t.say(f"5. the agent calls again with a new id {rpc + 1} (a second refund needs its own approval)")
        _, body = mcp.request("tools/call", {"name": tool, "arguments": tool_args}, rpc_id=rpc + 1)
        t.say(f"   -> {'TOOL ERROR, did NOT run: ' if body['result'].get('isError') else 'RAN: '}{_text(body['result'])}")
        t.say(f"   ledger: {len(ledger.entries())} refund(s)")
        out["final_ledger"] = len(ledger.entries())
        return out
    finally:
        server.shutdown()
        server.server_close()
