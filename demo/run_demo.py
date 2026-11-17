#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The AWS demo: a Strands agent whose refund tool runs only on Requisition's
signed allow for its exact arguments, approved by two approver accounts in Requisition's console.

Live mode calls Amazon Bedrock (openai.gpt-oss-120b-1:0, us-east-1, the AWS profile named by AWS_PROFILE,
synthetic prompts only). --scripted calls no model at all (the fallback).

    export REQUISITION_DEMO_DIR=/path/to/demo       # required: req/ is a Requisition checkout; transcripts go to log/
    # export REQUISITION_LOAD_WRAPPER=/path/to/cmd  # optional: a command placed before docker (--airgap)
    export REQUISITION_URL=http://127.0.0.1:4103
    export REQUISITION_CRED='rqc_...'          # the caller credential; never printed
    export REQUISITION_PRINCIPAL='rqp_...'
    export REQUISITION_LAB_KEY_FILE=...        # required; GET /v1/keys must serve the same bytes
    # export REQUISITION_SOCKET=/path/to.sock  # only if REQUISITION_LAB_SOCKET=true on the server
    uv run python demo/run_demo.py --transcript "$REQUISITION_DEMO_DIR/log/demo-transcript.txt"
    uv run python demo/run_demo.py --scripted --transcript ...

What it shows, in order: the agent's tool call held (interrupt) -> the approval link -> two approvals
in the console -> resume -> execute -> the tool prints REFUND SENT only on a signed allow -> the same
statement again under a fresh nonce is a signed deny statement_spent -> every record checked offline
(bin/verify_offline.py: the arguments recomputed to the signed act_hash, then bin/lab-verify:
"DEGRADED (lab)", a lab key served by the lab, not a trust root).

Limits said on screen: the record proves the act was authorized once,
not that it ran; the key is a lab key; this hook runs in the agent's own process (a compromised agent
can skip it); the interceptor and target forms do not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from strands import Agent, tool  # noqa: E402

from requisition_aws.client import Client  # noqa: E402
from requisition_aws.demo_flow import AIRGAP_IMAGE, Transcript, airgap_check, replay_attempt, run_agent, demo_dir, load_wrapper, verify_all  # noqa: E402
from requisition_aws.gate import Gate  # noqa: E402
from requisition_aws.keys import KeyRegistry  # noqa: E402
from requisition_aws.registry import ToolRegistry  # noqa: E402
from requisition_aws.scripted_model import ScriptedModel  # noqa: E402
from requisition_aws.store import Store  # noqa: E402
from requisition_aws.strands_hook import RequisitionHook  # noqa: E402

MODEL_ID = "openai.gpt-oss-120b-1:0"
REGION = "us-east-1"
PROFILE = None  # boto3's default chain: AWS_PROFILE, else the default profile
ACT_TYPE = "payments.refund_send"
TOOL_NAME = "payments_refund_send"

SYSTEM_PROMPT = (
    "You are a payments support agent. When a refund is needed, call the payments_refund_send tool once "
    "with amount_minor (integer minor units), currency (USD, EUR or GBP), account and a short reason. "
    "If the tool reports that it was held or refused, say so plainly and do not retry it."
)
PROMPT = (
    "Customer account acct-7781 was charged twice for order 4411. Refund 12.50 USD, that is "
    "amount_minor 1250, to account acct-7781 with the reason 'duplicate charge on order 4411'."
)
TRANSCRIPT: Transcript | None = None
SCRIPT_ARGS = {"amount_minor": 1250, "currency": "USD", "account": "acct-7781", "reason": "duplicate charge on order 4411"}


@tool
def payments_refund_send(amount_minor: int, currency: str, account: str, reason: str) -> str:
    """Send a refund to a customer account (a local stub: no money moves).

    Args:
        amount_minor: the amount in integer minor units (1250 is 12.50)
        currency: USD, EUR or GBP
        account: the customer account id
        reason: a short reason for the refund
    """
    line = f"TOOL: REFUND SENT: {amount_minor} {currency} minor units to {account} ({reason})"
    TRANSCRIPT.say(line) if TRANSCRIPT else print(line, flush=True)
    return "REFUND SENT"


def bedrock_model():
    import boto3
    from strands.models.bedrock import BedrockModel

    # the region rides on the session: BedrockModel refuses region_name beside boto_session (bedrock.py:324)
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    return BedrockModel(model_id=MODEL_ID, boto_session=session)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--transcript", required=True, help="where to write the transcript (no credentials)")
    parser.add_argument("--scripted", action="store_true", help="no model: a scripted agent calls the tool")
    parser.add_argument("--store", default=None, help="idempotency store (default: beside the transcript)")
    parser.add_argument("--seed", default=None, help="default: under REQUISITION_DEMO_DIR")
    parser.add_argument("--lab-verify", default=None, help="default: under REQUISITION_DEMO_DIR")
    parser.add_argument("--approval-base", default=None, help="console base URL (default REQUISITION_URL)")
    parser.add_argument("--poll", type=float, default=3.0)
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds to wait for the two approvals")
    parser.add_argument("--airgap", action="store_true",
                        help="then re-run the offline check in docker --network none and show a tampered copy FAIL")
    parser.add_argument("--airgap-image", default=AIRGAP_IMAGE)
    parser.add_argument("--require-pq", action=argparse.BooleanOptionalAction, default=True,
                        help="require each record's ML-DSA-87 co-signature at RUN time (the hook runs "
                             "the tool only then) and in the offline check; --no-require-pq against a server without it")
    parser.add_argument("--wrapper", default=None,
                        help="the load wrapper docker runs under ('' for none; default: REQUISITION_LOAD_WRAPPER, else none)")
    opts = parser.parse_args(argv)
    DEMO = demo_dir()
    if opts.seed is None:
        opts.seed = str(DEMO / "req" / "lab" / "seed" / "aws_demo.v1.json")
    if opts.lab_verify is None:
        opts.lab_verify = str(DEMO / "req" / "bin" / "lab-verify")
    if opts.wrapper is None:
        opts.wrapper = load_wrapper()

    missing = [k for k in ("REQUISITION_URL", "REQUISITION_CRED", "REQUISITION_PRINCIPAL", "REQUISITION_LAB_KEY_FILE")
               if not os.environ.get(k)]
    if missing:
        parser.error("set " + ", ".join(missing))
    url, cred, principal = (os.environ[k] for k in ("REQUISITION_URL", "REQUISITION_CRED", "REQUISITION_PRINCIPAL"))

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    transcript_path = pathlib.Path(opts.transcript)
    out_dir = transcript_path.with_name(transcript_path.stem + "-records")
    out_dir.mkdir(parents=True, exist_ok=True)
    global TRANSCRIPT
    t = TRANSCRIPT = Transcript(secrets_to_elide=(cred,))

    # REQUISITION_SOCKET: once Requisition's Unix socket is configured, /v1 answers only on it (router.ex:19-23)
    client = Client(url, cred, principal, unix_socket=os.environ.get("REQUISITION_SOCKET") or None)
    keys_bytes = pathlib.Path(os.environ["REQUISITION_LAB_KEY_FILE"]).read_bytes()  # the pinned key file
    if client.keys() != keys_bytes:  # GET /v1/keys must serve the same bytes
        t.say("REFUSED: GET /v1/keys is not byte-equal to REQUISITION_LAB_KEY_FILE")
        t.write(str(transcript_path))
        return 1
    registry_path = out_dir / "lab-keys.json"
    registry_path.write_bytes(keys_bytes)
    # require_pq at RUN time: the tool runs only on records whose ML-DSA-87 signature was checked here
    gate = Gate(client, Store(opts.store or str(out_dir / "store.json")),
                approval_base_url=opts.approval_base or url, keys=KeyRegistry.from_bytes(keys_bytes),
                require_pq=opts.require_pq)
    tools = ToolRegistry.from_seed(opts.seed, {TOOL_NAME: ACT_TYPE})

    session_id = f"demo-{run_id}"
    hook = RequisitionHook(gate, tools, agent_name="refund-agent", session_id=session_id,
                           on_event=lambda e: t.say(f"  hook: {e.kind} {e.detail}"))
    if opts.scripted:
        model, model_note = ScriptedModel([{"tool": TOOL_NAME, "input": SCRIPT_ARGS}, {"text": "Done."}]), "scripted (no model)"
    else:
        model, model_note = bedrock_model(), f"Amazon Bedrock {MODEL_ID}, {REGION}, profile {PROFILE or os.environ.get('AWS_PROFILE') or 'default'}"
    agent = Agent(model=model, tools=[payments_refund_send], hooks=[hook], system_prompt=SYSTEM_PROMPT, callback_handler=None)

    t.say(f"Requisition AWS demo, run {run_id}")
    t.say(f"  Requisition {url} (lab profile, dev-only); principal {principal}; credential <elided>")
    t.say(f"  agent model: {model_note}; session {session_id}")
    t.say("  limits: the record proves the act was AUTHORIZED once, not that it ran; the key is a LAB key "
          "served by the lab, not a trust root; this hook runs in the agent's own process (a compromised "
          "agent can skip it); the Gateway interceptor and target forms do not")
    t.say()
    run_agent(agent, hook, gate, PROMPT, t, poll=opts.poll, timeout=opts.timeout)
    t.say()
    try:
        replay_attempt(gate, hook, t)
    except Exception as error:  # noqa: BLE001 - shown, not hidden
        t.say(f"REPLAY: failed: {type(error).__name__}: {error}")
    t.say()
    ok = verify_all(hook.records, str(out_dir), lab_verify=opts.lab_verify, registry_path=str(registry_path), t=t,
                    require_pq=opts.require_pq)
    t.say()
    t.say(f"OFFLINE CHECK: {'every record passed' if ok else 'NOT every record passed (see above)'}; records in {out_dir}")
    if opts.airgap:
        t.say()
        ok = airgap_check(hook.records, str(out_dir), registry_path=str(registry_path), req_tree=str(DEMO / "req"),
                          t=t, image=opts.airgap_image, wrapper=(opts.wrapper,) if opts.wrapper else (),
                          require_pq=opts.require_pq) and ok
    t.write(str(transcript_path))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
