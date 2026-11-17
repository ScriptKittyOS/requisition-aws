# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A DRY-RUN stand-in for the lab /v1 server, so demo/rehearse.sh can be exercised with no live
Requisition and no Bedrock (REHEARSE_DRY=1). It is the tests' fake (tests/fake_requisition.py), NOT
Requisition: its records are signed by throwaway keys made at start, and it approves each request on
its Nth read (the console's two approvals, simulated).

    uv run python -m tests.fake_server_main --env-out DIR/env.sh --keys-out DIR/lab-keys.json \
        [--seed FILE] [--newer-routes] [--cosign signed|seat_absent] [--auto-approve-after 2]

--seed defaults to $REQUISITION_DEMO_DIR/req/lab/seed/aws_demo.v1.json, the file demo/run_demo.py
reads by default; with neither, it stops (exit 2).
"""

import argparse
import json
import os
import shlex
import signal
import sys
import threading

from requisition_aws import canonical

from .fake_requisition import FakeRequisition

SEED_UNDER_DEMO_DIR = ("req", "lab", "seed", "aws_demo.v1.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-out", required=True)
    ap.add_argument("--keys-out", required=True)
    ap.add_argument("--seed", default=None, help="default: under REQUISITION_DEMO_DIR")
    ap.add_argument("--newer-routes", action="store_true")
    ap.add_argument("--cosign", default=None)
    ap.add_argument("--auto-approve-after", type=int, default=2)
    a = ap.parse_args()
    if a.seed is None:
        demo = os.environ.get("REQUISITION_DEMO_DIR", "")
        if not demo:
            ap.error("pass --seed, or set REQUISITION_DEMO_DIR to the demo folder")
        a.seed = os.path.join(demo, *SEED_UNDER_DEMO_DIR)
    with open(a.seed) as handle:
        rows = json.load(handle)["act_types"]
    act_types = {r["registration"]["name"]: canonical.ArgsSchema(r["registration"]["display_schema"]) for r in rows}
    fake = FakeRequisition(act_types=act_types, newer_routes=a.newer_routes, cosign=a.cosign or None)
    fake.auto_approve_after = a.auto_approve_after
    url = fake.start()
    with open(a.keys_out, "w") as handle:
        json.dump(fake.registry, handle)
    with open(a.env_out, "w") as handle:
        for k, v in {"REQUISITION_URL": url, "REQUISITION_CRED": fake.credential,
                     "REQUISITION_PRINCIPAL": fake.principal, "REQUISITION_LAB_KEY_FILE": a.keys_out}.items():
            handle.write(f"export {k}={shlex.quote(v)}\n")
    print(f"DRY-RUN fake /v1 (not Requisition) on {url}", flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    fake.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
