#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Re-run the offline check of a finished run's records with NO network (docker --network none), then
show a one-character change of a copy's signed payload FAIL. No server, no AWS: local files only.

    uv run python demo/run_airgap.py --records <transcript>-records --transcript <dir>/airgap.txt [--no-require-pq]

The records directory is what demo/run_demo.py or demo/run_target_local.py wrote (manifest.json, the
NN-kind.arguments.json / .record.json pairs and lab-keys.json)."""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from requisition_aws.demo_flow import AIRGAP_IMAGE, Transcript, airgap_check, records_from_manifest, demo_dir, load_wrapper  # noqa: E402



def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--records", required=True)
    ap.add_argument("--registry", default=None, help="default: <records>/lab-keys.json")
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--req-tree", default=None, help="default: REQUISITION_DEMO_DIR/req")
    ap.add_argument("--image", default=AIRGAP_IMAGE)
    ap.add_argument("--wrapper", default=None,
                    help="the load wrapper ('' for none; default: REQUISITION_LOAD_WRAPPER, else none)")
    ap.add_argument("--require-pq", action=argparse.BooleanOptionalAction, default=True)
    a = ap.parse_args(argv)
    if a.req_tree is None:
        a.req_tree = str(demo_dir() / "req")
    if a.wrapper is None:
        a.wrapper = load_wrapper()
    records_dir = pathlib.Path(a.records)
    t = Transcript()
    ok = airgap_check(records_from_manifest(str(records_dir)), str(records_dir),
                      registry_path=a.registry or str(records_dir / "lab-keys.json"), req_tree=a.req_tree, t=t,
                      image=a.image, wrapper=(a.wrapper,) if a.wrapper else (), require_pq=a.require_pq)
    t.write(a.transcript)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
