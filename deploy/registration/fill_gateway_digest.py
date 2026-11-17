# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Complete the v2 registration payload with the Gateway's tool digest (G2). Local only:
it reads two files and writes one; no network, no AWS, no Requisition call.

    python deploy/registration/fill_gateway_digest.py \
        --incomplete deploy/registration/aws_demo_v2.INCOMPLETE.json \
        --captured <the saved tools/list response from deploy/gateway/capture_tools_list.py --go --save> \
        --tool refunds___payments_refund_send --out <dir>/aws_demo_v2.v1.json

The output's set is ``aws_demo_v2`` and its ``tool_digest`` enum holds every form's pin: the Strands
digest already in the incomplete file, then the digest of the Gateway's listed definition of
``--tool``. A capture without that tool, or with a definition that has no digest (a float), is refused
and nothing is written. The lab's operator then copies the output to the requisition repository's
``lab/seed/aws_demo_v2.v1.json`` and registers it (deploy/registration/README.md).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from requisition_aws import catalog  # noqa: E402
from requisition_aws.client import loads_strict  # noqa: E402


def listed_tools(captured: object) -> list:
    """The ``tools`` of a saved tools/list response: a JSON-RPC response, its ``result``, or a list of
    pages (each a response) as the capture script saves them."""
    pages = captured if isinstance(captured, list) else [captured]
    tools: list = []
    for page in pages:
        result = page.get("result", page) if isinstance(page, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise SystemExit("refused: the capture is not a tools/list response")
        tools.extend(result["tools"])
    return tools


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--incomplete", required=True)
    ap.add_argument("--captured", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    seed = loads_strict(pathlib.Path(a.incomplete).read_bytes())
    found = [t for t in listed_tools(loads_strict(pathlib.Path(a.captured).read_bytes()))
             if isinstance(t, dict) and t.get("name") == a.tool]
    if len(found) != 1:
        print(f"refused: the capture lists {len(found)} tools named {a.tool!r} (need exactly one)", file=sys.stderr)
        return 2
    try:
        digest = catalog.tool_digest(found[0])
    except catalog.CatalogRefusal as refusal:
        print(f"refused: {a.tool!r} has no digest ({refusal.code}); the tool stays refused", file=sys.stderr)
        return 2
    [row] = seed["act_types"]
    entry = next(e for e in row["registration"]["display_schema"] if e.get("path") == catalog.DIGEST_PATH)
    if digest not in entry["values"]:
        entry["values"].append(digest)
    seed.pop("incomplete", None)
    seed["set"] = "aws_demo_v2"
    out = pathlib.Path(a.out)
    out.write_text(json.dumps(seed, indent=1) + "\n")
    print(f"wrote {out}: tool_digest enum = {entry['values']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
