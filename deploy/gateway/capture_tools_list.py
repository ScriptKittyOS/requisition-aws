# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""OPERATOR-RUN, read only: list the Gateway's tools and print each listed tool's digest (G2). It sends tools/list (and its follow-up pages) and nothing else; it never invokes a tool.

    # dry: says what it would do, sends nothing
    python deploy/gateway/capture_tools_list.py
    # offline: digest a saved capture
    python deploy/gateway/capture_tools_list.py --from-file <capture.json>
    # live: a SigV4-signed tools/list to the Gateway's MCP endpoint
    python deploy/gateway/capture_tools_list.py --go --url https://<gateway>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp \
        --profile <profile> --region us-west-2 --save <dir>/capture.json

Output: one line per listed tool, ``<name> <digest>`` (``<name> UNENCODABLE (<code>)`` when the
definition has no digest). The Gateway digest for the v2 registration comes from this line, never
from the template (deploy/registration/fill_gateway_digest.py takes the saved capture).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent))

from requisition_aws import catalog  # noqa: E402
from requisition_aws.client import loads_strict  # noqa: E402

METHOD = "tools/list"
MAX_PAGES = 50


def digests(pages: list) -> list[str]:
    lines = []
    for page in pages:
        result = page.get("result", page) if isinstance(page, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise SystemExit("refused: not a tools/list response")
        for tool in result["tools"]:
            name = tool.get("name") if isinstance(tool, dict) else None
            try:
                lines.append(f"{name} {catalog.tool_digest(tool)}")
            except catalog.CatalogRefusal as refusal:
                lines.append(f"{name} UNENCODABLE ({refusal.code})")
    return lines


def live_pages(url: str, profile: str, region: str) -> list:  # pragma: no cover - the live read
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    credentials = boto3.Session(profile_name=profile, region_name=region).get_credentials().get_frozen_credentials()
    pages, cursor = [], None
    for n in range(MAX_PAGES):
        params = {"cursor": cursor} if cursor else {}
        body = json.dumps({"jsonrpc": "2.0", "id": n + 1, "method": METHOD, "params": params}).encode()
        request = AWSRequest(method="POST", url=url, data=body, headers={
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "Mcp-Method": METHOD})
        SigV4Auth(credentials, "bedrock-agentcore", region).add_auth(request)
        prepared = urllib.request.Request(url, data=body, headers=dict(request.headers), method="POST")
        with urllib.request.urlopen(prepared, timeout=30) as response:
            page = loads_strict(response.read())
        pages.append(page)
        cursor = (page.get("result") or {}).get("nextCursor") if isinstance(page, dict) else None
        if not cursor:
            return pages
    raise SystemExit(f"refused: more than {MAX_PAGES} pages")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Operator-run, read only: the Gateway's tools/list and each tool's digest")
    ap.add_argument("--go", action="store_true", help="make the live, signed tools/list request")
    ap.add_argument("--from-file", help="digest a saved capture instead (offline)")
    ap.add_argument("--url")
    ap.add_argument("--profile", default=None)
    ap.add_argument("--region", default="us-west-2")
    ap.add_argument("--save", help="where to save the raw pages (JSON list)")
    a = ap.parse_args(argv)
    if a.from_file:
        captured = loads_strict(pathlib.Path(a.from_file).read_bytes())
        pages = captured if isinstance(captured, list) else [captured]
    elif a.go:
        if not a.url:
            ap.error("--go needs --url (the Gateway's MCP endpoint)")
        pages = live_pages(a.url, a.profile, a.region)
        if a.save:
            pathlib.Path(a.save).write_text(json.dumps(pages, indent=1) + "\n")
    else:
        print(f"would send a SigV4-signed {METHOD} (and its follow-up pages) to the Gateway URL given with --url, "
              f"as profile {a.profile or '(boto3 default chain)'} in {a.region}, and print each listed tool's digest; nothing sent "
              "(pass --go for the live read, or --from-file for a saved capture)")
        return 0
    for line in digests(pages):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
