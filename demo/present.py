#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Print a transcript for the screen: short, no credentials. Keeps the story lines and each record's
verdicts; drops bin/lab-verify's raw output (it stays in the transcript file) and the timestamps.

    python3 -I demo/present.py TRANSCRIPT [SECRET_ENV_NAME ...]

Elided wherever they appear: the values of the named environment variables (default REQUISITION_CRED,
AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN), and anything shaped like a caller credential (rqc_...), a
bearer token, an AWS access key id or secret."""

import os
import re
import sys

PATTERNS = [
    re.compile(r"rqc_[A-Za-z0-9_-]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(aws_secret_access_key|aws_session_token)\s*[=:]\s*\S+"),
]
KEEP_INDENTED = ("verdict:", "signed verdict", "co-signature", "ML-DSA-87 signature", "outcome reported",
                 "post-quantum REQUIRED", "act_hash:", "network probe", "no network", "tampered copy",
                 "NETWORK PRESENT")
STAMP = re.compile(r"^\[\d\d:\d\d:\d\d\] ?")
LONG_HEX = re.compile(r"\b([0-9a-f]{16})[0-9a-f]{24,}\b")
DROP = ("== 2.", "== 3.", "lab-verify exit")


def present(lines, secrets):
    out = []
    for raw in lines:
        line = STAMP.sub("", raw.rstrip("\n"))
        stripped = line.strip()
        if stripped.startswith("|") or stripped.startswith(DROP):
            continue
        if line.startswith("    ") and not any(stripped.startswith(k) or k in stripped for k in KEEP_INDENTED):
            continue
        if stripped.startswith("hook: ") and not any(w in stripped for w in ("proposed", "allowed", "cancelled", "outcome")):
            continue
        for secret in secrets:
            line = line.replace(secret, "<elided>")
        for pattern in PATTERNS:
            line = pattern.sub("<elided>", line)
        line = LONG_HEX.sub(r"\1...", line)
        out.append(line)
    return out


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    names = argv[1:] or ["REQUISITION_CRED", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
    secrets = [os.environ[n] for n in names if os.environ.get(n)]
    with open(argv[0], encoding="utf-8") as handle:
        for line in present(handle, secrets):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
