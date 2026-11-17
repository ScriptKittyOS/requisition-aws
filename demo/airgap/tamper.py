# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Run INSIDE the airgap container (python3 -I): copy a signed record and change ONE character of its
signed payload, then recompute receipt_hash as a forger would, so only the signature can catch it.

    python3 -I tamper.py IN.json OUT.json

The character changed is the first one of the signed metadata's nonce (a decision) or the last digit
of occurred_at (any record): fields the act binding does not cover, so the binding still matches and
the failure shown is the signature's."""

import hashlib
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src) as handle:
    record = json.load(handle)
envelope = record
for key in ("decision", "statement", "record"):
    if isinstance(record.get(key), dict) and "signed_payload" in record[key]:
        envelope = record[key]
payload = envelope["signed_payload"]
signed = json.loads(payload)
nonce = signed.get("metadata", {}).get("nonce")
if isinstance(nonce, str) and nonce:
    needle = '"nonce":"%s"' % nonce
    at = payload.index(needle) + len('"nonce":"')
else:
    at = payload.index('"occurred_at":"') + len('"occurred_at":"') + len("2026-01-01T00:00:0")
old = payload[at]
new = {"0": "1"}.get(old, "0") if old.isdigit() else ("b" if old != "b" else "c")
envelope["signed_payload"] = payload[:at] + new + payload[at + 1:]
envelope["receipt_hash"] = hashlib.sha256(envelope["signed_payload"].encode("utf-8")).hexdigest()
with open(dst, "w") as handle:
    json.dump(record, handle)
print("tampered copy: signed_payload character %d changed %r -> %r; receipt_hash recomputed (as a forger would)"
      % (at, old, new))
