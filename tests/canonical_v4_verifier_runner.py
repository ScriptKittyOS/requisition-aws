# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The offline verifier's runner of the canonical_payload.v4 differential. Standard library only:

    python3 -I tests/canonical_v4_verifier_runner.py

It loads bin/verify_offline.py as the kit runs it (isolated mode, no site-packages, nothing of requisition_aws) and
gives every row of the shared vector file, and of the one-mutation negative set, to verify_offline.canonicalize_v4.
Each row must come back as exactly the row's canonical bytes, or as a refusal with the row's reason code.

CANONICAL_V4_FIXTURES names the fixture directory (default: this repository's byte copy, tests/vectors/canonical_v4).
With CANONICAL_V4_RESULTS_DIR set, the per-row answers are written to <dir>/verifier.jsonl for requisition's
bin/canonical-v4-compare. Exit 0 only when every row agrees and the two files are the pinned bytes.
"""

import base64
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "bin", "verify_offline.py")
PINS = {
    "vectors.jsonl": "994c7ead2259b0fbbe5201b29f189e84d25c16bc6f12cc3c3a5a5d5cd4643f98",
    os.path.join("negative", "cases.jsonl"): "ef5a499a9ed1e8fe336eee104e49457f9e157c4b760a8f46e1d2948c0964d669",
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_offline", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_rows(fixtures):
    rows = []
    for name, pin in PINS.items():
        with open(os.path.join(fixtures, name), "rb") as handle:
            data = handle.read()
        if hashlib.sha256(data).hexdigest() != pin:
            raise SystemExit("FAIL: %s is not the pinned file (sha256 %s)" % (name, hashlib.sha256(data).hexdigest()))
        rows += [json.loads(line) for line in data.decode("utf-8").splitlines()]
    return rows


def answer(verifier, row):
    try:
        out = verifier.canonicalize_v4(base64.b64decode(row["input_b64"]))
    except verifier.Refused as refusal:
        return {"id": row["id"], "result": "refuse", "reason": str(refusal.code)}
    return {"id": row["id"], "result": "bytes", "canonical_b64": base64.b64encode(out).decode("ascii")}


def expected(row):
    if row["expect"] == "bytes":
        return {"id": row["id"], "result": "bytes", "canonical_b64": row["canonical_b64"]}
    return {"id": row["id"], "result": "refuse", "reason": row["reason"]}


def run(fixtures=None, results=None):
    """(rows, wrong): the row count and the list of (id, answer, expected) that differ."""
    fixtures = fixtures or os.environ.get("CANONICAL_V4_FIXTURES") or os.path.join(HERE, "vectors", "canonical_v4")
    results = results or os.environ.get("CANONICAL_V4_RESULTS_DIR")
    verifier = load_verifier()
    rows = read_rows(fixtures)
    answers = [answer(verifier, row) for row in rows]
    if results:
        os.makedirs(results, exist_ok=True)
        with open(os.path.join(results, "verifier.jsonl"), "w", encoding="utf-8") as handle:
            for item in answers:
                handle.write(json.dumps(item, sort_keys=True) + "\n")
    wrong = [(row["id"], got, expected(row)) for row, got in zip(rows, answers) if got != expected(row)]
    return len(rows), wrong


def main():
    rows, wrong = run()
    for row_id, got, want in wrong[:20]:
        print("%s: answered %s, the row says %s" % (row_id, json.dumps(got)[:160], json.dumps(want)[:160]))
    if wrong or rows == 0:
        print("FAIL: %d of %d rows differ" % (len(wrong), rows))
        return 1
    print("PASS: bin/verify_offline.py gave the row's answer for each of %d rows" % rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
