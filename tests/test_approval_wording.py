# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""How this repository describes the two approvals an act needs.

An act is approved by two separate accounts. In the evaluation environment one person holds both (the signed records'
`hands` member says "one-person"), so no text here may use the words REFUSED below, which say that two people
approved. Docstrings and comments count: a reader of the code is told the same as a reader of the
README. The README states the approval in the prescribed words, "approved by two separate accounts".

Every pattern below is split into pieces, so that this file does not match itself."""

import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
PRESCRIBED = "approved by two separate accounts"
REFUSED = re.compile("|".join([r"\btwo[- ]" + r"person\b", r"\btwo people" + r" approved\b", r"\bnamed" + r" approvers?\b"]),
                     re.IGNORECASE)
# Text this repository does not author, so this check does not read it (each with its reason):
EXEMPT = {
    "bin/vendor/mldsa.py": "vendored byte for byte (bin/vendor/VENDORED.md)",
    "tests/fixtures/requisition/bin/lab-verify": "a byte copy of Requisition's file (its PROVENANCE.md)",
    "tests/fixtures/requisition/bench/holytrinity-v2/verifier/verify_receipt.py": "a byte copy of Requisition's file "
                                                                                  "(its PROVENANCE.md)",
    "tests/fixtures/verify_receipt_r4/verify_receipt.py": "a byte copy of Requisition's file (its PROVENANCE.md)",
}
EXEMPT_PREFIXES = {
    "tests/fixtures/real_lab_chain/": ".json files only: records as Requisition signed them; their bytes cannot change",
}


def _tracked_files():
    # a failure to list the files FAILS the test; it never skips
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, check=True, capture_output=True).stdout
    return [name for name in out.decode("utf-8").split("\0") if name]


def _exempt(name):
    if name in EXEMPT:
        return True
    return any(name.startswith(prefix) and name.endswith(".json") for prefix in EXEMPT_PREFIXES)


def _hits():
    hits = []
    for name in _tracked_files():
        path = REPO / name
        if _exempt(name) or not path.is_file():
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if REFUSED.search(line):
                hits.append("%s:%d: %s" % (name, number, line.strip()[:120]))
    return hits


def test_no_tracked_file_calls_the_approval_two_person():
    hits = _hits()
    assert hits == [], "say %r instead:\n%s" % (PRESCRIBED, "\n".join(hits))


def test_the_readme_says_approved_by_two_separate_accounts():
    text = re.sub(r"\s+", " ", (REPO / "README.md").read_text(encoding="utf-8"))
    assert PRESCRIBED in text, "README.md does not say %r" % PRESCRIBED


def test_the_exempt_list_names_tracked_files():
    tracked = set(_tracked_files())
    assert sorted(set(EXEMPT) - tracked) == []


def test_the_pattern_finds_each_refused_wording():
    for line in ["a two-" + "person registration", "Two " + "person approval", "two people" + " approved it",
                 "the named" + " approvers"]:
        assert REFUSED.search(line), line
    assert not REFUSED.search("approved by two separate accounts, held by one person")
