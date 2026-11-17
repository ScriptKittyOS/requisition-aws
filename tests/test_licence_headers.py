# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""This repository is Apache-2.0: the exact licence text in LICENSE, a NOTICE naming the copyright holder, the SPDX
expression in pyproject.toml, and the SPDX identifier with the copyright line at the top of every source file the
repository authors. A file is a source file when it is tracked and is Python, shell, Elixir script, escript or a
Dockerfile, or starts with "#!". The files that do not carry the header are listed below, each with its reason, and
the list is exact: an entry that is not a tracked source file, or that already carries the header, fails the test."""

import hashlib
import pathlib
import subprocess
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent
SPDX = "SPDX-License-Identifier: Apache-2.0"
COPYRIGHT = "Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)"
# The Apache License 2.0 text, byte for byte as the Apache Software Foundation distributes it (11,358 bytes).
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
SOURCE_SUFFIXES = {".py", ".sh", ".exs", ".escript"}
SOURCE_NAMES = {"Dockerfile"}
# The header is a comment in the first lines of the file (after a "#!" line, where there is one).
HEADER_LINES = 5
COMMENT_LEADERS = ("#", "%%", "%")

THIRD_PARTY = {
    "bin/vendor/mldsa.py": "mldsa-py 1.0.1 by Filippo Valsorda, CC0-1.0 OR 0BSD, byte for byte (bin/vendor/VENDORED.md)",
}
PINNED_COPIES = {
    "tests/fixtures/verify_receipt_r4/verify_receipt.py":
        "a byte copy of Requisition's file, pinned by sha256 (its PROVENANCE.md)",
}
EXEMPT = {**THIRD_PARTY, **PINNED_COPIES}


def _tracked():
    # a failure to list the files FAILS the test; it never skips
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, check=True, capture_output=True).stdout
    return sorted(name for name in out.decode("utf-8").split("\0") if name)


def _is_source(name):
    path = REPO / name
    if not path.is_file():
        return False
    if path.suffix in SOURCE_SUFFIXES or path.name in SOURCE_NAMES:
        return True
    with path.open("rb") as handle:
        return handle.read(2) == b"#!"


def _comment_texts(name):
    lines = (REPO / name).read_text(encoding="utf-8").splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    texts = []
    for line in lines[:HEADER_LINES]:
        for leader in COMMENT_LEADERS:
            if line.startswith(leader):
                texts.append(line[len(leader):].strip())
                break
    return texts


def _has_header(name):
    texts = _comment_texts(name)
    return SPDX in texts and COPYRIGHT in texts


def _sources():
    return [name for name in _tracked() if _is_source(name)]


def test_license_is_the_apache_2_0_text():
    data = (REPO / "LICENSE").read_bytes()
    assert hashlib.sha256(data).hexdigest() == APACHE_2_0_SHA256, "LICENSE is not the Apache License 2.0 text"


def test_notice_names_the_copyright_holder():
    lines = (REPO / "NOTICE").read_text(encoding="utf-8").splitlines()
    assert COPYRIGHT in lines, "NOTICE lacks the line %r" % COPYRIGHT


def test_pyproject_declares_apache_2_0():
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    # the wheel carries bin/vendor/mldsa.py (CC0-1.0 OR 0BSD), so the expression names both
    assert project.get("license") == "Apache-2.0 AND (CC0-1.0 OR 0BSD)"
    assert {"LICENSE", "NOTICE", "bin/vendor/LICENSE.mldsa"} <= set(project.get("license-files", []))


def test_every_source_file_carries_the_header():
    missing = [name for name in _sources() if name not in EXEMPT and not _has_header(name)]
    assert missing == [], "source files without %r and %r in their first lines: %s" % (SPDX, COPYRIGHT, missing)


def test_the_exempt_list_is_exact():
    sources = set(_sources())
    not_sources = sorted(name for name in EXEMPT if name not in sources)
    assert not_sources == [], "exempt entries that are not tracked source files: %s" % not_sources
    stale = sorted(name for name in EXEMPT if name in sources and _has_header(name))
    assert stale == [], "exempt entries that now carry the header (remove them from the list): %s" % stale
