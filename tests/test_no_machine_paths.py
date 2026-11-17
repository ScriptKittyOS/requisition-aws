# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""No tracked file names a home directory, one of the project's private working folders, or the project's internal
workflow (who runs what, review and finding ids, lane and plan names, internal gap and
requirement ids), and the canonical v4 test files name no scratch folder. A path that exists on one machine passes
there and fails, or reads something else, everywhere else; a pointer into a private folder or an internal process
means nothing to a reader of this repository.

Every pattern below is split into pieces, so that this file does not match itself."""

import pathlib
import re
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
FILES = ["test_canonical.py", "test_canonical_v4.py", "canonical_v4_verifier_runner.py"]
HOME_PATH = re.compile(r"/home/[A-Za-z0-9_.-]+|/Users/[A-Za-z0-9_.-]+")
# a working folder, dated or not, or the project folder holding them
PRIVATE_FOLDER = re.compile(r"\.scratch" + r"-|project" + r"-sanction")
# the workflow wording; an internal lane label is "lane" and a digit, in any case, with or without a space, "_" or
# "-" between them and no letter before it, in prose or inside an identifier (a test name, a flag, a variable)
WORKFLOW = re.compile("|".join([
    r"coordi" + r"nator", r"owner's" + r" go", r"owner" + r"-run", r"delta[- ]" + r"review", r"build" + r" review",
    r"review" + r"-r[0-9]", r"fix" + r" round", r"(?i:(?<![a-z])la" + r"ne[ _-]?[0-9])", r"PLAN" + r"\.md",
    r"HAND" + r"BACK", r"OWNER" + r"-GOS", r"RULES" + r"\.md", r"\bW1" + r"-[0-9]", r"GAP" + r"-[A-Z]+-[0-9]",
    r"\bREQ" + r"-[0-9]+", r"\bG" + r"-[0-9]{3}",
    # as requisition-ts's census: the earlier name of that package, and a landing named in text
    r"(?<![A-Za-z])[Rr][Ss]" + r"[Dd][Kk](?![A-Za-z])", r"R-" + r"SDK", r"this lan" + r"ding",
]))
# Text this repository does not author, so the workflow census does not read it (each with its reason):
WORKFLOW_EXEMPT = {
    "bin/vendor/mldsa.py": "vendored byte for byte (bin/vendor/VENDORED.md)",
    "tests/fixtures/requisition/bin/lab-verify": "a byte copy of Requisition's file (its PROVENANCE.md)",
    "tests/fixtures/requisition/bench/holytrinity-v2/verifier/verify_receipt.py": "a byte copy of Requisition's file "
                                                                                  "(its PROVENANCE.md)",
    "tests/fixtures/verify_receipt_r4/verify_receipt.py": "a byte copy of Requisition's file (its PROVENANCE.md)",
}
# The real lab records (tests/fixtures/real_lab_chain/) are read like any other file: the one internal reference they
# hold is the signed label below, inside their signed bytes.
WORKFLOW_EXEMPT_PREFIXES = {}
# the label Requisition signs into every lab record (its "hands" member), a quoted value inside signed bytes; the
# fake reproduces it byte for byte, and the real lab records carry it in their signed_payload
SIGNED_LABELS = ["one-person (G" + "-301)"]


# A commit id, in any tracked text file (prose, code comments, docstrings, data) or in a file or folder name. This
# repository's history and Requisition's are private, so such an id means nothing to a reader. A candidate is 7 to 40
# hexadecimal characters holding a letter and a digit, not part of a longer word, number or base64 run (a UUID is
# blanked first, and a longer hex run such as a sha256 is never a candidate). It is refused when:
#   - it is NAMED as a commit: right after "commit", "at", "from", "since", "rev", "tree", "version", "tip", "main" or
#     a repository name (requisition, requisition-aws, requisition-ts), with a space, a hyphen, a colon, "(" or "`"
#     between, so "requisition-<id>" and "at <id>" are refused at any length;
#   - or it stands alone (no hyphen joined to it) and is 7 to 12 or 40 characters long, the lengths git prints;
#   - or it stands alone in prose (.md, .txt) at any length from 7 to 40;
#   - or it is a whole piece of a file or folder name.
# Hex data joined by hyphens or of other lengths in code and data (a session id "mcp-session-<hex>", an RFC 8785 test
# value, a nonce, a vector message) is not named as a commit and is kept. Also kept: a public upstream commit listed
# below with its repository; the git tree id of requisition_aws/ written where it is named as that tree (a value a
# reader can recompute); a digest named as a sha256; the word ed25519, an algorithm's name. The byte copies
# WORKFLOW_EXEMPT lists are not read.
COMMIT_ID = re.compile(r"(?<![0-9A-Za-z_./+])(?=[0-9a-f]*[a-f])(?=[0-9a-f]*[0-9])[0-9a-f]{7," + r"40}(?![0-9A-Za-z_+/])")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
NAMED_AS_COMMIT = re.compile(r"(?i:\b(?:commits?|at|from|since|rev|tree|version|tip|main|requisition(?:-aws|-ts)?))"
                             r"[ \t`(:-]+$")
PUBLIC_COMMITS = {
    "975de31e": "usnistgov/ACVP-Server, release v1.1.0.43 (tests/vectors/mldsa87/PROVENANCE.md)",
    "d17cc89f": "C2SP/wycheproof (tests/vectors/mldsa87/PROVENANCE.md)",
    "13247ea5": "Probity agent-evidence-vectors (tests/vectors/canonical_v4/PROVENANCE.md)",
}
# the token right after one of these is named as what it is (a tree id of requisition_aws/, or a digest)
NAMED_NOT_A_COMMIT = re.compile(r"(?:requisition_aws tree: `|\"requisition_aws_tree\": \"|(?i:sha-?256:? ))$")
NOT_A_COMMIT_WORDS = {"ed25519"}
PROSE = (".md", ".txt")
PATH_PIECES = re.compile(r"[/_.\- ]")


def _masked(line):
    """The line with every UUID blanked (same length, so positions hold)."""
    return UUID.sub(lambda m: " " * len(m.group(0)), line)


def _kept(token):
    return token[:8] in PUBLIC_COMMITS or token in NOT_A_COMMIT_WORDS


def _refused(name, line, match):
    token, before, after = match.group(0), line[:match.start()], line[match.end():match.end() + 1]
    if _kept(token) or NAMED_NOT_A_COMMIT.search(before):
        return False
    if NAMED_AS_COMMIT.search(before):
        return True
    if before.endswith("-") or after == "-":
        return False
    return len(token) <= 12 or len(token) == 40 or name.endswith(PROSE)


def _commit_ids_in(name, text):
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        line = _masked(line)
        for match in COMMIT_ID.finditer(line):
            if _refused(name, line, match):
                hits.append("%s:%d: %s" % (name, number, match.group(0)))
    return hits


def _commit_ids_in_paths(paths):
    """Each piece of a path (split at /, _, ., - and space) that is wholly an id."""
    hits = []
    for path in paths:
        for piece in PATH_PIECES.split(path):
            if COMMIT_ID.fullmatch(piece) and not _kept(piece):
                hits.append("%s: %s" % (path, piece))
    return hits


def _commit_scanned():
    return [(name, text) for name, text in _tracked_texts() if not _workflow_exempt(name)]


def _commit_ids_anywhere():
    return [hit for name, text in _commit_scanned() for hit in _commit_ids_in(name, text)]


def _tracked_files():
    # a failure to list the files FAILS the test; it never skips
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, check=True, capture_output=True).stdout
    return [name for name in out.decode("utf-8").split("\0") if name]


def _tracked_texts():
    for name in _tracked_files():
        path = REPO / name
        if not path.is_file():
            continue
        try:
            yield name, path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue


def _tracked_lines_matching(pattern, exempt=lambda name: False, drop=()):
    hits = []
    for name, text in _tracked_texts():
        if exempt(name):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for label in drop:
                line = line.replace(label, "")
            if pattern.search(line):
                hits.append("%s:%d" % (name, number))
    return hits


def _workflow_exempt(name):
    if name in WORKFLOW_EXEMPT:
        return True
    return any(name.startswith(prefix) and name.endswith(".json") for prefix in WORKFLOW_EXEMPT_PREFIXES)


def test_no_tracked_file_names_a_home_directory():
    hits = _tracked_lines_matching(HOME_PATH)
    assert hits == [], "tracked files naming a home directory: %s" % hits


def test_no_tracked_file_names_a_private_working_folder():
    hits = _tracked_lines_matching(PRIVATE_FOLDER)
    assert hits == [], "tracked files naming a private working folder: %s" % hits


def test_no_tracked_file_speaks_the_internal_workflow():
    hits = _tracked_lines_matching(WORKFLOW, exempt=_workflow_exempt, drop=SIGNED_LABELS)
    assert hits == [], "tracked files with internal workflow wording: %s" % hits


def test_no_tracked_file_names_a_private_commit():
    hits = _commit_ids_anywhere()
    assert hits == [], "commit ids (name the version, a public tag or a sha256 instead): %s" % hits


# Made-up ids for the plants below: none is, or abbreviates, a commit or tree of any repository (checked with
# git cat-file -e in every local repository on 2026-11-17). Each is split so that this file does not match itself.
FAKE_7 = "c0ff" + "ee7"
FAKE_8 = "5eed" + "f00d"
FAKE_16 = "0ddb" + "a11c" + "0ffe" + "e123"
FAKE_40 = "f00d" + "f00d" * 9
FAKE_TREE = "7ee5" + "1d" * 18
FAKE_SHA256 = "a1b2" + "a1b2" * 15


def test_the_census_finds_a_lane_label_and_a_commit_id():
    for line in ["la" + "ne2b", "--la" + "ne1b", "LA" + "NE3_KEYS", "La" + "ne 2a", "la" + "ne_4", "def test_with_la" + "ne1b():",
                 "rs" + "dk-1-2", "R-" + "SDK", "refused in this lan" + "ding"]:
        assert WORKFLOW.search(line), line
    for line in ["at commit `" + FAKE_8 + "`", "requisition " + FAKE_40 + " here", "# router.ex:121 at " + FAKE_8,
                 "(as at " + FAKE_7 + ")", "# from requisition-" + FAKE_8, "the code at " + FAKE_16]:
        assert _commit_ids_in("planted.py", line), line
    for line in ["planes 2", "the lanes", "plane3", "a sha256 " + FAKE_SHA256, "tests/fixtures/verify_receipt_" + "r4/",
                 "abcdefab", "12345678", "base64 +" + FAKE_8 + "+x", "account:" + "8979b" + "ed4-1111-2222-3333-44445555aaaa",
                 '"mcp-session-' + FAKE_8 + '"', '"nonce": "' + FAKE_16 + '"',
                 "created at " + "8979b" + "ed4-1111-2222-3333-44445555aaaa"]:
        assert not (WORKFLOW.search(line) or _commit_ids_in("planted.py", line)), line


def test_the_commit_check_refuses_a_private_commit_and_keeps_the_named_values():
    text = ("tested at `" + FAKE_8 + "`\n"
            "    x = 1  # router.ex:121 at " + FAKE_7 + "\n"
            "vectors at `" + "975de31e" + "`, ed25519\n"
            "requisition_aws tree: `" + FAKE_TREE + "`\n"
            "sha256 " + FAKE_8 + "...86db8c, sha256: " + FAKE_SHA256 + "\n"
            "# from requisition-" + FAKE_8 + "\n"
            "# the code at " + FAKE_16 + "\n"
            'session = "mcp-session-' + FAKE_8 + '"; value = "' + FAKE_16 + '"\n'
            "# see " + FAKE_8 + " for the change\n")
    assert _commit_ids_in("planted.py", text) == ["planted.py:1: " + FAKE_8, "planted.py:2: " + FAKE_7,
                                                  "planted.py:6: " + FAKE_8, "planted.py:7: " + FAKE_16,
                                                  "planted.py:9: " + FAKE_8]
    assert _commit_ids_in("planted.md", "built from an id of " + FAKE_16 + " characters") == ["planted.md:1: " + FAKE_16]


def test_the_commit_check_reads_paths():
    paths = ["tests/fixtures/run_" + FAKE_8 + "/a.txt", "tests/" + FAKE_16 + ".json", "tests/test_ed25519_material.py",
             "tests/fixtures/verify_receipt_" + "r4/verify_receipt.py"]
    assert _commit_ids_in_paths(paths) == ["tests/fixtures/run_" + FAKE_8 + "/a.txt: " + FAKE_8,
                                           "tests/" + FAKE_16 + ".json: " + FAKE_16]


def test_no_tracked_path_names_a_private_commit():
    hits = _commit_ids_in_paths(_tracked_files())
    assert hits == [], "commit ids in file or folder names: %s" % hits


def test_the_commit_check_reads_code_data_and_prose():
    names = {name for name, _ in _commit_scanned()}
    for name in ["requisition_aws/gate.py", "bin/verify_chain.py", "demo/rehearse.sh", "tests/vectors/intake/intake.json",
                 "README.md"]:
        assert name in names, name


def test_the_public_commit_list_is_used():
    used = {m.group(0)[:8] for name, text in _tracked_texts() for m in COMMIT_ID.finditer(text)}
    assert sorted(set(PUBLIC_COMMITS) - used) == []


def test_the_canonical_v4_test_files_name_no_scratch_folder():
    named = {}
    for name in FILES:
        path = HERE / name
        if path.exists() and PRIVATE_FOLDER.search(path.read_text()):
            named[name] = ["a scratch folder"]
    assert named == {}, "scratch folder named: %s" % named
