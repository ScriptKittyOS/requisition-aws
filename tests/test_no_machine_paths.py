# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""No tracked file names a home directory, one of the project's private working folders, or the project's internal
workflow (who runs what, review and finding ids, lane and plan names, internal gap and
requirement ids), and the canonical v4 test files name no scratch folder. A path that exists on one machine passes
there and fails, or reads something else, everywhere else; a pointer into a private folder or an internal process
means nothing to a reader of this repository.

This repository stands alone: no tracked file names the source tree of the issuing server (its application name, one
of its Elixir source files, one of its functions written as Module.function/arity, a path under one of its folders,
or one of its own commands), or a secret-shaped string that is not a listed synthetic value. A comment says what the
server does; a reader of this repository cannot open the server's files. A check of build-machine names runs before
publication, outside this repository.

Every pattern below is split into pieces, so that this file does not match itself. The names it refuses that are
themselves private are held only as SHA-256 digests, so that this file does not spell them."""

import hashlib
import pathlib
import re
import subprocess
import unicodedata

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
FILES = ["test_canonical.py", "test_canonical_v4.py", "canonical_v4_verifier_runner.py"]
# a home directory in any of its forms: the absolute path; a tilde and a slash where a word starts, with or without a
# user name between them (one letter between them is an Elixir sigil, and is kept); the HOME variable
HOME_PATH = re.compile(r"/ho" + r"me/|/Users/[A-Za-z0-9_.-]+|(?<![A-Za-z0-9_~])~(?:[A-Za-z0-9_.-]{2,})?" + r"/"
                       r"|\$\{?HO" + r"ME\b")
# a working folder, dated or not, or the project folder holding them
PRIVATE_FOLDER = re.compile(r"\.scratch" + r"-|project" + r"-sanction")
# the workflow wording; an internal lane label is "lane" and a digit, in any case, with or without a space, "_" or
# "-" between them and no letter before it, in prose or inside an identifier (a test name, a flag, a variable)
WORKFLOW = re.compile("|".join([
    r"coordi" + r"nator", r"owner's" + r" go", r"owner" + r"-run", r"delta[- ]" + r"review", r"build" + r" review",
    r"review" + r"-r[0-9]", r"fix" + r" round", r"(?i:(?<![a-z])la" + r"ne[ _-]?[0-9])", r"PLAN" + r"\.md",
    r"HAND" + r"BACK", r"OWNER" + r"-GOS", r"RULES" + r"\.md", r"\bW1" + r"-[0-9]", r"GAP" + r"-[A-Z]+-[0-9]",
    # a reference number of the project: one of its letter prefixes, a hyphen, digits
    r"\bREQ" + r"-[0-9]+", r"\bPLAT" + r"-[0-9]+", r"\bSCR" + r"-[0-9]+", r"\bG" + r"-[0-9]+", r"\bD" + r"-[0-9]+",
    # as requisition-ts's census: the earlier name of that package
    r"(?<![A-Za-z])[Rr][Ss]" + r"[Dd][Kk](?![A-Za-z])", r"R-" + r"SDK",
    # how the project speaks of merging a change and of a group of changes
    r"(?i:\blan" + r"d(?:ing|ed)\b)", r"(?i:\bser" + r"ies\b)",
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
# the label Requisition signed into every lab record (its "hands" member) until 2026-11-19, a quoted value inside
# signed bytes: the real lab records carry it in their signed_payload. Requisition and the fake now sign the same
# label without the suffix, which needs no entry here
SIGNED_LABELS = ["one-person (G" + "-301)"]
# The label is not read only where it is quoted whole, as the signed value is: the label and nothing else between two
# double quotation marks (inside a record's signed bytes each mark has a backslash before it) or two backticks.
# Anywhere else its reference number is reported like any other: in prose, or quoted with other words.
SIGNED_LABEL_QUOTED = re.compile("|".join('(?<=")%s(?=\\\\?")|(?<=`)%s(?=`)' % (re.escape(label), re.escape(label))
                                          for label in SIGNED_LABELS))


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


def _tracked_lines_matching(pattern, exempt=lambda name: False, drop=None):
    hits = []
    for name, text in _tracked_texts():
        if exempt(name):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if drop is not None:
                line = drop.sub("", line)
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
    hits = _tracked_lines_matching(WORKFLOW, exempt=_workflow_exempt, drop=SIGNED_LABEL_QUOTED)
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
    for line in ["at commit `" + FAKE_8 + "`", "requisition " + FAKE_40 + " here", "# router:121 at " + FAKE_8,
                 "(as at " + FAKE_7 + ")", "# from requisition-" + FAKE_8, "the code at " + FAKE_16]:
        assert _commit_ids_in("planted.py", line), line
    for line in ["planes 2", "the lanes", "plane3", "a sha256 " + FAKE_SHA256, "tests/fixtures/verify_receipt_" + "r4/",
                 "abcdefab", "12345678", "base64 +" + FAKE_8 + "+x", "account:" + "8979b" + "ed4-1111-2222-3333-44445555aaaa",
                 '"mcp-session-' + FAKE_8 + '"', '"nonce": "' + FAKE_16 + '"',
                 "created at " + "8979b" + "ed4-1111-2222-3333-44445555aaaa"]:
        assert not (WORKFLOW.search(line) or _commit_ids_in("planted.py", line)), line


def test_the_commit_check_refuses_a_private_commit_and_keeps_the_named_values():
    text = ("tested at `" + FAKE_8 + "`\n"
            "    x = 1  # router:121 at " + FAKE_7 + "\n"
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


# --- this repository stands alone ---------------------------------------------------------------------------------
# The issuing server's source tree is private. Three ways of naming it are refused, in every tracked text file:
#   - its application name, in either spelling;
#   - an Elixir source file (a name ending in .ex or .exs) that is neither a tracked file of this repository nor a
#     file of a public release (PUBLIC_ELIXIR_FILES);
#   - an Elixir function written as Module.function/arity.
PRIVATE_APP = re.compile(r"autonomous" + r"_agency|Autonomous" + r"Agency")
ELIXIR_FILE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_]+\.e" + r"xs?(?![A-Za-z0-9_])")
ELIXIR_FUNCTION = re.compile(r"(?<![A-Za-z0-9_.])[A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)*\.[a-z_][a-z0-9_]*[!?]?/[0-9]"
                             r"(?![0-9A-Za-z])")
PUBLIC_ELIXIR_FILES = {
    "verify_receipt" + ".exs": "the Elixir receipt verifier of the public receipt-verification release",
    "verify_receipt_checkpoint" + ".exs": "its checkpoint module, in the same release",
}
# Byte copies of Requisition's files, pinned by sha256 and never edited here: each follows Requisition's file, so its
# wording is corrected there and arrives with the next refresh. An entry whose file no longer names the private tree
# FAILS (test_the_private_tree_exemptions_are_exact), so an entry cannot outlive its reason.
PRIVATE_TREE_EXEMPT = {
    "tests/fixtures/requisition/bin/lab-verify": "a byte copy of Requisition's file (its PROVENANCE.md lists the sha256)",
    "tests/vectors/key_rule_vectors.v1.json": "a byte copy of Requisition's vector file (tests/test_key_rule.py pins "
                                              "the sha256)",
}
# A secret-shaped string: the shapes a secret scanner stops a push for. The synthetic values the tests and the demos
# need are listed by value; any other match fails until it is looked at.
SECRET_SHAPE = re.compile(r"sk_li" + r"ve_[0-9A-Za-z]{8,}|(?<![0-9A-Z])A[KS]" + r"IA[0-9A-Z]{16}(?![0-9A-Z])|"
                          r"gh[pousr]" + r"_[0-9A-Za-z]{20,}|xo" + r"x[abprs]-[0-9A-Za-z-]{8,}")
SYNTHETIC_SECRETS = {
    "AKIA" + "FIXTURENOTREAL01": "the access key id of the recorded interceptor requests (tests/fixtures/interceptor/)",
    "AKIA" + "FIXTURENOTREAL0C": "tests/test_stateless_interceptor.py",
    "ASIA" + "FIXTURENOTREAL0A": "tests/test_stateless_interceptor.py, tests/test_catalog_binding.py",
    "ASIA" + "FIXTURENOTREAL0B": "tests/test_stateless_interceptor.py",
    "ASIA" + "FIXTURENOTREAL0R": "tests/test_stateless_interceptor.py",
    "AKIA" + "PLACEHOLDERLOCAL": "demo/run_interceptor_local.py, a placeholder signature",
    "AKIA" + "ABCDEFGHIJKLMNOP": "tests/test_demo_scripts.py, a value the transcript must redact",
}
# the redactor's differential cases are 4,010 strings built from secret-shaped words, by design
SECRET_SHAPE_EXEMPT = {"tests/fixtures/elixir_differential/redact_cases.json": "the redactor's test strings"}


# A reference to the source tree of the issuing server: a path under one of that tree's top folders, or one of the
# server's own commands. Every run of path characters that holds a "/" is read, whatever it starts with: a folder
# name, "./", "../", "/", a tilde, a variable, the name of a repository. Leading "./" and "../" are dropped. The
# reference is the run from its first piece that is one of SERVER_FOLDERS and has a piece after it. It is kept only
# when
#   - the whole run is a path of this repository (whole, or a part of one: the byte copy of Requisition's lab record
#     checker gives the two-piece end of its own path), or is listed in KEPT_PATHS; or
#   - the reference is such a path or is listed, and no piece before it is the name of the server's repository.
# Anything else is refused, so a path that only starts like one of those folders (a system folder, a method name of a
# protocol, a file of the other public repository) is listed below with what it is. The byte copies
# PRIVATE_TREE_EXEMPT lists are not read.
SERVER_FOLDERS = {".github", "artifacts", "assets", "bench", "bin", "config", "docs", "lab", "lib", "ops", "priv",
                  "rel", "scripts", "test", "toolchain", "tools", "vectors"}
# The names of the server's repository: its public name, and the private name of its repository held as the SHA-256
# of the name as _normalised_name writes it.
SERVER_REPOSITORIES = {"requisition"}
SERVER_REPOSITORY_DIGESTS = {"c258b0e237e78f7e3f74835b8b7a7282bff76a2dc183470d242af0bc82866fb0"}
# The one top folder of that tree whose name holds a space, so no run of path characters can hold it: (the SHA-256 of
# its name as _normalised_name writes it, the length of that name). A line names it when, read as _normalised_name
# reads it, the characters of that length right before a "/" or a "\" have that digest.
SPACED_FOLDER_DIGESTS = {("aa0bdb8356181453d274be58d85995a0354a00d9772404af6dd9cb32d48d4ebd", 14)}
# every run of spaces, underscores, hyphens and dashes, a "%20" and a backslash before a space
NAME_SEPARATORS = re.compile(r"(?:\\ |%20|[\s_\u2010-\u2015-])+")
PATH_RUN = re.compile(r"[A-Za-z0-9_.~$@+{}<>/-]+")
SERVER_COMMAND = re.compile(r"\bmi" + r"x requisition\.[a-z_.]+")
KEPT_PATHS = {
    "tes" + "t/vecto" + "rs/python/ed25519.json": "a file of the public requisition-ts repository (tests/test_input_rules.py)",
    "tes" + "t/vecto" + "rs/python/intake.json": "a file of the public requisition-ts repository (tests/vectors/intake/)",
    "too" + "ls/gen_python_vectors.py": "the program of the public requisition-ts repository that writes the intake "
                                       "vectors (tests/vectors/intake/)",
    "/usr/bi" + "n/env": "the system's env, in the first line of a program",
    "/bi" + "n/sh": "the system's shell (tests/test_verify_chain.py)",
    ".venv/bi" + "n/pip": "this repository's own virtual environment (README.md)",
    "<requisition-aws>/.venv/bi" + "n/python": "the same, as a demo's usage line writes it",
    ".asdf/installs/erlang/28.5.0.8-openssl-3.5.9/bi" + "n/escript": "an Erlang install, by its version (the test that "
                                                                    "reads it is skipped where it is absent)",
    "too" + "ls/call": "a method name of the Model Context Protocol",
    "too" + "ls/list": "a method name of the Model Context Protocol",
    "too" + "ls/call2": "a method name no server has, in a test (tests/test_stateless_interceptor.py)",
}


def _normalised_name(text):
    """``text`` as the private names are compared: NFKC, lower case, and every run of NAME_SEPARATORS one "-"."""
    return NAME_SEPARATORS.sub("-", unicodedata.normalize("NFKC", text).lower())


def _name_digest(name):
    return hashlib.sha256(_normalised_name(name).encode("utf-8")).hexdigest()


def _server_repository(piece, repositories):
    """Whether one piece of a path is the name of the server's repository."""
    return _normalised_name(piece) in SERVER_REPOSITORIES or _name_digest(piece) in repositories


def _spaced_folder_hit(digest):
    return "a folder of the server's tree, by its digest " + digest[:12]


def _spaced_folders_in(line, folders):
    """The digest of every listed folder ``line`` names, once for each place it names it."""
    normal = _normalised_name(line)
    return [digest for slash in re.finditer(r"[/\\]", normal) for digest, length in sorted(folders)
            if slash.start() >= length
            and hashlib.sha256(normal[slash.start() - length:slash.start()].encode("utf-8")).hexdigest() == digest]


def _own_paths():
    """Every tracked path, every folder, and every end of one ("a/b/c" gives a/b/c, b/c, c, a/b, b, a)."""
    own = set()
    for name in _tracked_files():
        parts = name.split("/")
        own.update("/".join(parts[i:j]) for i in range(len(parts)) for j in range(i + 1, len(parts) + 1))
    return own


def _server_paths_in(line, own, kept, repositories=None):
    """[(what is refused or None, the listed path that kept it or None)] for every reference in one line."""
    repositories = SERVER_REPOSITORY_DIGESTS if repositories is None else repositories
    found = []
    for match in PATH_RUN.finditer(line):
        if "/" not in match.group(0):
            continue
        pieces = match.group(0).rstrip("./-").split("/")
        while pieces and pieces[0] in (".", ".."):
            pieces = pieces[1:]
        start = next((i for i in range(len(pieces) - 1) if pieces[i] in SERVER_FOLDERS and pieces[i + 1]), None)
        if start is None:
            continue
        whole, reference = "/".join(pieces), "/".join(pieces[start:])
        named = any(_server_repository(piece, repositories) for piece in pieces[:start])
        if whole in own:
            continue
        if whole in kept:
            found.append((None, whole))
        elif not named and reference in own:
            continue
        elif not named and reference in kept:
            found.append((None, reference))
        else:
            found.append((whole if named else reference, None))
    return found


def _server_tree_in(name, text, own=frozenset(), kept=None, repositories=None, folders=None):
    """Every path or command of the server's tree in ``text``, as "name:line: what". The digest tables are the
    check's own unless others are given."""
    kept = KEPT_PATHS if kept is None else kept
    folders = SPACED_FOLDER_DIGESTS if folders is None else folders
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        hits.extend("%s:%d: %s" % (name, number, what) for what, _ in _server_paths_in(line, own, kept, repositories)
                    if what)
        hits.extend("%s:%d: %s" % (name, number, _spaced_folder_hit(digest)) for digest in _spaced_folders_in(line, folders))
        hits.extend("%s:%d: %s" % (name, number, match.group(0)) for match in SERVER_COMMAND.finditer(line))
    return hits


def test_no_tracked_file_names_a_path_or_a_command_of_the_server_tree():
    own = _own_paths()
    hits = [hit for name, text in _tracked_texts() if name not in PRIVATE_TREE_EXEMPT
            for hit in _server_tree_in(name, text, own)]
    assert hits == [], ("tracked files naming a path or a command of the issuing server's source tree (say what the "
                        "file or the command is for): %s" % hits)


def test_the_kept_paths_are_used_and_are_not_paths_of_this_repository():
    own = _own_paths()
    used = {listed for name, text in _tracked_texts() if name not in PRIVATE_TREE_EXEMPT for line in text.splitlines()
            for _, listed in _server_paths_in(line, own, KEPT_PATHS) if listed}
    assert sorted(set(KEPT_PATHS) - used) == [], "listed paths that no file names"
    assert sorted(set(KEPT_PATHS) & own) == [], "listed paths that are paths of this repository"


def test_the_server_tree_check_finds_a_planted_line_of_each_kind():
    own = {"bi" + "n/mine.py", "mine.py", "bi" + "n", "kept/bi" + "n/copy", "bi" + "n/copy"}
    planted = [("run bi" + "n/scratch-db first", "bi" + "n/scratch-db"),
               ("registered from `la" + "b/seed/demo.v1.json`.", "la" + "b/seed/demo.v1.json"),
               ("reads $DIR/req/la" + "b/seed/demo.v1.json", "la" + "b/seed/demo.v1.json"),
               ("# as li" + "b/server/rule does", "li" + "b/server/rule"),
               ("(pri" + "v/repo/migrations)", "pri" + "v/repo/migrations"),
               ("see confi" + "g/runtime", "confi" + "g/runtime"),
               ("its tes" + "t/support/fixtures/x folder", "tes" + "t/support/fixtures/x"),
               ("run `mi" + "x requisition.lab.seed --set x`", "mi" + "x requisition.lab.seed"),
               # every form of a reference: after "./", "../", "/", a folder, a variable, the repository's
               # name, a tilde; and every top folder of that tree
               ("run ./bi" + "n/scratch-db --keep first", "bi" + "n/scratch-db"),
               ("run ../bi" + "n/scratch-db first", "bi" + "n/scratch-db"),
               ("run requisition/bi" + "n/scratch-db first", "requisition/bi" + "n/scratch-db"),
               ("see ~" + "/requisition/bi" + "n/gate", "~" + "/requisition/bi" + "n/gate"),
               ("see $HO" + "ME/work/bi" + "n/gate", "bi" + "n/gate"),
               ("[the page](/do" + "cs/internal/page.md)", "do" + "cs/internal/page.md"),
               ("$CHECKOUT/op" + "s/runbook.md", "op" + "s/runbook.md"),
               ("the copy of another checkout: requisition/bi" + "n/copy", "requisition/bi" + "n/copy"),
               ("#!/usr/bi" + "n/env python3", "bi" + "n/env"), (".venv/bi" + "n/pip install", "bi" + "n/pip"),
               ("/usr/li" + "b/python3", "li" + "b/python3"), ("$PREFIX/li" + "b/libx.a", "li" + "b/libx.a")]
    # every top folder of that tree, written out here: a folder taken out of SERVER_FOLDERS, or put into it, fails
    folders = [".git" + "hub", "artifa" + "cts", "asse" + "ts", "ben" + "ch", "bi" + "n", "confi" + "g", "do" + "cs", "la" + "b",
               "li" + "b", "op" + "s", "pri" + "v", "re" + "l", "script" + "s", "tes" + "t", "toolcha" + "in", "too" + "ls", "vecto" + "rs"]
    assert sorted(folders) == sorted(SERVER_FOLDERS)
    for folder in folders:
        planted.append(("see " + folder + "/" + "internal/x.md", folder + "/" + "internal/x.md"))
    for line, what in planted:
        assert _server_tree_in("planted.md", line, own, {}) == ["planted.md:1: " + what], line
    for line in ["run bi" + "n/mine.py", "run ./bi" + "n/mine.py", "the copy bi" + "n/copy", "the copy /path/to/bi" + "n/copy",
                 "requisition-la" + "b:account:x", "the la" + "b / dev profile", "POST /v1/la" + "b-keys", "mi" + "x test",
                 "a mi" + "x of requisition records", "tests/test_x.py", "the bi" + "n/ folder", "a do" + "cs/ folder, and li" + "b/",
                 'params._meta["requisition/session"]', "application/json", "a/b ratio 1/2"]:
        assert _server_tree_in("planted.md", line, own, {}) == [], line
    listed = {"tes" + "t/vecto" + "rs/x.json": "public", "/usr/bi" + "n/env": "the system's"}
    for line in ["see tes" + "t/vecto" + "rs/x.json", "see /path/to/tes" + "t/vecto" + "rs/x.json", "#!/usr/bi" + "n/env python3"]:
        assert _server_tree_in("planted.md", line, own, listed) == [], line
    assert _server_tree_in("planted.md", "see requisition/tes" + "t/vecto" + "rs/x.json", own, listed) == \
        ["planted.md:1: requisition/tes" + "t/vecto" + "rs/x.json"]
    assert _server_tree_in("planted.md", "x/usr/bi" + "n/env", own, listed) == ["planted.md:1: bi" + "n/env"]


def _example_tables():
    """Two made-up names, a repository and a folder whose name holds a space, and the digest tables that list them."""
    repository, folder = "Example-Repository", "Example Folder"
    return repository, folder, {_name_digest(repository)}, {(_name_digest(folder), len(_normalised_name(folder)))}


def test_the_private_names_are_held_as_digests():
    for digest in SERVER_REPOSITORY_DIGESTS | {digest for digest, _ in SPACED_FOLDER_DIGESTS}:
        assert re.fullmatch(r"[0-9a-f]{64}", digest), digest
    assert SERVER_REPOSITORY_DIGESTS and SPACED_FOLDER_DIGESTS
    assert all(length > 0 for _, length in SPACED_FOLDER_DIGESTS)
    # the form the digests are taken of: each separator run is one hyphen, in lower case, after NFKC
    assert _normalised_name("Ex\uff41mple \u00a0_Name%20x\\ y\u2011-z") == "example-name-x-y-z"


def test_the_private_names_are_found_by_their_digests_in_every_form():
    # The check is given the digest tables of two made-up names in place of its own, and every generated form of each
    # name is found; the check's own tables find none of them, so a form is found by the table, not by a spelling.
    repository, folder, repositories, folders = _example_tables()
    (digest, _), = folders
    own = {"bi" + "n/mine.py", "mine.py", "bi" + "n"}
    cases = lambda name: sorted({name, name.lower(), name.upper(), name.swapcase()})
    for spelled in cases(folder):
        for space in [" ", "  ", "_", "-", "%20", "\\ ", " ", "‑", " - "]:
            for before in ["", "in ", "x", "/", "./", "~" + "/", "a/b/", "`", "(", '"']:
                for after in ["/", "/notes.md", "\\", "\\notes.md"]:
                    line = before + spelled.replace(" ", space) + after
                    assert _server_tree_in("planted.md", line, own, {}, repositories, folders) == \
                        ["planted.md:1: " + _spaced_folder_hit(digest)], line
                    assert _server_tree_in("planted.md", line, own, {}) == [], line
    for line in ["Example Folders/", "an Example Folder here", "Example Folder.md", "Example/Folder/", "ExampleFolder/",
                 "Example Folder", "an Example Folderx/", "Example Folder |"]:
        assert _server_tree_in("planted.md", line, own, {}, repositories, folders) == [], line
    # the name in full-width letters is read as NFKC reads it
    wide = "".join(chr(ord(c) + 0xFEE0) if c != " " else c for c in folder) + "/"
    assert _server_tree_in("planted.md", wide, own, {}, repositories, folders) == \
        ["planted.md:1: " + _spaced_folder_hit(digest)], wide
    for spelled in cases(repository):
        for dash in ["-", "_", "--", "-_"]:
            for before in ["", "./", "../", "/", "~" + "/", "$HO" + "ME/", "work/", "see ", "`", "("]:
                for top in sorted(SERVER_FOLDERS):
                    for tail in ["x", "x/y.md", "mine.py"]:
                        name = spelled.replace("-", dash)
                        line = before + name + "/" + top + "/" + tail
                        lead = before if "/" in before and not before.startswith(".") else ""
                        assert _server_tree_in("planted.md", line, own, {}, repositories, folders) == \
                            ["planted.md:1: " + lead + name + "/" + top + "/" + tail], line
                        reference = top + "/" + tail
                        assert _server_tree_in("planted.md", line, own, {}) == \
                            ([] if reference in own else ["planted.md:1: " + reference]), line
    for line in ["Example-Repository-Two/bi" + "n/x", "an-Example-Repository/bi" + "n/x", "ExampleRepository/bi" + "n/x"]:
        assert _server_tree_in("planted.md", line, own, {}, repositories, folders) == ["planted.md:1: bi" + "n/x"], line


def _own_file_names():
    return {name.rsplit("/", 1)[-1] for name in _tracked_files()}


def _private_tree_in(name, text, own=frozenset()):
    """Every line of ``text`` that names the private tree, as "name:line: kind"."""
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        kinds = []
        if PRIVATE_APP.search(line):
            kinds.append("application name")
        if any(m.group(0) not in own and m.group(0) not in PUBLIC_ELIXIR_FILES for m in ELIXIR_FILE.finditer(line)):
            kinds.append("Elixir source file")
        if ELIXIR_FUNCTION.search(line):
            kinds.append("Elixir function")
        hits.extend("%s:%d: %s" % (name, number, kind) for kind in kinds)
    return hits


def _secret_shapes_in(name, text):
    return ["%s: %s..." % (name, m.group(0)[:9]) for m in SECRET_SHAPE.finditer(text)
            if m.group(0) not in SYNTHETIC_SECRETS]


def test_no_tracked_file_names_the_private_tree():
    own = _own_file_names()
    hits = [hit for name, text in _tracked_texts() if name not in PRIVATE_TREE_EXEMPT
            for hit in _private_tree_in(name, text, own)]
    assert hits == [], "tracked files naming the issuing server's source tree (say what the server does): %s" % hits


def test_the_private_tree_exemptions_are_exact():
    own, texts = _own_file_names(), dict(_tracked_texts())
    for name in PRIVATE_TREE_EXEMPT:
        assert name in texts, "%s is exempt and is not a tracked text file" % name
        assert _private_tree_in(name, texts[name], own), "%s is exempt and names nothing: drop its entry" % name


def test_no_tracked_file_holds_a_secret_shaped_string():
    texts = [(name, text) for name, text in _tracked_texts() if name not in SECRET_SHAPE_EXEMPT]
    hits = [hit for name, text in texts for hit in _secret_shapes_in(name, text)]
    assert hits == [], "secret-shaped strings (list a synthetic value in SYNTHETIC_SECRETS, with where it is used): %s" % hits
    used = {m.group(0) for _, text in texts for m in SECRET_SHAPE.finditer(text)}
    assert sorted(set(SYNTHETIC_SECRETS) - used) == [], "listed synthetic values that no file holds"
    for name in SECRET_SHAPE_EXEMPT:
        assert SECRET_SHAPE.search(dict(_tracked_texts())[name]), "%s is exempt and holds no such string" % name


def test_the_stand_alone_checks_find_a_planted_line_of_each_kind():
    app, source, function = "autonomous" + "_agency", "lab_key_rule" + ".ex", "LabKeyRule" + ".standing/3"
    for line, kind in [("lib/" + app + "/authority/x", "application name"), ("alias Autonomous" + "Agency.Repo", "application name"),
                       ("# " + source + ":12-14", "Elixir source file"), ("see deps/jason/li" + "b/encode" + ".ex", "Elixir source file"),
                       ("run diff" + ".exs here", "Elixir source file"), ("as " + function + " does", "Elixir function"),
                       ("``Security.Redaction.redact" + "_text/1``", "Elixir function")]:
        assert _private_tree_in("planted.py", line) == ["planted.py:1: " + kind], line
    for line in ["the public verify_receipt" + ".exs", "an example", "index.exe", "Math.floor(n / 2)", "a/b ratio 1/2",
                 "requisition_aws.keys.KeyRegistry", "POST /v1/execute", "RFC 8785 3.2.3"]:
        assert _private_tree_in("planted.py", line) == [], line
    assert _private_tree_in("planted.py", "kept: mine" + ".exs", own={"mine" + ".exs"}) == []
    for value in ["sk_li" + "ve_" + "a1B2c3D4e5", "AK" + "IA" + "Q" * 16, "gh" + "p_" + "a" * 36, "xo" + "xb-" + "1234-abcd"]:
        assert _secret_shapes_in("planted.txt", "key = " + value), value
    for value in ["AK" + "IA" + "Q" * 15, "task_live_x", next(iter(SYNTHETIC_SECRETS))]:
        assert _secret_shapes_in("planted.txt", "key = " + value) == [], value
    for line in ["/ho" + "me/someone/x", "/ho" + "me/$USER", "see ~" + "/requisition/x", "cd ~" + "/", "in ~someone" + "/work",
                 "$HO" + "ME/work", "${HO" + "ME}/work", '"$HO' + 'ME"']:
        assert HOME_PATH.search(line), line
    for line in ["~r" + "/[0-9]+/", "~s" + "/a/", "a ~ b / c", "x~" + "/y", "$HOMEBREW_PREFIX", "at home"]:
        assert not HOME_PATH.search(line), line
    for line in ["after this lan" + "ding", "Lan" + "ded on main", "the fix ser" + "ies", "see G" + "-301 for the rule",
                 "G" + "-7", "SC" + "R-1500", "PL" + "AT-083", "decision D" + "-29", "RE" + "Q-171"]:
        assert WORKFLOW.search(line), line
    for line in ["the island", "a serious error", "outlanding", "ML-DSA-87", "RFC-8785", "SHA-256", "ID-1", "MD-5"]:
        assert not WORKFLOW.search(line), line
    # the signed label: kept where it is quoted whole, reported in prose and when quoted with anything else
    label = SIGNED_LABELS[0]
    for line in ['{"hands": "' + label + '"}', '\\"hands\\":\\"' + label + '\\",\\"k\\":1', "signed as `" + label + "`"]:
        assert not WORKFLOW.search(SIGNED_LABEL_QUOTED.sub("", line)), line
    for line in ["the label " + label + " means one operator", '"' + label + " per SC" + 'R-1513"', "`" + label + " and more`",
                 '"hands: ' + label + '"', "'" + label + "'", '"' + label + '" as SC' + "R-1513 says",
                 '"' + label + ' means one operator"', "see " + label + '" here', '"the label ' + label + '"',
                 "see " + label + "` here"]:
        assert WORKFLOW.search(SIGNED_LABEL_QUOTED.sub("", line)), line
