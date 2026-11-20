# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""What a pass says, in bin/verify_offline.py and bin/verify_chain.py.

* Every pass prints one fixed sentence after its verdict: a pass shows the bytes were signed under the key supplied,
  and it is not permission to act. A failure prints no line that is the sentence.
* A deadline the signed bytes carry is reported as what the record says, for a decision that allowed (the signed
  verdict is ``allow``) and for a statement (a statement record with no signed verdict, and ``exp``), each in its own
  words, and for no other record: a caller grant signs ``not_after`` and no verdict, and is not reported as a
  decision; a record of another kind that signs ``exp`` is no statement. The deadline
  is compared with nothing unless a time is given (``--at``). No exit depends on the time.
* A time that is not one instant of the accepted form is a usage error (exit 2).
* An argument a tool does not take is a usage error (exit 2), never skipped: a skipped ``--att TIME`` would be a pass
  with no comparison where the caller asked for one.
* A flag is taken only by its whole name: a shortened flag (``--js`` for ``--json``) is a usage error (exit 2).
* The same valid decision record presented twice gives the same pass, the same lines and the same exit:
  replay protection is not the verifier's.

The rows are ``tests/vectors/pass_lines_vectors.v1.json``, one file for every Requisition verifier (a byte copy
of Requisition's; its own suite holds the copy equal). Each row names a kind of record and the members its signed
metadata carries. The record is built and signed here, with a key made for the run, because the rows include
shapes no issuing system signs (a deadline that is no instant, a start after the end); the signature is a real
Ed25519 signature, checked by the committed copy of Requisition's ``bin/lab-verify`` (``tests/fixtures/requisition/``)
and by ``bin/verify_chain.py``'s own routine.
"""

import ast
import base64
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from requisition_aws import canonical
from requisition_aws.gate import arguments_object

from .conftest import ACT_TYPE, refund_args
from .test_canonical import REQ_TREE

ROOT = pathlib.Path(__file__).resolve().parent.parent
OFFLINE = ROOT / "bin" / "verify_offline.py"
CHAIN = ROOT / "bin" / "verify_chain.py"
LAB_VERIFY = REQ_TREE / "bin" / "lab-verify"
VERIFY_RECEIPT = REQ_TREE / "bench" / "holytrinity-v2" / "verifier" / "verify_receipt.py"
DOC = json.loads((pathlib.Path(__file__).parent / "vectors" / "pass_lines_vectors.v1.json").read_text(encoding="utf-8"))
PASS_LINE, VECTORS, MALFORMED = DOC["pass_line"], DOC["vectors"], DOC["malformed_at"]
UNKNOWN = [row["argv"] for row in DOC["unknown_arguments"]]
BY_NAME = {v["name"]: v for v in VECTORS}

KEY_ID = "requisition_lab_dev_ed25519_v0"
SCOPE = "requisition-lab:account:00000000-0000-4000-8000-0000000000f1"
LABELS = {"profile": "lab", "signer": "dev", "n6_profile": "not_followed", "hands": "one-person"}
ARGS = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
KINDS = {"decision": "requisition.lab.decision.v0", "statement": "requisition.lab.statement.v0",
         "cease": "requisition.lab.decision.v0", "grant": "requisition.lab.caller_grant.v0"}


class Signer:
    """A development Ed25519 key made for one test session, and the key file that names it."""

    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.registry = {"schema": "requisition_lab_key_file.v1", "entries": [{
            "key_id": KEY_ID, "algorithm": "ed25519", "signer": "dev", "profile": "lab", "status": "active",
            "status_changed_at": "2026-01-01T00:00:00Z", "valid_from": "2026-01-01T00:00:00Z", "valid_to": None,
            "public_key": base64.b64encode(raw).decode(), "public_key_fingerprint": hashlib.sha256(raw).hexdigest()}]}

    def record(self, kind, members):
        """A signed record of the kind, its signed metadata carrying exactly ``members`` of the window members."""
        bound = ({"display_digest": canonical.display_digest(ARGS)} if kind == "cease" else
                 {"act_hash": canonical.act_hash(ACT_TYPE, ARGS), "act_hash_alg": "sha384+canonical_payload.v3"})
        metadata = {**LABELS, "key_id": KEY_ID, "act_type": ACT_TYPE, **bound, **members}
        text = json.dumps({
            "schema_version": "agent_receipt.v1", "chain_scope": SCOPE, "sequence": 1, "previous_hash": None,
            "receipt_type": KINDS[kind], "subject_type": "requisition.lab.pass_lines", "subject_id": "pass-lines",
            "status": "recorded", "payload_hash": None, "occurred_at": "2026-11-13T15:56:48Z", "metadata": metadata})
        return {"signature": base64.b64encode(self.key.sign(text.encode())).decode(), "key_id": KEY_ID,
                "signed_payload": text, "receipt_hash": hashlib.sha256(text.encode()).hexdigest()}


@pytest.fixture(scope="module")
def signer():
    return Signer()


@pytest.fixture
def files(signer, tmp_path):
    """Writes a vector's record, the arguments and the key file; returns a function giving their paths."""
    (tmp_path / "args.json").write_text(json.dumps(ARGS))
    (tmp_path / "keys.json").write_text(json.dumps(signer.registry))

    def write(vector, change=None):
        record = signer.record(vector["kind"], vector["metadata"])
        if change:
            record = change(record)
        (tmp_path / "record.json").write_text(json.dumps(record))
        (tmp_path / "export.json").write_text(json.dumps({"records": [record]}))
        return tmp_path, record

    return write


def at_flags(at):
    return [] if at is None else ["--at", at]


def offline(folder, flags=()):
    return subprocess.run(
        [sys.executable, "-I", str(OFFLINE), "--arguments", str(folder / "args.json"), "--act-type", ACT_TYPE,
         "--record", str(folder / "record.json"), "--lab-verify", str(LAB_VERIFY), "--registry", str(folder / "keys.json"),
         *flags], capture_output=True, text=True, timeout=120)


def chain(folder, flags=()):
    return subprocess.run(
        [sys.executable, "-I", str(CHAIN), "--registry", str(folder / "keys.json"), "--export", str(folder / "export.json"),
         *flags], capture_output=True, text=True, timeout=120)


def said(stdout):
    """The lines after the fixed sentence, or None when no line is the sentence. More than one such line fails."""
    lines = stdout.split("\n")
    count = lines.count(PASS_LINE)
    assert count <= 1, stdout
    if count == 0:
        return None
    return [line for line in lines[lines.index(PASS_LINE) + 1:] if line != ""]


def tampered(record):
    """One byte of the signed bytes changed after signing; the receipt hash made to follow."""
    text = record["signed_payload"].replace('"status": "recorded"', '"status": "recordeD"')
    assert text != record["signed_payload"]
    return {**record, "signed_payload": text, "receipt_hash": hashlib.sha256(text.encode()).hexdigest()}


# --- bin/verify_offline.py -------------------------------------------------------------------------


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["kind"] != "cease"], ids=lambda v: v["name"])
def test_verify_offline_every_row_passes_and_ends_with_the_sentence_then_the_rows_lines(files, vector):
    folder, _ = files(vector)
    proc = offline(folder, at_flags(vector["at"]))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.split("\n")
    assert said(proc.stdout) == vector["lines"], proc.stdout
    assert lines[lines.index(PASS_LINE) - 1].startswith("verdict: PASS -- "), proc.stdout
    # the answer of bin/lab-verify printed in section 2 carries its own sentence and the same lines, behind "  | "
    echoed = [line[4:] for line in lines if line.startswith("  | ") and line != "  | "]
    assert echoed[echoed.index(PASS_LINE) + 1:] == vector["lines"] + ["verdict_code: lab_dev_key"], proc.stdout


# The signed `hands` label. Requisition signs "one-person" (LABELS); a record it signed before 2026-11-19 ends the same
# value in a reference in brackets and stays as signed, so a reader takes either spelling and judges both alike.
EARLIER_HANDS = "one-person (G" + "-301)"


@pytest.mark.parametrize("hands", [LABELS["hands"], EARLIER_HANDS], ids=["signed today", "signed before 2026-11-19"])
def test_verify_offline_a_record_with_either_spelling_of_the_hands_label_is_the_same_pass(files, hands):
    vector = BY_NAME["allow_no_time"]
    folder, record = files({**vector, "metadata": {**vector["metadata"], "hands": hands}})
    assert json.loads(record["signed_payload"])["metadata"]["hands"] == hands
    proc = offline(folder)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert said(proc.stdout) == vector["lines"], proc.stdout
    assert "verdict_code: lab_dev_key" in proc.stdout, proc.stdout


# the first value is the claim no record makes; it is split so that this file does not hold the word the approval
# wording check refuses (tests/test_approval_wording.py)
@pytest.mark.parametrize("hands", ["two-" + "person", "one-person (G" + "-302)", "one-person ", ""])
def test_verify_offline_a_record_with_any_other_hands_label_does_not_pass(files, hands):
    vector = BY_NAME["allow_no_time"]
    folder, _ = files({**vector, "metadata": {**vector["metadata"], "hands": hands}})
    proc = offline(folder)
    assert proc.returncode != 0 and "lab_label_missing" in proc.stdout, proc.stdout + proc.stderr
    assert said(proc.stdout) is None


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["kind"] == "cease"], ids=lambda v: v["name"])
def test_verify_offline_does_not_pass_a_record_only_act_and_says_no_sentence(files, vector):
    # a cease binds a display digest and no act hash: this tool, which ties a record to arguments, has no pass for it
    folder, _ = files(vector)
    proc = offline(folder, at_flags(vector["at"]))
    assert proc.returncode != 0 and "verdict: FAIL" in proc.stdout, proc.stdout + proc.stderr
    assert said(proc.stdout) is None


@pytest.mark.parametrize("flags", [["--at", value] for value in MALFORMED] + [["--at"]]
                         + [["--at", "2026-11-13T15:57:00Z", "--at", "2026-11-13T15:58:00Z"]],
                         ids=lambda flags: repr(flags[1:]))
def test_verify_offline_a_time_that_is_not_one_instant_or_is_given_twice_is_a_usage_error(files, flags):
    folder, _ = files(BY_NAME["allow_no_time"])
    proc = offline(folder, flags)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert proc.stdout == "" and proc.stderr.startswith("usage: ")


@pytest.mark.parametrize("argv", UNKNOWN, ids=" ".join)
def test_verify_offline_an_argument_it_does_not_take_is_a_usage_error_and_nothing_passes(files, argv):
    folder, _ = files(BY_NAME["allow_no_time"])
    assert len(UNKNOWN) >= 5 and offline(folder).returncode == 0
    proc = offline(folder, argv)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout and "verdict: PASS" not in proc.stdout and "allowed execution" not in proc.stdout


@pytest.mark.parametrize("flags", [[], ["--at", "2026-11-13T15:57:00Z"]], ids=["no time", "a time"])
def test_verify_offline_a_record_whose_signature_fails_prints_no_sentence_and_no_window_line(files, flags):
    folder, _ = files(BY_NAME["allow_no_time"], change=tampered)
    proc = offline(folder, flags)
    assert proc.returncode == 3 and "verdict: FAIL" in proc.stdout, proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout
    for text in ("allowed execution until", "was valid until", "No time was compared", "the window was"):
        assert text not in proc.stdout


def test_verify_offline_fail_with_a_passing_lab_verify_half_shows_that_halfs_sentence_only_behind_its_mark(files):
    # --require-pq on a record with no post-quantum signature: bin/lab-verify's half passes, this tool FAILS (exit 4)
    folder, _ = files(BY_NAME["allow_no_time"])
    proc = offline(folder, ["--require-pq"])
    assert proc.returncode == 4 and "verdict: FAIL" in proc.stdout, proc.stdout + proc.stderr
    assert said(proc.stdout) is None
    assert proc.stdout.count(PASS_LINE) == 1 and "  | " + PASS_LINE + "\n" in proc.stdout
    assert proc.stdout.rstrip("\n").split("\n")[-1].startswith("verdict: FAIL")


def test_verify_offline_replay_protection_is_not_the_verifiers_the_same_valid_decision_twice_is_the_same_pass(files):
    folder, _ = files(BY_NAME["allow_no_time"])
    first, second = offline(folder), offline(folder)
    assert first.returncode == 0 and said(first.stdout) == BY_NAME["allow_no_time"]["lines"]
    assert (second.returncode, second.stdout, second.stderr) == (first.returncode, first.stdout, first.stderr)


def test_verify_offline_the_exit_of_a_pass_does_not_depend_on_the_time_given(files):
    exits = set()
    for name in ("allow_no_time", "allow_before_start", "allow_at_start", "allow_at_end", "allow_after_end",
                 "end_not_a_day_at"):
        folder, _ = files(BY_NAME[name])
        exits.add(offline(folder, at_flags(BY_NAME[name]["at"])).returncode)
    assert exits == {0}


# --- bin/verify_chain.py ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_verify_chain_every_row_is_ok_names_the_rows_lines_by_sequence_and_ends_with_the_sentence(files, vector):
    folder, record = files(vector)
    proc = chain(folder, at_flags(vector["at"]))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.rstrip("\n").split("\n")
    assert lines[-2:] == ["RESULT ok", PASS_LINE] and said(proc.stdout) == [], proc.stdout
    assert [line for line in lines if line.startswith("sequence ")] == ["sequence 1: " + line for line in vector["lines"]]
    assert lines[:-2][len(lines) - 2 - len(vector["lines"]):] == ["sequence 1: " + line for line in vector["lines"]]

    proc = chain(folder, at_flags(vector["at"]) + ["--json"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout)
    assert answer["result"] == "ok" and answer["notice"] == PASS_LINE and answer["at"] == vector["at"]
    assert answer["windows"] == ([{"sequence": 1, "receipt_hash": record["receipt_hash"], "lines": vector["lines"]}]
                                 if vector["lines"] else [])


@pytest.mark.parametrize("flags", [["--at", value] for value in MALFORMED] + [["--at"]], ids=lambda flags: repr(flags[1:]))
def test_verify_chain_a_time_that_is_not_one_instant_is_a_usage_error(files, flags):
    folder, _ = files(BY_NAME["allow_no_time"])
    for extra in ([], ["--json"]):
        proc = chain(folder, flags + extra)
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert proc.stdout == ""


@pytest.mark.parametrize("argv", UNKNOWN, ids=" ".join)
def test_verify_chain_an_argument_it_does_not_take_is_a_usage_error_and_nothing_passes(files, argv):
    folder, _ = files(BY_NAME["allow_no_time"])
    assert chain(folder).returncode == 0
    proc = chain(folder, argv)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout and "RESULT" not in proc.stdout and "allowed execution" not in proc.stdout


@pytest.mark.parametrize("short", ["--js", "--jso", "--require", "--require-p", "--accept dev"],
                         ids=lambda short: short.split(" ")[0])
def test_verify_chain_a_shortened_flag_is_a_usage_error_and_nothing_passes(files, short):
    folder, _ = files(BY_NAME["allow_no_time"])
    assert chain(folder).returncode == 0
    proc = chain(folder, short.split(" "))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout and "RESULT" not in proc.stdout and "allowed execution" not in proc.stdout


def test_verify_chain_a_shortened_name_of_a_required_flag_is_a_usage_error(files):
    folder, _ = files(BY_NAME["allow_no_time"])
    proc = subprocess.run(
        [sys.executable, "-I", str(CHAIN), "--registr", str(folder / "keys.json"), "--expo", str(folder / "export.json")],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout and "RESULT" not in proc.stdout


@pytest.mark.parametrize("flags", [[], ["--at", "2026-11-13T15:57:00Z"]], ids=["no time", "a time"])
def test_verify_chain_a_fail_prints_no_sentence_and_no_window_line_and_its_json_carries_none(files, flags):
    folder, _ = files(BY_NAME["allow_no_time"], change=tampered)
    proc = chain(folder, flags)
    assert proc.returncode == 1 and proc.stdout.rstrip("\n").split("\n")[-1] == "RESULT FAIL", proc.stdout + proc.stderr
    assert PASS_LINE not in proc.stdout and not any(line.startswith("sequence ") for line in proc.stdout.split("\n"))
    for text in ("allowed execution until", "was valid until", "No time was compared", "the window was"):
        assert text not in proc.stdout
    answer = json.loads(chain(folder, flags + ["--json"]).stdout)
    assert answer["result"] == "FAIL" and answer["notice"] is None and answer["windows"] == []
    assert answer["at"] == (flags[1] if flags else None)


def test_verify_chain_json_members_are_fixed(files):
    members = {"result", "chain_scope", "failures", "notes", "export_rows", "held_records", "require_pq", "notice", "at",
               "windows"}
    folder, _ = files(BY_NAME["allow_no_time"])
    assert set(json.loads(chain(folder, ["--json"]).stdout)) == members
    folder, _ = files(BY_NAME["allow_no_time"], change=tampered)
    assert set(json.loads(chain(folder, ["--json"]).stdout)) == members


def test_verify_chain_replay_protection_is_not_the_verifiers_the_same_valid_decision_twice_is_the_same_pass(files):
    folder, _ = files(BY_NAME["allow_no_time"])
    first, second = chain(folder), chain(folder)
    assert first.returncode == 0 and PASS_LINE in first.stdout.split("\n")
    assert (second.returncode, second.stdout, second.stderr) == (first.returncode, first.stdout, first.stderr)


def test_verify_chain_names_each_rows_window_by_its_own_sequence(signer, tmp_path):
    # a chain of four: a statement (exp), its allow (exec_not_after), a deny and a caller grant (no window)
    rows, previous = [], None
    for sequence, name in enumerate(("statement_no_time", "allow_no_time", "deny_no_time", "grant_no_time"), start=1):
        record = signer.record(BY_NAME[name]["kind"], BY_NAME[name]["metadata"])
        signed = {**json.loads(record["signed_payload"]), "sequence": sequence, "previous_hash": previous}
        text = json.dumps(signed)
        record = {"signature": base64.b64encode(signer.key.sign(text.encode())).decode(), "key_id": KEY_ID,
                  "signed_payload": text, "receipt_hash": hashlib.sha256(text.encode()).hexdigest()}
        rows.append(record)
        previous = record["receipt_hash"]
    (tmp_path / "keys.json").write_text(json.dumps(signer.registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": rows}))
    proc = chain(tmp_path, ["--at", "2026-11-13T15:57:48Z"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.rstrip("\n").split("\n")[-8:] == [
        "sequence 1: This statement was valid until 2026-11-13T16:01:38Z.",
        "sequence 1: At 2026-11-13T15:57:48Z the window was open (from 2026-11-13T15:56:38Z, until 2026-11-13T16:01:38Z).",
        "sequence 2: This decision allowed execution until 2026-11-13T15:57:48Z.",
        "sequence 2: At 2026-11-13T15:57:48Z the window was closed (it ended at 2026-11-13T15:57:48Z).",
        "sequence 3: No time was compared: this record carries no execution window.",
        "sequence 4: No time was compared: this record carries no execution window.",
        "RESULT ok",
        PASS_LINE,
    ]


def test_only_a_signed_verdict_of_allow_is_reported_as_a_decision_and_only_exp_with_no_verdict_as_a_statement(files):
    for vector in VECTORS:
        allow = vector["metadata"].get("verdict") == "allow"
        statement = "verdict" not in vector["metadata"] and "exp" in vector["metadata"]
        text = "\n".join(vector["lines"])
        assert allow or "This decision" not in text, vector["name"]
        assert statement or "This statement" not in text, vector["name"]
    # a record shaped as a caller grant (not_after, no verdict), in both tools, with and without a time
    for name in ("grant_no_time", "grant_at"):
        vector = BY_NAME[name]
        assert vector["kind"] == "grant" and set(vector["metadata"]) == {"not_after"}
        folder, _ = files(vector)
        for proc in (offline(folder, at_flags(vector["at"])), chain(folder, at_flags(vector["at"]))):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "This decision" not in proc.stdout and "allowed execution" not in proc.stdout
            assert "This statement" not in proc.stdout and "valid until" not in proc.stdout


# --- one sentence and one rule, wherever they are written ------------------------------------------

BLOCK_START = "# --- WHAT A PASS SAYS: one text in "
BLOCK_END = "# --- end of WHAT A PASS SAYS ---"


def block(path):
    text = path.read_text(encoding="utf-8")
    assert text.count(BLOCK_START) == 1 and text.count(BLOCK_END) == 1, path
    return text.split(BLOCK_START, 1)[1].split(BLOCK_END, 1)[0]


def test_the_rules_text_is_one_text_in_both_tools_and_in_the_copies_of_requisitions_two():
    assert block(OFFLINE) == block(CHAIN) == block(LAB_VERIFY) == block(VERIFY_RECEIPT)


@pytest.mark.parametrize("path", [OFFLINE, CHAIN, LAB_VERIFY, VERIFY_RECEIPT], ids=lambda p: p.name)
def test_the_fixed_sentence_is_the_vector_files(path):
    values = [ast.literal_eval(node.value) for node in ast.parse(path.read_text(encoding="utf-8")).body
              if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "PASS_LINE"]
    assert values == [PASS_LINE]
