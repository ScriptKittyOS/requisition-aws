# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""canonical_payload.v4: the package's encoder and the offline verifier's copy.

The differential: every row of the shared vector file (tests/vectors/canonical_v4, a byte copy of requisition's
test/support/fixtures/canonical_v4, both files pinned by SHA-256) gives exactly the row's canonical bytes, or a
refusal with the row's reason, from requisition_aws.canonical.canonicalize_v4 AND from bin/verify_offline.py's
canonicalize_v4. With CANONICAL_V4_RESULTS_DIR set, the answers are written for requisition's bin/canonical-v4-compare
(python.jsonl here, verifier.jsonl by tests/canonical_v4_verifier_runner.py).

The rule tests call encode_v4 directly on Python values, with no reader in front: the integer bound is the
ENCODER's.
"""

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

import pytest

from requisition_aws import canonical

from . import canonical_v4_verifier_runner as verifier_runner

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin" / "verify_offline.py"
FIXTURES = pathlib.Path(os.environ.get("CANONICAL_V4_FIXTURES") or ROOT / "tests" / "vectors" / "canonical_v4")
PINS = {
    "vectors.jsonl": "994c7ead2259b0fbbe5201b29f189e84d25c16bc6f12cc3c3a5a5d5cd4643f98",
    "negative/cases.jsonl": "ef5a499a9ed1e8fe336eee104e49457f9e157c4b760a8f46e1d2948c0964d669",
}
REASONS = {"malformed_json", "invalid_utf8", "duplicate_key", "lone_surrogate", "integer_out_of_range", "float_refused", "too_deep",
           "negative_zero"}
MAX = 2**53 - 1
V3, V4 = "sha384+canonical_payload.v3", "sha384+canonical_payload.v4"


def _module():
    spec = importlib.util.spec_from_file_location("verify_offline_v4", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vo = _module()


def _rows():
    rows = []
    for name in PINS:
        rows += [json.loads(line) for line in (FIXTURES / name).read_bytes().decode("utf-8").splitlines()]
    return rows


def _expected(row):
    if row["expect"] == "bytes":
        return {"id": row["id"], "result": "bytes", "canonical_b64": row["canonical_b64"]}
    return {"id": row["id"], "result": "refuse", "reason": row["reason"]}


def _answer(row):
    try:
        out = canonical.canonicalize_v4(base64.b64decode(row["input_b64"]))
    except canonical.CanonicalRefusal as refusal:
        return {"id": row["id"], "result": "refuse", "reason": refusal.code}
    return {"id": row["id"], "result": "bytes", "canonical_b64": base64.b64encode(out).decode("ascii")}


def _code(fn, *args):
    with pytest.raises((canonical.CanonicalRefusal, vo.Refused)) as caught:
        fn(*args)
    return caught.value.code


# --- the differential -----------------------------------------------------------------------------


def test_the_vector_files_are_the_pinned_bytes():
    for name, pin in PINS.items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == pin, name
    rows = _rows()
    assert len(rows) == 376 and len({r["id"] for r in rows}) == 376
    assert {r["reason"] for r in rows if r["expect"] == "refuse"} == REASONS


def test_the_package_gives_every_row_its_bytes_or_its_refusal():
    rows = _rows()
    answers = [_answer(row) for row in rows]
    results = os.environ.get("CANONICAL_V4_RESULTS_DIR")
    if results:
        os.makedirs(results, exist_ok=True)
        with open(os.path.join(results, "python.jsonl"), "w", encoding="utf-8") as handle:
            for item in answers:
                handle.write(json.dumps(item, sort_keys=True) + "\n")
    wrong = [(got, _expected(row)) for row, got in zip(rows, answers) if got != _expected(row)]
    assert wrong == [] and len(answers) == 376


def test_the_offline_verifier_gives_every_row_its_bytes_or_its_refusal():
    """In process (the pytest half) and as the kit runs it: python3 -I, the standard library alone."""
    rows, wrong = verifier_runner.run(fixtures=str(FIXTURES), results=None)
    assert (rows, wrong) == (376, [])
    env = {k: v for k, v in os.environ.items() if k != "CANONICAL_V4_RESULTS_DIR"}
    env["CANONICAL_V4_FIXTURES"] = str(FIXTURES)
    done = subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "canonical_v4_verifier_runner.py")],
                          capture_output=True, text=True, env=env)
    assert done.returncode == 0 and "each of 376 rows" in done.stdout, done.stdout + done.stderr


def test_the_verifiers_encoder_is_the_packages_on_every_accepted_row_and_every_refusal_code_agrees():
    for row in _rows():
        data = base64.b64decode(row["input_b64"])
        if row["expect"] == "bytes":
            value = json.loads(data)
            assert vo.encode_v4(value) == canonical.encode_v4(value) == base64.b64decode(row["canonical_b64"]), row["id"]
        else:
            assert _code(vo.canonicalize_v4, data) == _code(canonical.canonicalize_v4, data) == row["reason"], row["id"]


def test_every_negative_case_is_one_edit_of_an_accepted_row():
    accepted = {r["id"]: r for r in _rows() if r["expect"] == "bytes"}
    cases = [json.loads(line) for line in (FIXTURES / "negative/cases.jsonl").read_text().splitlines()]
    assert len(cases) == 34 and {c["reason"] for c in cases} == REASONS
    for case in cases:
        base = base64.b64decode(accepted[case["base"]]["input_b64"])
        edit = case["edit"]
        mutated = base[: edit["offset"]] + base64.b64decode(edit["insert_b64"]) + base[edit["offset"] + edit["delete"]:]
        assert mutated == base64.b64decode(case["input_b64"]) and mutated != base, case["id"]
        assert _code(canonical.canonicalize_v4, mutated) == case["reason"], case["id"]


# --- the rules, at the encoder (no reader in front) ------------------------------------------------


@pytest.mark.parametrize("encode", [canonical.encode_v4, vo.encode_v4], ids=["package", "verifier"])
def test_the_integer_bound_is_the_encoders(encode):
    assert encode(MAX) == b"9007199254740991" and encode(-MAX) == b"-9007199254740991"
    for out in (MAX + 1, -(MAX + 1), 2**63, -(2**63), 2**64, 10**30, 10**5000):
        assert _code(encode, out) == "integer_out_of_range"
        assert _code(encode, {"a": [0, {"amount_minor": out}]}) == "integer_out_of_range"
    # how such a value is carried under v4: as a string
    assert encode({"amount": str(2**64)}) == b'{"amount":"18446744073709551616"}'


def test_v3_is_untouched_it_still_writes_what_it_wrote():
    # the package's v3 encoder has no bound (catalog tool digests rely on it) and still has none
    assert canonical.encode(2**64) == b"18446744073709551616"
    assert vo.encode(2**64) == b"18446744073709551616"
    assert canonical.encode({"k": "\x1f"}) == b'{"k":"\\u001F"}' == vo.encode({"k": "\x1f"})
    assert canonical.ACT_HASH_ALG == V3 and vo.LABEL == V3, "the label this package SENDS moved"


@pytest.mark.parametrize("encode", [canonical.encode_v4, vo.encode_v4], ids=["package", "verifier"])
def test_zero_floats_and_literals(encode):
    assert encode(0) == b"0" and encode(-0) == b"0"
    for value in (-0.0, 0.0, 1.0, 1.5, 1e30, float("nan"), float("inf")):
        assert _code(encode, value) == "float_refused"
    assert encode([True, False, None]) == b"[true,false,null]"


@pytest.mark.parametrize("encode", [canonical.encode_v4, vo.encode_v4], ids=["package", "verifier"])
def test_strings_and_key_order(encode):
    short = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}
    for cp in range(0x20):
        assert encode(chr(cp)) == ('"' + short.get(cp, "\\u%04x" % cp) + '"').encode(), hex(cp)
    assert encode('"\\') == b'"\\"\\\\"'
    for raw in ("/", "\x7f", "\x80", "é", " ", "\U0001f600"):
        assert encode(raw) == ('"' + raw + '"').encode("utf-8")
    assert encode("é") != encode("é")  # no normalisation
    # UTF-16 code units: U+10000 (D800 DC00) sorts before U+FF61; by code point it would sort after
    assert encode({"｡": 1, "\U00010000": 2}) == '{"\U00010000":2,"｡":1}'.encode("utf-8")
    assert encode({"b": 1, "a": {"d": 1, "c": 2}, "": 0, "aa": 3}) == b'{"":0,"a":{"c":2,"d":1},"aa":3,"b":1}'
    for lone in ("\ud800", "\udc00", "a\ud83dz"):
        assert _code(encode, lone) == "lone_surrogate"
        assert _code(encode, {lone: 1}) == "lone_surrogate"


@pytest.mark.parametrize("encode", [canonical.encode_v4, vo.encode_v4], ids=["package", "verifier"])
def test_other_values_are_refused_and_depth_is_bounded(encode):
    class Sub(int):
        pass

    class Text(str):
        pass

    for value in ((1, 2), {1, 2}, b"x", bytearray(b"x"), object(), Sub(1), Text("a"), 1 + 2j):
        assert _code(encode, value) == "unencodable", repr(value)
    for key in (1, None, True, (1,), Text("a")):
        assert _code(encode, {key: 1}) == "non_string_key", repr(key)
    nested = []
    for _ in range(63):
        nested = [nested]
    assert encode(nested) == b"[" * 64 + b"]" * 64
    assert _code(encode, [nested]) == "too_deep"
    objects = {}
    for _ in range(64):
        objects = {"a": objects}
    assert _code(encode, objects) == "too_deep"


@pytest.mark.parametrize("canonicalize", [canonical.canonicalize_v4, vo.canonicalize_v4], ids=["package", "verifier"])
def test_the_reader_refuses_what_is_not_strict_json(canonicalize):
    assert canonicalize(b' { "b" : [ 0 , 1 ] , "a" : null } ') == b'{"a":null,"b":[0,1]}'
    assert _code(canonicalize, b'{"a":1,"a":2}') == "duplicate_key"
    assert _code(canonicalize, b'{"a":1,"\\u0061":2}') == "duplicate_key"
    for text in (b"NaN", b"Infinity", b"-Infinity", b"\xef\xbb\xbf1", b"", b"[1,]", b"01", b"'a'"):
        assert _code(canonicalize, text) == "malformed_json", text
    for text in (b"1.0", b"1e2", b"-0.0", b"4.50", b"1e400"):
        assert _code(canonicalize, text) == "float_refused", text
    assert _code(canonicalize, b'"\xff"') == "invalid_utf8"
    assert _code(canonicalize, b'"\\ud800"') == "lone_surrogate"
    assert _code(canonicalize, b"9007199254740992") == "integer_out_of_range"
    assert _code(canonicalize, b"1" * 5000) == "integer_out_of_range"
    assert _code(canonicalize, b"[" * 65 + b"]" * 65) == "too_deep"


@pytest.mark.parametrize("canonicalize", [canonical.canonicalize_v4, vo.canonicalize_v4], ids=["package", "verifier"])
def test_the_reader_refuses_the_integer_lexeme_minus_zero_negative_zero_right_after_float_refused(canonicalize):
    """RFC 8785 erratum 7920 (Verified): a parser SHOULD error on -0. Python's int("-0") is 0, so only the lexeme can tell."""
    for text in (b"-0", b" -0 ", b"[-0]", b"[0,-0]", b'{"a":-0}', b'{"a":[{"b":{"c":[-0]}}]}', b"[1,-1,-0,0]"):
        assert _code(canonicalize, text) == "negative_zero", text
    assert canonicalize(b'{"-0":"-0","a":[0,-1]}') == b'{"-0":"-0","a":[0,-1]}'  # a string -0 and -1 are not -0
    for text in (b"-0.0", b"-0e0", b"-0E+0", b"-0.0e-0"):
        assert _code(canonicalize, text) == "float_refused", text  # not integer lexemes
    assert _code(canonicalize, b"-00") == "malformed_json"
    # the order: ... lone_surrogate, float_refused, negative_zero, integer_out_of_range, whatever the positions
    for text in (b"[-0,1.5]", b"[1.5,-0]"):
        assert _code(canonicalize, text) == "float_refused", text
    for text in (b"[-0,9007199254740992]", b"[9007199254740992,-0]", b"[99999999999999999,-0]", b"[-0," + b"9" * 5000 + b"]"):
        assert _code(canonicalize, text) == "negative_zero", text[:40]
    assert _code(canonicalize, b'[-0,"\\ud800"]') == "lone_surrogate"
    assert _code(canonicalize, b'{"a":-0,"a":1}') == _code(canonicalize, b'{"a":1,"a":-0}') == "duplicate_key"
    assert _code(canonicalize, b"[-0,]") == "malformed_json"
    assert _code(canonicalize, b"[" * 65 + b"-0" + b"]" * 65) == "too_deep"
    assert _code(canonicalize, b'[-0,"\xff"]') == "invalid_utf8"


def test_the_encoder_is_unchanged_python_has_no_integer_minus_zero():
    """The refusal is the READER's: a Python int has no sign of zero, so encode_v4(-0) is encode_v4(0); -0.0 is a float."""
    for encode in (canonical.encode_v4, vo.encode_v4):
        assert encode(-0) == b"0" and encode({"a": [-0]}) == b'{"a":[0]}'
        assert _code(encode, -0.0) == "float_refused"


# --- the label picks the encoder ------------------------------------------------------------------

ARGS = {"amount_minor": 4200, "currency": "USD", "memo": "refund 7"}


def _v4_hash(act_type, args):
    """The SHA-384 of the v4 encoder's bytes, written out here: the v4 label derives nothing, the encoder stays."""
    return hashlib.sha384(vo.encode_v4(dict(args, act_type=act_type))).hexdigest()


def test_the_act_hash_is_derived_under_v3_only_and_the_v4_label_is_refused_like_any_unknown_label():
    for mod, labels in ((canonical, canonical.ACT_HASH_ALGS), (vo, tuple(vo.ENCODERS))):
        assert tuple(labels) == (V3,)
        want = hashlib.sha384(mod.encode_v4({**ARGS, "act_type": "payments.refund_send"})).hexdigest()
        # no control character, no float, integers in bound: v3 hashes the same bytes
        assert mod.act_hash("payments.refund_send", ARGS) == mod.act_hash("payments.refund_send", ARGS, V3) == want
        assert len(mod.act_hash("payments.refund_send", {"amount_minor": 2**53}, V3)) == 96
        for unknown in (V4, "sha384+canonical_payload.v5", "sha256+rfc8785-v1", "", None, 4, ["a"]):
            assert _code(mod.act_hash, "payments.refund_send", ARGS, unknown) == "act_hash_alg_unknown", unknown
        # the encoder is still there
        assert isinstance(mod.encode_v4({**ARGS, "act_type": "payments.refund_send"}), bytes)
    assert not hasattr(canonical, "ACT_HASH_ALG_V4")
    assert not hasattr(vo, "LABEL_V4")


def _envelope(label, act_hash, kind="requisition.lab.statement.v0", act_type="payments.refund_send"):
    metadata = {"act_hash": act_hash, "act_type": act_type, "display_digest": vo.display_digest(ARGS)}
    if label is not None:
        metadata["act_hash_alg"] = label
    signed = json.dumps({"receipt_type": kind, "metadata": metadata}, sort_keys=True, separators=(",", ":"))
    return {"signed_payload": signed, "receipt_hash": hashlib.sha256(signed.encode()).hexdigest(), "signature": "", "key_id": "k"}


def test_check_binding_recomputes_under_v3_and_a_v4_label_is_a_mismatch():
    control = {"memo": "\x1f"}
    h3 = vo.act_hash("note.write", control, V3)
    h4 = hashlib.sha384(vo.encode_v4(dict(control, act_type="note.write"))).hexdigest()
    assert h3 != h4

    def bound(label, signed_hash):
        metadata = {"act_hash": signed_hash, "act_type": "note.write", "act_hash_alg": label}
        signed = json.dumps({"receipt_type": "requisition.lab.statement.v0", "metadata": metadata})
        envelope = {"signed_payload": signed, "receipt_hash": hashlib.sha256(signed.encode()).hexdigest()}
        return vo.check_binding(control, "note.write", envelope)

    lines, ok, recomputed = bound(V3, h3)
    assert ok and recomputed == h3
    # a record whose signed label is the v4 string binds with neither hash, and the lines name act_hash_alg
    for signed_hash in (h3, h4):
        lines, ok, _ = bound(V4, signed_hash)
        assert ok is False and any(line.startswith("act_hash_alg:") for line in lines), lines


@pytest.mark.parametrize("label", ["sha384+canonical_payload.v4", "sha384+canonical_payload.v5", "sha256+rfc8785-v1", "", 4, ["sha384+canonical_payload.v4"]])
def test_a_record_under_a_label_the_verifier_does_not_derive_is_never_a_pass(label):
    for signed_hash in (vo.act_hash("payments.refund_send", ARGS, V3), _v4_hash("payments.refund_send", ARGS)):
        envelope = _envelope(label, signed_hash)
        assert vo.derivation_label(envelope) == V3
        lines, ok, _ = vo.check_binding(ARGS, "payments.refund_send", envelope)
        assert ok is False and any(line.startswith("act_hash_alg: MISMATCH") for line in lines), lines


def test_a_record_with_no_act_hash_alg_member_is_refused_with_its_own_reason():
    # Every producer of a record that binds an act writes the member, so a record without it is
    # not a server record. Its reason is its own, not "a label that does not match".
    for signed_hash in (vo.act_hash("payments.refund_send", ARGS, V3), _v4_hash("payments.refund_send", ARGS)):
        envelope = _envelope(None, signed_hash)
        assert "act_hash_alg" not in json.loads(envelope["signed_payload"])["metadata"]
        lines, ok, _ = vo.check_binding(ARGS, "payments.refund_send", envelope)
        assert ok is False, lines
        assert any(line.startswith("act_hash_alg: ABSENT") for line in lines), lines
        assert not any(line.startswith("act_hash_alg: MISMATCH") for line in lines), lines
    # a member that is present and JSON null is a label this verifier does not know: the other reason
    metadata = {"act_hash": "0" * 96, "act_type": "payments.refund_send", "act_hash_alg": None}
    signed = json.dumps({"receipt_type": "requisition.lab.statement.v0", "metadata": metadata})
    envelope = {"signed_payload": signed, "receipt_hash": hashlib.sha256(signed.encode()).hexdigest()}
    lines, ok, _ = vo.check_binding(ARGS, "payments.refund_send", envelope)
    assert ok is False and any(line.startswith("act_hash_alg: MISMATCH") for line in lines), lines


def test_a_record_that_says_the_v4_label_does_not_bind():
    envelope = _envelope(V4, _v4_hash("payments.refund_send", ARGS))
    assert vo.derivation_label(envelope) == V3
    lines, ok, _ = vo.check_binding(ARGS, "payments.refund_send", envelope)
    assert ok is False, lines
    # the encoder's own bound still holds, with no label in front of it
    assert _code(vo.encode_v4, {"amount_minor": 2**53}) == "integer_out_of_range"


# --- the published record and the published kit: checked in Requisition's own suite, where the kit, this
# repository and Requisition's bin/lab-verify are all present (test/bin_scripts/requisition_aws_drift_test.exs).
