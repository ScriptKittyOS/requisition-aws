# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""ONE written rule for a retired, revoked or foreign-signer
key, run against every verifier in this repository with ONE shared vector file.

The rule (the issuing server's key rule is its text): for a record whose
signed ``occurred_at`` is T and a key entry E, in this order --
  1. E.status is ``compromised`` or ``revoked``                    -> key_revoked   (earlier records too: no
                                                                      verifier here holds the log binding)
  2. E.status is not ``active`` or ``retired``, or ``retired`` with no valid_to -> key_status_unusable
  3. E.valid_from / E.valid_to unreadable                           -> key_window_unreadable
  4. T unreadable                                                   -> signed_instant_unreadable
  5. not valid_from <= T < valid_to (valid_to null: open)          -> key_not_valid_at_signing
  6. an accepted-signers set is given and E.signer is not in it    -> signer_not_accepted
Otherwise the signature is checked. The window is half open, as the released verify_receipt.py's is.

Verifiers under test: requisition_aws.keys.KeyRegistry (the gates), bin/verify_chain.py, bin/verify_offline.py's
ML-DSA-87 check (the Ed25519 half of verify_offline is bin/lab-verify's, tested in requisition).
"""

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

from requisition_aws.keys import KeyRegistry

from . import key_rule_harness as H
from .test_verify_offline import LAB_VERIFY, vo

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHAIN = ROOT / "bin" / "verify_chain.py"
VECTORS_SHA256 = "91e08c1d96be2a6bd84b299166f8046ea7c9c8af8ff1b9dddaa584ca5362d517"
VECTORS = H.load_vectors()
ALGORITHMS = ["ed25519", "mldsa87"]


def test_the_vector_file_is_the_pinned_copy():
    """The pin. That the file is a byte copy of Requisition's key-rule vector file is checked in
    Requisition's suite."""
    assert hashlib.sha256(H.VECTOR_FILE.read_bytes()).hexdigest() == VECTORS_SHA256


def ids(vector):
    return vector["name"]


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("vector", VECTORS, ids=ids)
def test_the_gates_registry_follows_the_rule(vector, algorithm):
    registry, envelope = H.build(vector, algorithm)
    options = {} if vector["accept_signers"] is None else {"accept_signers": vector["accept_signers"]}
    keys = KeyRegistry.from_bytes(json.dumps(registry).encode(), **options)
    assert keys.verify(envelope) is (vector["expect"] is None), vector["name"]
    assert keys.check(envelope) == vector["expect"], vector["name"]


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["accept_signers"] is None], ids=ids)
def test_the_mldsa_check_of_verify_offline_follows_the_rule(vector):
    registry, envelope = H.build(vector, "mldsa87")
    lines, ok = vo.check_mldsa87(envelope, registry["entries"][0])
    assert ok is (vector["expect"] is None), (vector["name"], lines)
    if vector["expect"] is not None:
        assert vector["expect"] in " ".join(lines), (vector["name"], lines)


@pytest.mark.parametrize("vector", [v for v in VECTORS if v["accept_signers"] is not None], ids=ids)
def test_the_mldsa_check_of_verify_offline_takes_the_accepted_signers(vector):
    registry, envelope = H.build(vector, "mldsa87")
    lines, ok = vo.check_mldsa87(envelope, registry["entries"][0], accept_signers=vector["accept_signers"])
    assert ok is (vector["expect"] is None), (vector["name"], lines)
    if vector["expect"] is not None:
        assert vector["expect"] in " ".join(lines), (vector["name"], lines)


def chain(tmp_path, vector, algorithm, *extra):
    registry, envelope = H.build(vector, algorithm)
    (tmp_path / "keys.json").write_text(json.dumps(registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": [envelope]}))
    for flag in vector["accept_signers"] or []:
        extra += ("--accept-signer", flag)
    done = subprocess.run([sys.executable, "-I", str(CHAIN), "--registry", str(tmp_path / "keys.json"), "--export",
                           str(tmp_path / "export.json"), "--json", *extra], capture_output=True, text=True, timeout=300)
    return done


@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("vector", VECTORS, ids=ids)
def test_verify_chain_follows_the_rule_and_accuses_nobody(tmp_path, vector, algorithm):
    done = chain(tmp_path, vector, algorithm)
    report = json.loads(done.stdout)
    if vector["expect"] is None:
        assert (done.returncode, report["result"]) == (0, "ok"), (vector["name"], done.stdout, done.stderr)
    else:
        codes = [f["code"] for f in report["failures"]]
        # a refusal of the KEY is a trust refusal under its own name, never signature_invalid (an accusation)
        assert codes == [vector["expect"]], (vector["name"], codes)
        assert done.returncode == 1


def _sources(path, wanted):
    import ast
    text = path.read_text()
    parts = []
    for node in ast.parse(text).body:
        name = getattr(node, "name", None) or (
            node.targets[0].id if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) else None)
        if name in wanted:
            parts.append(ast.get_source_segment(text, node))
    return parts


RULE = {"_INSTANT_SHAPE", "_is_instant", "key_standing"}
READER = {"MAX_DEPTH", "MAX_INTEGER", "_check_depth", "_bounded_int"}
MATERIAL = {"_P", "_L", "_D", "_SQRT_M1", "_IDENTITY", "_decode_canonical_point", "_add", "_multiply", "ed25519_key_acceptable",
            "ed25519_signature_canonical"}


def _req_tools():
    """Requisition's bin/lab-verify as committed here; its log checker, and its live bin/lab-verify, are
    compared with these texts in Requisition's suite."""
    return [LAB_VERIFY]


def test_the_rule_is_one_function_copied_byte_for_byte():
    """keys.py is the original; verify_chain.py, verify_offline.py and the committed copy of Requisition's
    bin/lab-verify run under -I and carry the same source."""
    original = _sources(ROOT / "requisition_aws" / "keys.py", RULE)
    assert len(original) == 3
    for tool in (CHAIN, ROOT / "bin" / "verify_offline.py", LAB_VERIFY):
        assert _sources(tool, RULE) == original, tool


@pytest.mark.parametrize("signer", [["kms"], {"kms": 1}], ids=["a list", "an object"])
def test_a_signer_that_is_a_list_or_an_object_is_not_accepted_and_raises_nothing(signer):
    """The three copies of the rule in this repository. bin/lab-verify's copy is compared by the test above, and is run on
    such a key file in requisition."""
    import importlib.util

    from requisition_aws.keys import key_standing
    spec = importlib.util.spec_from_file_location("verify_chain_key_rule_under_test", CHAIN)
    chain_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chain_module)
    entry = {"status": "active", "valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "signer": signer}
    at = "2026-11-09T12:00:00Z"
    for rule in (key_standing, chain_module.key_standing, vo.key_standing):
        assert rule(entry, at, frozenset({"kms"})) == "signer_not_accepted"
        assert rule(entry, at) is None  # no accepted-signers set is given: the signer is not asked for
        assert rule(dict(entry, status="compromised"), at, frozenset({"kms"})) == "key_revoked"  # the order holds


def test_the_ed25519_key_material_rule_is_one_text_in_every_python_verifier():
    """keys.py is the original (prime-order keys, canonical R and S < L); verify_chain.py, bin/lab-verify and
    Requisition's log checker carry the same text."""
    original = _sources(ROOT / "requisition_aws" / "keys.py", MATERIAL)
    assert len(original) == 10
    for tool in [CHAIN] + _req_tools():
        assert _sources(tool, MATERIAL) == original, tool


def test_the_reader_bound_is_one_text_in_every_python_reader():
    """client.py is the original; the -I tools (aws and requisition) carry the same bound."""
    original = _sources(ROOT / "requisition_aws" / "client.py", READER)
    assert len(original) == 4
    tools = [CHAIN, ROOT / "bin" / "verify_offline.py"] + _req_tools()
    for tool in tools:
        assert _sources(tool, READER) == original, tool


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_verify_chain_names_a_duplicated_key_id_as_a_registry_fault_not_a_bad_signature(tmp_path, algorithm):
    vector = next(v for v in VECTORS if v["name"] == "active_open_inside")
    registry, envelope = H.build(vector, algorithm)
    registry["entries"] = registry["entries"] + [dict(registry["entries"][0], status="retired", valid_to="2026-11-02T00:00:00Z")]
    (tmp_path / "keys.json").write_text(json.dumps(registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": [envelope]}))
    done = subprocess.run([sys.executable, "-I", str(CHAIN), "--registry", str(tmp_path / "keys.json"), "--export",
                           str(tmp_path / "export.json"), "--json"], capture_output=True, text=True, timeout=300)
    assert [f["code"] for f in json.loads(done.stdout)["failures"]] == ["registry_duplicate_key"], done.stdout


def test_verify_chain_refuses_an_empty_signer_label_as_usage(tmp_path):
    vector = next(v for v in VECTORS if v["name"] == "active_open_inside")
    registry, envelope = H.build(vector, "ed25519")
    (tmp_path / "keys.json").write_text(json.dumps(registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": [envelope]}))
    done = subprocess.run([sys.executable, "-I", str(CHAIN), "--registry", str(tmp_path / "keys.json"), "--export",
                           str(tmp_path / "export.json"), "--accept-signer", ""], capture_output=True, text=True, timeout=300)
    assert done.returncode == 2 and "empty" in done.stderr, (done.returncode, done.stderr)


@pytest.mark.parametrize("tool", ["verify_offline.py"])
def test_verify_offline_carries_the_rule_and_no_unused_ed25519_screening(tool):
    """verify_offline.py checks no Ed25519 signature itself (bin/lab-verify does): the key screening, which verify_chain.py
    needs and carries (test_the_ed25519_key_material_rule...), would be dead code here."""
    source = (ROOT / "bin" / tool).read_text()
    assert "_SQRT_M1" not in source and "def ed25519_key_acceptable" not in source
