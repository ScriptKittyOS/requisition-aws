# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The KEY MATERIAL rule -- a public key is accepted only if it decodes canonically, is not
small-order and [L]P is the identity (prime-order subgroup); a signature whose R is not a canonical point encoding or whose
S >= L is refused -- in requisition_aws.keys (the gates), bin/verify_chain.py and (tests in requisition) bin/lab-verify and
bin/lab-log-verify. The vectors are the shared file's ed25519_* sections, made by tools/gen_ed25519_vectors.py with
independent arithmetic; the two ed25519_triples are the cases on which the deployed verifiers were MEASURED to disagree
(OpenSSL reduces h mod L, the released verify_receipt.py (r4) uses the full h) -- with a mixed-order key refused, none can."""

import base64
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from requisition_aws import keys as keysmod
from requisition_aws.keys import KeyRegistry

from . import key_rule_harness as H

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = json.loads(H.VECTOR_FILE.read_text())


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHAIN = _load(ROOT / "bin" / "verify_chain.py", "verify_chain_material_under_test")
IMPLS = {"keys": keysmod, "verify_chain": CHAIN}


@pytest.mark.parametrize("impl", sorted(IMPLS))
@pytest.mark.parametrize("vector", DOC["ed25519_keys"], ids=lambda v: v["name"])
def test_a_public_key_is_accepted_only_if_canonical_small_order_free_and_prime_order(impl, vector):
    assert IMPLS[impl].ed25519_key_acceptable(bytes.fromhex(vector["public_key"])) is (vector["expect"] == "ok")


@pytest.mark.parametrize("impl", sorted(IMPLS))
@pytest.mark.parametrize("vector", DOC["ed25519_signatures"], ids=lambda v: v["name"])
def test_a_signature_needs_a_canonical_R_and_S_below_L(impl, vector):
    assert IMPLS[impl].ed25519_signature_canonical(bytes.fromhex(vector["signature"])) is (vector["expect"] == "ok")


@pytest.mark.parametrize("impl", sorted(IMPLS))
@pytest.mark.parametrize("vector", DOC["ed25519_triples"], ids=lambda v: v["name"])
def test_the_measured_disagreement_cases_are_refused_at_the_key(impl, vector):
    """OpenSSL, node:crypto and python cryptography answer one way, the released verify_receipt.py (r4) the other, on a mixed-order
    key: the key is refused, so there is no signature left to disagree about."""
    assert IMPLS[impl].ed25519_key_acceptable(bytes.fromhex(vector["public_key"])) is False


def test_the_cryptography_backend_really_does_accept_what_the_rule_refuses():
    """The control for the rule: without it the mixed-order key and the non-canonical R are live (OpenSSL accepts the key, the
    released verifier the R) -- so the vectors are not refused by the backend for us."""
    mixed = next(v for v in DOC["ed25519_keys"] if v["name"].startswith("mixed_order_honest_plus_torsion_order_8"))
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(mixed["public_key"]))  # loads: OpenSSL has no objection to the key


def _signed_by_a_mixed_order_key(nonce):
    """A record whose key is A + T (T of order 8) and whose signature the key holder made honestly with the secret of A,
    hashing the mixed key's bytes: the construction behind that disagreement. Returns (registry, envelope)."""
    ref = _load(ROOT / "bin" / "vendor" / "ed25519_rfc8032.py", "vendored_ed_for_the_test")
    seed = hashlib.sha256(b"fix-verifiers mixed order %d" % nonce).digest()
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = ref._scalarmult(ref.B, a)
    torsion = bytes.fromhex(next(v for v in DOC["ed25519_keys"] if v["name"].startswith("torsion_order_8"))["public_key"])
    mixed = ref._edwards(A, ref._decode_point(torsion))
    mixed_bytes = (mixed[1] | ((mixed[0] & 1) << 255)).to_bytes(32, "little")
    payload = json.dumps({"chain_scope": H.SCOPE, "sequence": 1, "previous_hash": None, "receipt_type": "requisition.lab.statement.v0",
                          "occurred_at": "2026-11-05T00:00:00Z", "metadata": {"nonce": nonce}}, sort_keys=True, separators=(",", ":"))
    message = payload.encode()
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % ref.Q
    Rpt = ref._scalarmult(ref.B, r)
    R = (Rpt[1] | ((Rpt[0] & 1) << 255)).to_bytes(32, "little")
    h = int.from_bytes(hashlib.sha512(R + mixed_bytes + message).digest(), "little")
    signature = R + ((r + h * a) % ref.Q).to_bytes(32, "little")
    entry = {"key_id": "requisition_lab_vec_ed25519_v0", "algorithm": "ed25519", "public_key": base64.b64encode(mixed_bytes).decode(),
             "public_key_fingerprint": hashlib.sha256(mixed_bytes).hexdigest(), "status": "active", "valid_from": "2026-11-01T00:00:00Z",
             "valid_to": None, "signer": "dev", "profile": "lab"}
    envelope = {"signature": base64.b64encode(signature).decode(), "key_id": entry["key_id"], "signed_payload": payload,
                "receipt_hash": hashlib.sha256(message).hexdigest()}
    return {"schema": "requisition_lab_key_file.v1", "entries": [entry]}, envelope, mixed_bytes, signature, message


def _a_message_openssl_accepts():
    for nonce in range(64):
        registry, envelope, key, signature, message = _signed_by_a_mixed_order_key(nonce)
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        except InvalidSignature:
            continue
        return registry, envelope
    pytest.fail("no honest signature under a mixed-order key verifies under OpenSSL in 64 tries (h mod 8 is uniform: impossible)")


def test_a_record_signed_by_a_mixed_order_key_is_not_verified_by_the_gate():
    registry, envelope = _a_message_openssl_accepts()
    keys = KeyRegistry.from_bytes(json.dumps(registry).encode())
    assert keys.verify(envelope) is False  # the key is never held
    assert keys.check(envelope) == "unknown_key"


def test_verify_chain_refuses_the_mixed_order_key_by_name_not_as_a_bad_signature(tmp_path):
    registry, envelope = _a_message_openssl_accepts()
    (tmp_path / "keys.json").write_text(json.dumps(registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": [envelope]}))
    done = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "verify_chain.py"), "--registry", str(tmp_path / "keys.json"),
                           "--export", str(tmp_path / "export.json"), "--json"], capture_output=True, text=True, timeout=300)
    assert [f["code"] for f in json.loads(done.stdout)["failures"]] == ["key_not_prime_order"], done.stdout


# The demo lab's dev registry: tracked (public keys only, signer dev, profile lab; see its PROVENANCE.md).
DEV_REGISTRY = ROOT / "tests" / "fixtures" / "real_lab_chain" / "aws-instance" / "instance-lab-keys.json"
# The demo lab's AWS KMS Ed25519 public key, without its key id or ARN (tests/fixtures/kms_lab_key/PROVENANCE.md).
KMS_KEY = ROOT / "tests" / "fixtures" / "kms_lab_key" / "ed25519-public-key.json"


def _every_ed25519_entry_is_prime_order(path):
    seen = 0
    for entry in json.loads(path.read_text())["entries"]:
        if entry.get("algorithm") == "ed25519":
            seen += 1
            assert keysmod.ed25519_key_acceptable(base64.b64decode(entry["public_key"])), (path.name, entry.get("key_id"))
    assert seen > 0, "%s holds no ed25519 entry" % path.name


def test_the_demo_labs_dev_registry_keys_are_prime_order():
    """The genuine keys of the demo lab's dev registry pass the rule: an honest key is always prime order."""
    _every_ed25519_entry_is_prime_order(DEV_REGISTRY)


def test_the_demo_labs_kms_key_is_prime_order():
    """The genuine Ed25519 key the demo lab's AWS KMS key holds passes the same rule."""
    _every_ed25519_entry_is_prime_order(KMS_KEY)


def _signed_with_a_non_canonical_r():
    """A prime-order key, and a signature whose R is the identity written non-canonically (y = p + 1 .. ee ff .. 7f) and S = h*a mod L:
    the equation S*B = R + h*A holds, the released verifier's decode accepts the R, OpenSSL refuses the encoding."""
    ref = _load(ROOT / "bin" / "vendor" / "ed25519_rfc8032.py", "vendored_ed_for_the_noncanonical_r")
    seed = hashlib.sha256(b"fix-verifiers non-canonical R").digest()
    digest = hashlib.sha512(seed).digest()
    a = (int.from_bytes(digest[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    A = ref._scalarmult(ref.B, a)
    key = (A[1] | ((A[0] & 1) << 255)).to_bytes(32, "little")
    payload = json.dumps({"chain_scope": H.SCOPE, "sequence": 1, "previous_hash": None, "receipt_type": "requisition.lab.statement.v0",
                          "occurred_at": "2026-11-05T00:00:00Z", "metadata": {}}, sort_keys=True, separators=(",", ":"))
    R = bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    h = int.from_bytes(hashlib.sha512(R + key + payload.encode()).digest(), "little")
    signature = R + ((h * a) % ref.Q).to_bytes(32, "little")
    assert ref.ed25519_verify(signature, payload.encode(), key) is True  # the released verifier accepts it
    entry = {"key_id": "requisition_lab_vec_ed25519_v0", "algorithm": "ed25519", "public_key": base64.b64encode(key).decode(),
             "public_key_fingerprint": hashlib.sha256(key).hexdigest(), "status": "active", "valid_from": "2026-11-01T00:00:00Z",
             "valid_to": None, "signer": "dev", "profile": "lab"}
    envelope = {"signature": base64.b64encode(signature).decode(), "key_id": entry["key_id"], "signed_payload": payload,
                "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}
    return {"schema": "requisition_lab_key_file.v1", "entries": [entry]}, envelope


def test_a_non_canonical_r_that_the_released_verifier_accepts_is_refused_by_verify_chain(tmp_path):
    registry, envelope = _signed_with_a_non_canonical_r()
    (tmp_path / "keys.json").write_text(json.dumps(registry))
    (tmp_path / "export.json").write_text(json.dumps({"records": [envelope]}))
    done = subprocess.run([sys.executable, "-I", str(ROOT / "bin" / "verify_chain.py"), "--registry", str(tmp_path / "keys.json"),
                           "--export", str(tmp_path / "export.json"), "--json"], capture_output=True, text=True, timeout=300)
    assert [f["code"] for f in json.loads(done.stdout)["failures"]] == ["signature_invalid"], done.stdout


def test_the_gate_checks_the_signature_encoding_itself_not_only_through_the_backend(monkeypatch):
    """OpenSSL happens to refuse a non-canonical R; the rule must not depend on that: with a backend that accepts everything
    the registry still refuses it."""
    registry, envelope = _signed_with_a_non_canonical_r()
    import cryptography.hazmat.primitives.asymmetric.ed25519 as backend

    class AcceptsAnything:
        @staticmethod
        def from_public_bytes(raw):
            return type("K", (), {"verify": staticmethod(lambda signature, data: None)})()

    monkeypatch.setattr(backend, "Ed25519PublicKey", AcceptsAnything)
    keys = KeyRegistry.from_bytes(json.dumps(registry).encode())
    assert keys.check(envelope) == "signature_invalid"
