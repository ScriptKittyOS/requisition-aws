# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""bin/vendor/ed25519_rfc8032.py: the pin, the copy against its source range, and the routine against
an independent Ed25519 (cryptography's, the test environment only)."""

import hashlib
import importlib.util
import os
import pathlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parent.parent
COPY = ROOT / "bin" / "vendor" / "ed25519_rfc8032.py"
# verify_receipt.py as published in receipt-verification r4, the copy's source (tests/fixtures/verify_receipt_r4/PROVENANCE.md)
SOURCE = ROOT / "tests" / "fixtures" / "verify_receipt_r4" / "verify_receipt.py"
SOURCE_SHA256 = "6414bcb3f4a4a02c14a70ffe7e74dc6bb5b5725d6dc9f83ead38f5bd5286db8c"


def _script():
    spec = importlib.util.spec_from_file_location("verify_chain", ROOT / "bin" / "verify_chain.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_pin_in_the_script_and_vendored_md_is_the_file():
    digest = hashlib.sha256(COPY.read_bytes()).hexdigest()
    assert _script().ED25519_SHA256 == digest
    assert digest in (ROOT / "bin" / "vendor" / "VENDORED.md").read_text()


def test_a_changed_copy_is_refused(tmp_path):
    bad = tmp_path / "ed.py"
    bad.write_bytes(COPY.read_bytes() + b"\n")
    mod = _script()
    with pytest.raises(mod.Usage):
        mod.load_pinned(str(bad), mod.ED25519_SHA256, "x_ed")


def test_the_copy_is_lines_58_to_134_of_verify_receipt_byte_for_byte():
    source = SOURCE.read_bytes()
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA256
    want = b"\n".join(source.split(b"\n")[57:134]) + b"\n"
    copy = COPY.read_bytes()
    assert copy.endswith(b"import hashlib\n\n" + want)


def test_the_routine_agrees_with_an_independent_ed25519():
    ed = _script().load_pinned(str(COPY), _script().ED25519_SHA256, "x_ed_ok")
    for _ in range(4):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        message = os.urandom(80)
        sig = key.sign(message)
        assert ed.ed25519_verify(sig, message, pub) is True
        flipped = bytearray(sig)
        flipped[5] ^= 0x10
        assert ed.ed25519_verify(bytes(flipped), message, pub) is False
        assert ed.ed25519_verify(sig, message + b"x", pub) is False
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        assert ed.ed25519_verify(sig, message, other) is False
        assert ed.ed25519_verify(sig[:63], message, pub) is False
