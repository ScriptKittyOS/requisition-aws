# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The vendored ML-DSA-87 verifier (bin/vendor/mldsa.py, PyPI mldsa 1.0.1) against NIST ACVP sigVer and
Wycheproof (negatives included: the repeated-hint class of CVE-2026-24850), and against two other
implementations: cryptography (OpenSSL) live, and Erlang/OTP :crypto (OpenSSL 3.5.9) recorded in
tests/otp/ and re-run when that toolchain is on this machine. Provenance: tests/vectors/mldsa87/."""

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess

import pytest

from requisition_aws import pq

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = pathlib.Path(__file__).parent / "vectors" / "mldsa87"
OTP_DIR = pathlib.Path(__file__).parent / "otp"
OTP_RESULTS = OTP_DIR / "otp_28.5.0.8_openssl-3.5.9_results.txt"
ESCRIPT = pathlib.Path.home() / ".asdf/installs/erlang/28.5.0.8-openssl-3.5.9/bin/escript"

ACVP = json.loads((VEC / "acvp_sigver_mldsa87_pure_external.json").read_text())
WYCHE = json.loads((VEC / "wycheproof_mldsa_87_verify_test.json").read_text())


def acvp_cases():
    for g in ACVP["testGroups"]:
        for t in g["tests"]:
            yield (f"a{t['tcId']}", bytes.fromhex(t["pk"]), bytes.fromhex(t["signature"]),
                   bytes.fromhex(t["message"]), bytes.fromhex(t["context"]), t["testPassed"])


def wyche_cases():
    for g in WYCHE["testGroups"]:
        for t in g["tests"]:
            yield (f"w{t['tcId']}", bytes.fromhex(g["publicKey"]), bytes.fromhex(t["sig"]),
                   bytes.fromhex(t["msg"]), bytes.fromhex(t.get("ctx", "")), t["result"] == "valid")


ALL = list(acvp_cases()) + list(wyche_cases())


# --- the pin -----------------------------------------------------------------------------------


def test_the_vendored_file_is_the_pinned_one_everywhere():
    digest = hashlib.sha256(pq.MLDSA_PATH.read_bytes()).hexdigest()
    assert digest == pq.MLDSA_SHA256 == "0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a"
    spec = importlib.util.spec_from_file_location("vo_pin", ROOT / "bin" / "verify_offline.py")
    vo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vo)
    assert vo.MLDSA_SHA256 == pq.MLDSA_SHA256
    assert pq.MLDSA_SHA256 in (ROOT / "bin" / "vendor" / "VENDORED.md").read_text()
    text = pq.MLDSA_PATH.read_text()
    assert "CC0 1.0" in text and "0BSD" in text and "def sign(" not in text and "class SigningKey" not in text


def test_a_changed_vendored_file_is_refused(tmp_path):
    spec = importlib.util.spec_from_file_location("vo_pin2", ROOT / "bin" / "verify_offline.py")
    vo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vo)
    changed = tmp_path / "mldsa.py"
    changed.write_bytes(pq.MLDSA_PATH.read_bytes() + b"\n# one more line\n")
    with pytest.raises(vo.Refused):
        vo.load_mldsa(str(changed))


def test_vector_files_are_the_recorded_ones():
    assert hashlib.sha256((VEC / "wycheproof_mldsa_87_verify_test.json").read_bytes()).hexdigest() == \
        "54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14"
    assert hashlib.sha256((VEC / "acvp_sigver_mldsa87_pure_external.json").read_bytes()).hexdigest() == \
        "768460682c2d81e101eeeefac12a0cfdb5d4712e0f718c2212bcfdf0a4a90522"
    assert WYCHE["algorithm"] == "ML-DSA-87" and WYCHE["numberOfTests"] == 241
    assert [(g["tgId"], g["parameterSet"], g["preHash"], g["signatureInterface"]) for g in ACVP["testGroups"]] == \
        [(5, "ML-DSA-87", "pure", "external")]


# --- the vectors -------------------------------------------------------------------------------


@pytest.mark.parametrize("case", list(acvp_cases()), ids=lambda c: c[0])
def test_nist_acvp_sigver(case):
    _id, pk, sig, msg, ctx, expected = case
    assert pq.verify_mldsa87(pk, sig, msg, ctx) is expected


def test_wycheproof_all_241():
    wrong = [c[0] for c in wyche_cases() if pq.verify_mldsa87(c[1], c[2], c[3], c[4]) is not c[5]]
    assert wrong == []
    counts = [c[5] for c in wyche_cases()]
    assert (counts.count(True), counts.count(False)) == (71, 170)


def test_the_repeated_hint_case_cve_2026_24850_is_rejected():
    (case,) = [(g, t) for g in WYCHE["testGroups"] for t in g["tests"] if t["comment"] == "signature with a repeated hint"]
    group, test = case
    assert test["result"] == "invalid" and test["flags"] == ["InvalidHintsEncoding"]
    assert pq.verify_mldsa87(bytes.fromhex(group["publicKey"]), bytes.fromhex(test["sig"]), bytes.fromhex(test["msg"])) is False


# --- differential: cryptography (OpenSSL), live -----------------------------------------------


def _crypto_mldsa():
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        return None
    return mldsa if backend.mldsa_supported() else None


needs_crypto_mldsa = pytest.mark.skipif(_crypto_mldsa() is None, reason="cryptography without ML-DSA")


@needs_crypto_mldsa
def test_differential_against_cryptography_on_every_vector():
    from cryptography.exceptions import InvalidSignature

    mldsa = _crypto_mldsa()
    disagree = []
    for cid, pk, sig, msg, ctx, _expected in ALL:
        try:
            mldsa.MLDSA87PublicKey.from_public_bytes(pk).verify(sig, msg, ctx or None)
            theirs = True
        except (InvalidSignature, ValueError):
            theirs = False
        if theirs is not pq.verify_mldsa87(pk, sig, msg, ctx):
            disagree.append(cid)
    assert disagree == []


@needs_crypto_mldsa
def test_signatures_cryptography_makes_verify_here_and_one_flipped_bit_does_not():
    key = _crypto_mldsa().MLDSA87PrivateKey.generate()
    pk = key.public_key().public_bytes_raw()
    for msg, ctx in [(b"", b""), (b'{"verdict":"allow"}', b""), (os.urandom(997), b"ctx-requisition")]:
        sig = key.sign(msg, ctx or None)
        assert pq.verify_mldsa87(pk, sig, msg, ctx)
        flipped = bytearray(sig)
        flipped[len(sig) // 2] ^= 0x01
        assert not pq.verify_mldsa87(pk, bytes(flipped), msg, ctx)
        assert not pq.verify_mldsa87(pk, sig, msg + b"x", ctx)
        assert not pq.verify_mldsa87(pk, sig, msg, ctx + b"x")


# --- differential: Erlang/OTP :crypto over OpenSSL 3.5.9 -------------------------------------


def otp_cases():
    """Every vector with an EMPTY context: OTP 28.5's :crypto takes no ML-DSA context argument."""
    return [c for c in ALL if not c[4]]


def otp_input(path):
    lines = [f"{cid} {pk.hex()} {sig.hex() or '-'} {msg.hex() or '-'}" for cid, pk, sig, msg, _ctx, _ in otp_cases()]
    path.write_text("\n".join(lines) + "\n")


def parse_otp(text):
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("true", "false", "error"):
            out[parts[0]] = parts[1] == "true"
    return out


def test_agrees_with_the_recorded_otp_run():
    recorded = parse_otp(OTP_RESULTS.read_text())
    assert "OpenSSL 3.5.9" in OTP_RESULTS.read_text()
    cases = otp_cases()
    assert sorted(recorded) == sorted(c[0] for c in cases) and len(cases) == 235
    assert [c[0] for c in cases if recorded[c[0]] is not pq.verify_mldsa87(c[1], c[2], c[3])] == []


@pytest.mark.skipif(not ESCRIPT.exists(), reason="the OTP 28.5.0.8 / OpenSSL 3.5.9 toolchain is not on this machine")
def test_agrees_with_otp_live(tmp_path):
    cases = tmp_path / "cases.txt"
    otp_input(cases)
    proc = subprocess.run([str(ESCRIPT), str(OTP_DIR / "mldsa87_verify.escript"), str(cases)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert parse_otp(proc.stdout) == parse_otp(OTP_RESULTS.read_text())
