# Vendored files

## `mldsa.py`: ML-DSA (FIPS 204) signature verification, pure Python

| | |
|---|---|
| what | `src/mldsa/mldsa.py` of mldsa-py, copied byte for byte, unmodified |
| author | Filippo Valsorda |
| upstream | https://github.com/FiloSottile/mldsa-py (PyPI project `mldsa`, https://pypi.org/project/mldsa/) |
| version | **1.0.1** (uploaded to PyPI 2026-07-26) |
| downloaded from | https://files.pythonhosted.org/packages/ee/12/47c2ce5d1c133fbdb50d24c8fc10cd7a5f4000a6f57888565514051a97fb/mldsa-1.0.1-py3-none-any.whl (fetched 2026-11-09) |
| wheel sha256 | `cad0a75124c5a6f4c1efe0e013039e9b0a1a86a9bb8ec5a75d6cf71a45ce08f9` (equals PyPI's published digest) |
| sdist sha256 | `005a296d138448d9210a1f36bdc3190d30a19595f1bbf2b92aa537049d797a31` (`mldsa-1.0.1.tar.gz`; its `src/mldsa/mldsa.py` is byte-identical to the wheel's) |
| **file sha256** | **`0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a`** |
| licence | CC0-1.0 OR 0BSD (the file's own header; PyPI `License-Expression`). `LICENSE.mldsa` here is the upstream 0BSD `LICENSE`, sha256 `74b344a43288283ca7896b38d859bd6b91035110bb9c69856afbc60a01ff65e4` |
| dependencies | none: `hashlib.shake_128`/`shake_256`, `dataclasses`, `enum`, `sys`, `typing` (stdlib); Python 3.8+ |
| what it does | verification only: `VerificationKey(pk, parameters=ParameterSet.ML_DSA_87).verify(signature, message, context=b"")` raises `VerificationError` on an invalid signature. It holds no signing code. |

**How it is loaded.** Never imported by name. `bin/verify_offline.py` (`load_mldsa`) and
`requisition_aws/pq.py` (`mldsa()`) read the file by path, refuse it unless its SHA-256 equals the
pinned value above (both carry the constant; `tests/test_mldsa_vendored.py` pins the two and the file
equal), then execute it as a module. `python3 -I` does not put the script's directory on `sys.path`,
so this is also what makes it reachable under `-I`.

**What it is checked against** (`tests/test_mldsa_vendored.py`):

- NIST ACVP-Server `ML-DSA-sigVer-FIPS204/internalProjection.json` at release v1.1.0.43 (commit
  `975de31eb83d87039ec88934fdc47d8c312b892d`), its ML-DSA-87 pure external-interface group (tgId 5,
  15 cases): `tests/vectors/mldsa87/PROVENANCE.md`.
- C2SP Wycheproof `testvectors_v1/mldsa_87_verify_test.json` at commit
  `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (241 cases, among them tcId 21 "signature with a repeated
  hint": the class of CVE-2026-24850, the RustCrypto `ml-dsa` crate accepting repeated hint indices).
- A differential against two other implementations: `cryptography`'s ML-DSA-87 (OpenSSL 4.0.3, the
  test environment only), live; and Erlang/OTP 28.5.0.8 `:crypto` over OpenSSL 3.5.9, recorded in
  `tests/otp/` and re-run when that toolchain is present.

**Updating it** is a reviewed change: replace the file from a new release, record the new URLs and
digests here, change the pinned constant in both loaders, and run the tests.

## `ed25519_rfc8032.py`: Ed25519 verification (RFC 8032), standard library only

| | |
|---|---|
| what | lines 58-134 of `receipt-verification/verifier/verify_receipt.py` in the public receipt-verification r4 release (the stdlib Ed25519 it carries; its arithmetic follows the structure of the public-domain Ed25519 Python reference code, not RFC 8032's section 6 code), copied byte for byte under a short header and `import hashlib` |
| source | that file as published in receipt-verification r4 (HolyTrinity-Benchmark tag `receipt-verification-r4`; the file last changed 2026-09-20) |
| **source file sha256** | **`6414bcb3f4a4a02c14a70ffe7e74dc6bb5b5725d6dc9f83ead38f5bd5286db8c`** (`verify_receipt.py`, whole file) |
| source range sha256 | `ac18b516dc59325c88073df02bd538508179f02f94fd14d5d756cca67af7757c` (`sed -n '58,134p' verify_receipt.py \| sha256sum`) |
| **file sha256** | **`cef4cb15f0f6f2b820c4cb06a3df6abd35352adcbaf26c93e836a928403a096e`** (this copy, pinned in `bin/verify_chain.py`) |
| licence | Apache-2.0: this project's own code (its header names the licence and the copyright holder) |
| what it does | `ed25519_verify(signature, message, public_key) -> bool`; verification only, no signing code |

**How it is loaded.** As `mldsa.py` is: `bin/verify_chain.py` reads it by path, refuses it unless its
SHA-256 equals the pinned value above, then executes it as a module. **Recipe to re-derive:**
`sed -n '58,134p' verify_receipt.py` must equal this file from the line after `import hashlib` and its
blank line to the end. `tests/test_verify_chain_vendored.py` checks the pin, the range against the
requisition tree when present, and the routine against `cryptography`'s Ed25519 (valid, wrong key,
flipped bit).
