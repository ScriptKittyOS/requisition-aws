# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The vendored ML-DSA (FIPS 204) verifier, for the package (``keys.KeyRegistry``).

The one copy in this repository lives beside the offline check, ``bin/vendor/mldsa.py`` (PyPI ``mldsa``
1.0.1 by Filippo Valsorda, CC0-1.0 OR 0BSD; ``bin/vendor/VENDORED.md``). The wheel carries it inside the
package as ``requisition_aws/_vendor/mldsa.py`` (pyproject.toml's force-include), and that copy is used
when it is there. Either is loaded by path and refused unless its bytes hash to the pinned SHA-256;
``tests/test_mldsa_vendored.py`` pins this constant equal to ``bin/verify_offline.py``'s.

Only verification exists: the module holds no signing code (secrets cannot be handled in constant
time in Python, its README says). Lab records are signed by Requisition's ML-DSA-87 seat.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
import types

_PACKAGED = pathlib.Path(__file__).resolve().parent / "_vendor" / "mldsa.py"  # installed from the wheel
_CHECKOUT = pathlib.Path(__file__).resolve().parent.parent / "bin" / "vendor" / "mldsa.py"  # this repository
MLDSA_PATH = _PACKAGED if _PACKAGED.is_file() else _CHECKOUT
MLDSA_SHA256 = "0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a"
MLDSA87_PUBLIC_BYTES = 2592
MLDSA87_SIGNATURE_BYTES = 4627
_MODULE_NAME = "requisition_aws._vendored_mldsa"
_cached: types.ModuleType | None = None


class VendoredFileChanged(RuntimeError):
    """bin/vendor/mldsa.py is not the pinned file: refuse to verify with it (fail closed)."""


def mldsa() -> types.ModuleType:
    global _cached
    if _cached is None:
        source = MLDSA_PATH.read_bytes()
        if hashlib.sha256(source).hexdigest() != MLDSA_SHA256:
            raise VendoredFileChanged(f"{MLDSA_PATH} is not the pinned file (sha256 {MLDSA_SHA256})")
        module = types.ModuleType(_MODULE_NAME)
        module.__file__ = str(MLDSA_PATH)
        sys.modules[_MODULE_NAME] = module
        exec(compile(source, str(MLDSA_PATH), "exec"), module.__dict__)
        _cached = module
    return _cached


def verify_mldsa87(public_key: bytes, signature: bytes, message: bytes, context: bytes = b"") -> bool:
    """Pure ML-DSA-87; ``False`` for any invalid signature, key or context."""
    m = mldsa()
    try:
        m.VerificationKey(public_key, parameters=m.ParameterSet.ML_DSA_87).verify(signature, message, context=context)
        return True
    except (m.VerificationError, ValueError):
        return False
