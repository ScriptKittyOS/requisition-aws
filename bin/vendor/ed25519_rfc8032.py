# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Ed25519 verification (RFC 8032), stdlib only: a byte-for-byte copy of lines 58-134 of
receipt-verification/verifier/verify_receipt.py in the public receipt-verification r4 release (file sha256
6414bcb3f4a4a02c14a70ffe7e74dc6bb5b5725d6dc9f83ead38f5bd5286db8c). The arithmetic follows the structure of the
public-domain Ed25519 Python reference code; it is not RFC 8032's section 6 code. Everything below the
"import hashlib" line is that range, unmodified (its sha256 is in bin/vendor/VENDORED.md).
Verification only. Loaded by bin/verify_chain.py by path under a pinned sha256 of this whole file."""

import hashlib

# --- RFC 8032 Ed25519 verification -------------------------------------------------------------
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = 4 * _inv(5)
B = [_xrecover(BY) % P, BY % P]


def _edwards(a, b):
    x1, y1 = a
    x2, y2 = b
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return [x3 % P, y3 % P]


def _scalarmult(point, e):
    result = [0, 1]
    addend = point
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _on_curve(point):
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decode_point(raw):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (raw[31] >> 7) & 1:
        x = P - x
    point = [x, y]
    if not _on_curve(point):
        raise ValueError("point is not on the curve")
    return point


def ed25519_verify(signature, message, public_key):
    """True when `signature` is a valid Ed25519 signature over `message` under `public_key`."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r = _decode_point(signature[:32])
        a = _decode_point(public_key)
    except (ValueError, IndexError):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _scalarmult(B, s) == _edwards(r, _scalarmult(a, h))
