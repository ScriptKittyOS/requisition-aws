# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Ed25519 checks of lab records inside the adapter (optional; ``bin/lab-verify`` is the offline check).

A lab record is the four-field envelope ``{signature, key_id, signed_payload, receipt_hash}``
(``sanction_requests.ex:509-517``); the signature is Ed25519 over the UTF-8 bytes of
``signed_payload`` and ``receipt_hash`` is their SHA-256 (``lab_records.ex:141-150``;
``bench/holytrinity-v2/verifier/verify_receipt.py:423-434``). The key file is what ``GET /v1/keys``
serves (``router.ex:251-264``): ``{"entries": [{key_id, algorithm, public_key (base64),
public_key_fingerprint (sha256 hex of the raw key), status, ...}]}``.

THE KEY RULE (requisition lib/autonomous_agency/authority/execute_api/lab_key_rule.ex is its text,
tests/vectors/key_rule_vectors.v1.json its vectors, run against every verifier). For a record whose signed
``occurred_at`` is T and a key entry E, in this order: status ``compromised``/``revoked`` -> ``key_revoked``;
status not ``active``/``retired`` (or ``retired`` with no valid_to) -> ``key_status_unusable``; valid_from/valid_to
unreadable -> ``key_window_unreadable``; T unreadable -> ``signed_instant_unreadable``; not
valid_from <= T < valid_to (valid_to null: open) -> ``key_not_valid_at_signing``; an accepted-signers set is
given and E.signer is not in it -> ``signer_not_accepted``. Otherwise the signature is checked. ``check`` returns
the reason (or ``signature_invalid`` / ``unknown_key`` / ``key_file_unreadable``); ``verify`` is ``check is None``.

An entry with ``"algorithm": "mldsa87"`` (the lab's ML-DSA-87 seat, ``lab_signer.ex``: key id
``requisition_lab_dev_mldsa87_v0``, a 2,592-byte public key) is checked as pure ML-DSA-87 with the
empty context over the same bytes (``requisition.lab.verify_mldsa87.ex``), by the vendored verifier
(``requisition_aws.pq``), under the same key rule as an Ed25519 key (a retired ML-DSA-87 key still verifies
its own window).

An Ed25519 key is held only when it is a canonical point encoding of a point of the PRIME-ORDER subgroup other than the
identity (``ed25519_key_acceptable``: [L]P is the identity; small-order and mixed-order keys are
refused, on which verifiers that reduce h mod L and verifiers that do not answer differently for one signature), and a
signature is checked only when its R is canonical and S < L (``ed25519_signature_canonical``). ``from_bytes`` skips any
other entry, as requisition-ts's ``KeyRegistry.fromBytes`` does (@noble/curves 2.4.0 ``Point.fromBytes(bytes, false)``,
strict, then ``isTorsionFree()``), and the constructor refuses one. Without it, the identity key verifies R = identity,
S = 0 for every message. The key file is read with ``client.loads_strict``.

LIMIT: a key fetched from the lab itself is the lab key, served by the lab, not a trust root.
Pin the file once (``from_bytes``) and the adapter at least notices a key change.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import threading
import time

from . import pq
from .client import loads_strict

ED25519 = "ed25519"
MLDSA87 = "mldsa87"


class KeyError_(Exception):
    pass


# --- THE KEY RULE (one function, copied into bin/verify_chain.py and bin/verify_offline.py, which run under -I
# and cannot import this package; tests/test_key_rule.py pins the three sources equal and runs the vectors) ------

_INSTANT_SHAPE = "dddd-dd-ddTdd:dd:ddZ"


def _is_instant(value):
    """Exactly ``YYYY-MM-DDTHH:MM:SSZ`` (ASCII digits only), the one spelling every verifier accepts."""
    return (isinstance(value, str) and len(value) == 20
            and all((c in "0123456789") if m == "d" else c == m for c, m in zip(value, _INSTANT_SHAPE)))


def key_standing(entry, occurred_at, accept_signers=None):
    """None when ``entry`` may be used for a record signed at ``occurred_at``, else the reason. See the module doc."""
    if accept_signers is not None and not accept_signers:
        raise ValueError("an empty accepted-signers set is a configuration error, never 'any'")
    status = entry.get("status")
    if status in ("compromised", "revoked"):
        return "key_revoked"
    if status not in ("active", "retired"):
        return "key_status_unusable"
    valid_from, valid_to = entry.get("valid_from"), entry.get("valid_to")
    if status == "retired" and valid_to is None:
        return "key_status_unusable"  # retired with no end is no standing at all
    if not _is_instant(valid_from) or (valid_to is not None and not _is_instant(valid_to)):
        return "key_window_unreadable"
    if not _is_instant(occurred_at):
        return "signed_instant_unreadable"
    if occurred_at < valid_from or (valid_to is not None and occurred_at >= valid_to):
        return "key_not_valid_at_signing"
    signer = entry.get("signer")  # a list or an object is no label: it is not accepted, and no set is asked for it
    if accept_signers is not None and (isinstance(signer, (list, dict)) or signer not in accept_signers):
        return "signer_not_accepted"
    return None



# --- ED25519 KEY MATERIAL : one text in keys.py, verify_chain.py, bin/lab-verify and bin/lab-log-verify ---
# edwards25519 (RFC 8032 section 5.1): p, the prime group order L, d, and sqrt(-1) = 2^((p-1)/4)
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1)


def _decode_canonical_point(raw: bytes) -> tuple[int, int] | None:
    """RFC 8032 section 5.1.3, strictly: None for y >= p (step 1), no square root (step 3), or x = 0 with
    the sign bit set (step 4)."""
    if len(raw) != 32:
        return None
    n = int.from_bytes(raw, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P  # d is not a square, so d*y^2 + 1 is never 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:  # x = 0 only for y = 1 or p-1, both small order: kept for RFC 8032 conformance
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y


def _add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    """a + b by the complete twisted Edwards addition law (a = -1; RFC 8032 section 5.1.4, affine); also the doubling."""
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return (x1 * y2 + x2 * y1) * pow(1 + t, -1, _P) % _P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P


def _multiply(point: tuple[int, int], n: int) -> tuple[int, int]:
    result = _IDENTITY
    while n:
        if n & 1:
            result = _add(result, point)
        point = _add(point, point)
        n >>= 1
    return result


def ed25519_key_acceptable(raw: bytes) -> bool:
    """A canonical encoding (RFC 8032 5.1.3, strict) of a point of the PRIME-ORDER subgroup other than the identity:
    [L]P is the identity. That refuses the eight small-order points, every non-canonical encoding AND every mixed-order
    point (a prime-order point plus a torsion point), on which verifiers that reduce h mod L (OpenSSL) and verifiers that
    do not (verify_receipt.py) answer differently for the same signature. An honest key a*B is always prime order."""
    point = _decode_canonical_point(raw) if isinstance(raw, (bytes, bytearray)) else None
    return point is not None and point != _IDENTITY and _multiply(point, _L) == _IDENTITY


def ed25519_signature_canonical(signature: bytes) -> bool:
    """64 bytes, R a canonical point encoding (the same strict decode as a key) and S < L. Every verifier in this
    repository refuses a signature that fails this rule. The Python verifier of the published receipt-verification
    release r4 (verify_receipt.py) predates the rule (2026-11-13) and accepts a non-canonical R."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    return _decode_canonical_point(bytes(signature[:32])) is not None and int.from_bytes(signature[32:], "little") < _L


def _occurred_at(envelope):
    """The signed instant of a record: ``occurred_at`` of its strictly parsed signed_payload, else None."""
    try:
        signed = loads_strict(envelope["signed_payload"])
    except (ValueError, KeyError, TypeError):
        return None
    return signed.get("occurred_at") if isinstance(signed, dict) else None


def _parse(data: bytes):
    """(Ed25519 keys, ML-DSA-87 keys, meta) of a key file. EVERY status is held (with its window and signer): what a
    key may sign is the rule's, decided at ``check``, so a retired or revoked key answers with its reason."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: F401
    except ImportError as error:  # fail closed: a configured check that cannot run is refused
        raise KeyError_("the 'cryptography' package is needed for in-process signature checks") from error
    try:
        parsed = loads_strict(data)
    except ValueError as error:
        raise KeyError_(f"key file is not strict JSON: {error}") from error
    entries = parsed.get("entries") if isinstance(parsed, dict) else None
    if not isinstance(entries, list):
        raise KeyError_("key file has no entries list")
    keys: dict[str, bytes] = {}
    ml: dict[str, bytes] = {}
    meta: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("algorithm") not in (ED25519, MLDSA87):
            continue
        pq_entry = entry["algorithm"] == MLDSA87
        key_id = entry.get("key_id")
        try:
            raw = base64.b64decode(entry.get("public_key", ""), validate=True)
        except (binascii.Error, TypeError):
            continue
        size = pq.MLDSA87_PUBLIC_BYTES if pq_entry else 32
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != entry.get("public_key_fingerprint"):
            continue
        if not pq_entry and not ed25519_key_acceptable(raw):  # skipped, as requisition-ts keys.ts:86
            continue
        if key_id in keys or key_id in ml:
            raise KeyError_(f"key file names {key_id!r} twice")
        (ml if pq_entry else keys)[key_id] = raw
        meta[key_id] = {name: entry.get(name) for name in ("status", "valid_from", "valid_to", "signer")}
    return keys, ml, meta


def _signers(accept_signers):
    if accept_signers is None:
        return None
    if isinstance(accept_signers, str):
        raise KeyError_("accept_signers is a set of signer labels, not a string")
    signers = frozenset(accept_signers)
    if not signers:
        raise KeyError_("accept_signers is empty: an empty accepted-signers set is a configuration error, never 'any'")
    return signers


class _Source:
    def __init__(self, path, max_age, clock):
        self.path, self.max_age, self.clock = path, max_age, clock
        self.stamp = None
        self.loaded_at = 0.0
        self.failed = None


class KeyRegistry:
    def __init__(self, entries: dict[str, bytes], mldsa87: dict[str, bytes] | None = None, *,
                 meta: dict[str, dict] | None = None, accept_signers=None):
        for key_id, raw in entries.items():
            if not ed25519_key_acceptable(raw):  # never held, however the registry is built
                raise KeyError_(f"Ed25519 key {key_id!r} is small-order or not a canonical encoding")
        self._keys = entries
        self._mldsa87 = mldsa87 or {}
        self._meta = meta or {}  # a key with no meta has no standing: refused (default deny)
        self.accept_signers = _signers(accept_signers)
        self._source = None
        self._lock = threading.RLock()

    # --- construction ------------------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes, *, accept_signers=None) -> "KeyRegistry":
        keys, ml, meta = _parse(data)
        return cls(keys, ml, meta=meta, accept_signers=accept_signers)

    @classmethod
    def from_file(cls, path: str, *, accept_signers=None, max_age_seconds: float = 300.0,
                  clock=time.time) -> "KeyRegistry":
        """The key file read from ``path`` and re-read when it changes (its mtime, size or inode) or at the latest
        every ``max_age_seconds``, so a retirement or revocation reaches a running gate. A file that cannot be
        read or parsed on a re-read fails CLOSED (every check answers ``key_file_unreadable``) until a good read."""
        if not max_age_seconds > 0:
            raise KeyError_("max_age_seconds must be positive")
        with open(path, "rb") as handle:
            data = handle.read()
        registry = cls.from_bytes(data, accept_signers=accept_signers)
        registry._source = _Source(path, max_age_seconds, clock)
        registry._source.stamp = cls._stamp(path)
        registry._source.loaded_at = clock()
        return registry

    @classmethod
    def from_env(cls, env: dict) -> "KeyRegistry":
        """The entry points' key file: ``REQUISITION_KEYS_FILE`` (required), ``REQUISITION_ACCEPT_SIGNERS`` (comma
        separated signer labels; default ``kms``: KMS custody bounds what verifies; ``any`` lifts it; empty is
        refused) and ``REQUISITION_KEYS_MAX_AGE_SECONDS`` (default 300, the bound on a stale key file)."""
        text = env.get("REQUISITION_ACCEPT_SIGNERS", "kms")
        if text.strip() == "any":
            accept = None
        else:
            accept = [part.strip() for part in text.split(",")]
            if not all(accept):
                raise KeyError_("REQUISITION_ACCEPT_SIGNERS is a comma-separated list of signer labels, or 'any'")
        return cls.from_file(env["REQUISITION_KEYS_FILE"], accept_signers=accept,
                             max_age_seconds=float(env.get("REQUISITION_KEYS_MAX_AGE_SECONDS", "300")))

    @staticmethod
    def _stamp(path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _refresh(self):
        source = self._source
        if source is None:
            return
        with self._lock:
            stamp = self._stamp(source.path)
            if stamp == source.stamp and source.clock() - source.loaded_at < source.max_age:
                return
            try:
                with open(source.path, "rb") as handle:
                    keys, ml, meta = _parse(handle.read())
            except (OSError, KeyError_) as error:
                source.failed = str(error)
                self._keys, self._mldsa87, self._meta = {}, {}, {}
            else:
                source.failed = None
                self._keys, self._mldsa87, self._meta = keys, ml, meta
            source.stamp, source.loaded_at = stamp, source.clock()

    # --- queries -----------------------------------------------------------------------------------

    def algorithm(self, key_id: str) -> str | None:
        self._refresh()
        if key_id in self._keys:
            return ED25519
        if key_id in self._mldsa87:
            return MLDSA87
        return None

    def status_of(self, key_id: str) -> str | None:
        self._refresh()
        return (self._meta.get(key_id) or {}).get("status")

    def pq_expected(self, envelope: dict) -> bool:
        """True when the pinned file holds an ML-DSA-87 key of the SAME signer as the record's key that was
        usable at the record's signed instant: the file says this signer signs post-quantum, whatever the record's
        own ``cosign`` member claims."""
        self._refresh()
        mine = self._meta.get(envelope.get("key_id"))
        at = _occurred_at(envelope)
        if mine is None or at is None:
            return False
        return any(key_id in self._mldsa87 and meta.get("signer") == mine.get("signer")
                   and key_standing(meta, at) is None for key_id, meta in self._meta.items())

    def check(self, envelope: dict) -> str | None:
        """None when the record's signature verifies under a key the rule lets sign at its signed instant, else the
        reason (the rule's, or ``unknown_key``, ``signature_invalid``, ``key_file_unreadable``)."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        self._refresh()
        if self._source is not None and self._source.failed is not None:
            return "key_file_unreadable"
        if not isinstance(envelope, dict):
            return "signature_invalid"
        key_id = envelope.get("key_id")
        ml_raw = self._mldsa87.get(key_id)
        raw = self._keys.get(key_id)
        if ml_raw is None and raw is None:
            return "unknown_key"
        reason = key_standing(self._meta.get(key_id) or {}, _occurred_at(envelope), self.accept_signers)
        if reason is not None:
            return reason
        try:
            signature = base64.b64decode(envelope.get("signature", ""), validate=True)
            message = envelope["signed_payload"].encode("utf-8")
            if ml_raw is not None:
                return None if pq.verify_mldsa87(ml_raw, signature, message) else "signature_invalid"
            if not ed25519_signature_canonical(signature):
                return "signature_invalid"
            Ed25519PublicKey.from_public_bytes(raw).verify(signature, message)
            return None
        except (InvalidSignature, binascii.Error, ValueError, TypeError, KeyError, AttributeError):
            return "signature_invalid"

    def verify(self, envelope: dict) -> bool:
        return self.check(envelope) is None
