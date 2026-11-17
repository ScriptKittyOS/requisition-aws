#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""verify_chain.py -- a stranger's offline check of one Requisition lab ACCOUNT chain export against
signed records kept outside it (F1b).

    python3 -I bin/verify_chain.py --registry LAB-KEYS.json --export EXPORT [--held FILE]... \
        [--require-pq] [--json]

EXPORT      one account chain's stored rows, ordered by sequence: the CSV bin/export_chain.sh writes
            (header chain_scope,sequence,signature,key_id,signed_payload,receipt_hash,cosignature,
            cosignature_key_id) or JSON {"records": [row, ...]} (or a bare list), each row a four-field
            envelope or {"record": envelope, "cosignature": envelope}. Every position is read from the
            SIGNED payload (requisition schema/lab_receipt.ex: signed_payload is authoritative); the
            other columns are lookup copies and are not trusted.
--held FILE signed records kept outside the store: an envelope; {"record"|"statement"|"decision":
            envelope, "cosignature": ...}; a list of those; {"records": [...]}; or a relying party's
            equivocation evidence entry {"held": envelope, "presented": envelope} (or {"evidence":
            [entries]}, as requisition_aws.Store.evidence() returns them). Identical copies are one.
LAB-KEYS    the key file GET /v1/keys serves (lab keys: NOT a trust root). THE KEY RULE (one rule in
            every verifier, requisition lib/autonomous_agency/authority/execute_api/lab_key_rule.ex is its text and
            tests/vectors/key_rule_vectors.v1.json its vectors): a record verifies under a key iff, in this order,
            the key is not compromised/revoked (key_revoked), is active or retired (key_status_unusable), has a
            readable window (key_window_unreadable; a retired key needs a valid_to), the record's signed occurred_at
            is readable (signed_instant_unreadable) and lies in valid_from <= occurred_at < valid_to
            (key_not_valid_at_signing), and, under --accept-signer, the key's signer is accepted
            (signer_not_accepted). A refused KEY is a trust refusal under that name, never signature_invalid (which
            accuses the record); an honest rotated history verifies.
--accept-signer LABEL   (repeatable) refuse any record whose key entry's signer is not one of the labels
            (--accept-signer kms bounds what verifies by KMS custody). Default: any signer.

Signatures: Ed25519 by bin/vendor/ed25519_rfc8032.py (a pinned byte copy of the Ed25519 routine of the
receipt verifier published in receipt-verification r4); ML-DSA-87 by bin/vendor/mldsa.py (pinned). Both are loaded by path and refused unless
their SHA-256 is the pinned one (bin/vendor/VENDORED.md).

--require-pq: every AGENT-TOOL record -- one whose signed metadata carries "cosign" (requisition
lab_records.ex:44-64: only an agent-tool row's statement, decision and outcome; every other record has
none) -- needs a valid ML-DSA-87 signature over its own bytes (its own, or the co-signature whose bytes,
hash and key id match the signed cosign member). Other records are reported "Ed25519 only".

Account scopes only (requisition-lab:account:<id>): permit chains may legitimately skip sequences, so
any other scope is refused (exit 2).

FAIL codes (each names its records; a pair names both):
  link_broken             a row's signed previous_hash is not the SHA-256 of the row before it
  sequence_gap            a sequence is missing between two rows
  sequence_duplicate      two rows at one sequence
  export_not_from_genesis the first row is not sequence 1 with previous_hash null
  held_record_differs     the export's record at a held record's position is another one (or none)
  export_short            the export ends before a held record's sequence
  equivocation            two VALID signed records at one position (held + export, within the export,
                          or within held): the signer signed two histories
  signature_invalid       an export row whose hash, key or signature does not verify
  key_revoked, key_status_unusable, key_window_unreadable, signed_instant_unreadable, key_not_valid_at_signing,
  signer_not_accepted     an export row whose KEY the rule above refuses (the signature was not judged)
  key_not_prime_order     an export row whose Ed25519 key is not a canonical prime-order point ([L]P is the identity: no small-order
                          and no mixed-order key); a signature with a non-canonical R or S >= L is signature_invalid
  registry_duplicate_key  an export row whose key_id the key file names more than once (a registry fault, not a bad signature)
  held_record_invalid     a held record that does not verify (it accuses nothing)
  held_other_scope        a held record of another chain scope (never a silent pass)
  pq_missing              under --require-pq, an agent-tool record without a valid ML-DSA-87 signature
Result "ok" when there is none.

WHAT IT JUDGES: the export it is given. A stranger needs the operator's export or a relying party's held
records; an operator who hands over an old dump passes against nothing newer. A claim about the live
service waits for checkpoints. Lab profile, lab key: two records at one position prove that the
holder of that key signed two histories.

EXIT: 0 ok; 1 FAIL; 2 usage, an unreadable input, or a scope that is not an account chain.
Standard library and the two pinned vendored files only.
"""

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import os
import re
import sys
import types

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
ENVELOPE = ("signature", "key_id", "signed_payload", "receipt_hash")
ACCOUNT_SCOPE = re.compile(r"\Arequisition-lab:account:[A-Za-z0-9-]{1,64}\Z")
VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
MLDSA_PATH = os.path.join(VENDOR, "mldsa.py")
MLDSA_SHA256 = "0e8885d01ed76919f3152caa160f90949c03efc6a3748865aaf4beb2737c7a4a"
ED25519_PATH = os.path.join(VENDOR, "ed25519_rfc8032.py")
ED25519_SHA256 = "cef4cb15f0f6f2b820c4cb06a3df6abd35352adcbaf26c93e836a928403a096e"
MLDSA87_PUBLIC_BYTES, MLDSA87_SIGNATURE_BYTES = 2592, 4627


class Usage(Exception):
    pass


# --- THE KEY RULE: a byte copy of requisition_aws/keys.py's (this file runs under -I and cannot import the
# package; tests/test_key_rule.py pins the sources equal and runs the shared vectors against both) ---------------

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


# --- ED25519 KEY MATERIAL: one text in keys.py, verify_chain.py, bin/lab-verify and bin/lab-log-verify ---
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


# --- the pinned vendored verifiers ---------------------------------------------------------------


def load_pinned(path, pinned, name):
    """Load a vendored file by path (python -I does not put this directory on sys.path), refusing it
    unless its bytes hash to the pinned SHA-256."""
    with open(path, "rb") as handle:
        source = handle.read()
    if hashlib.sha256(source).hexdigest() != pinned:
        raise Usage("%s is not the pinned file (sha256 %s)" % (os.path.relpath(path), pinned))
    module = types.ModuleType(name)
    module.__file__ = path
    sys.modules[name] = module  # dataclasses look the module up while the class is built
    exec(compile(source, path, "exec"), module.__dict__)
    return module


class Verifiers:
    def __init__(self, registry, accept_signers=None):
        self.registry = registry
        self.accept_signers = accept_signers
        self._ed = None
        self._ml = None

    @property
    def ed(self):
        if self._ed is None:
            self._ed = load_pinned(ED25519_PATH, ED25519_SHA256, "requisition_vendored_ed25519")
        return self._ed

    @property
    def ml(self):
        if self._ml is None:
            self._ml = load_pinned(MLDSA_PATH, MLDSA_SHA256, "requisition_vendored_mldsa")
        return self._ml

    def entries_named(self, key_id):
        entries = self.registry.get("entries") if isinstance(self.registry, dict) else None
        return [e for e in entries if isinstance(e, dict) and e.get("key_id") == key_id] if isinstance(entries, list) else []

    def entry(self, key_id):
        found = self.entries_named(key_id)
        return found[0] if len(found) == 1 else None

    def check(self, envelope):
        """(ok, algorithm, why): the envelope's own hash, key entry and signature."""
        ok, algorithm, why, _code = self.check_ex(envelope)
        return ok, algorithm, why

    def check_ex(self, envelope):
        """(ok, algorithm, why, code): code is the KEY RULE's reason when the key (not the record) is refused."""
        if hashlib.sha256(envelope["signed_payload"].encode("utf-8")).hexdigest() != envelope["receipt_hash"]:
            return False, None, "receipt_hash is not the SHA-256 of signed_payload", None
        named = self.entries_named(envelope["key_id"])
        if len(named) > 1:
            return False, None, "key %r is named %d times in the key file: a registry fault, not a bad signature" % (
                envelope["key_id"], len(named)), "registry_duplicate_key"
        if not named:
            return False, None, "key %r is not in the key file" % envelope["key_id"], None
        entry = named[0]
        reason = key_standing(entry, self._occurred_at(envelope), self.accept_signers)
        if reason is not None:
            return False, None, "key %r is refused by the key rule: %s (status %r, signer %r)" % (
                envelope["key_id"], reason, entry.get("status"), entry.get("signer")), reason
        raw = _b64(entry.get("public_key"))
        if raw is None or (entry.get("public_key_fingerprint") is not None
                           and hashlib.sha256(raw).hexdigest() != entry.get("public_key_fingerprint")):
            return False, None, "key %r: public_key does not hash to its fingerprint" % envelope["key_id"], None
        signature = _b64(envelope["signature"])
        message = envelope["signed_payload"].encode("utf-8")
        algorithm = entry.get("algorithm")
        if algorithm == "ed25519":
            if not ed25519_key_acceptable(raw):
                return False, algorithm, "key %r is not a canonical prime-order Ed25519 public key" % envelope["key_id"], "key_not_prime_order"
            ok = (signature is not None and ed25519_signature_canonical(signature)
                  and self.ed.ed25519_verify(signature, message, raw))
        elif algorithm == "mldsa87":
            ok = signature is not None and len(raw) == MLDSA87_PUBLIC_BYTES and len(signature) == MLDSA87_SIGNATURE_BYTES
            if ok:
                try:
                    self.ml.VerificationKey(raw, parameters=self.ml.ParameterSet.ML_DSA_87).verify(signature, message)
                except (self.ml.VerificationError, ValueError):
                    ok = False
        else:
            return False, algorithm, "key %r: algorithm %r is neither ed25519 nor mldsa87" % (envelope["key_id"], algorithm), None
        return bool(ok), algorithm, None if ok else "the %s signature does not verify under %s" % (algorithm, envelope["key_id"]), None

    @staticmethod
    def _occurred_at(envelope):
        try:
            signed = _json(envelope["signed_payload"])
        except ValueError:
            return None
        return signed.get("occurred_at") if isinstance(signed, dict) else None


def _b64(text):
    if not isinstance(text, str):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


# --- reading inputs ------------------------------------------------------------------------------


def _no_dupes(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate member %r" % k)
        seen[k] = v
    return seen


def _no_constant(name):
    raise ValueError("%s is not JSON (RFC 8259 section 6)" % name)


def _finite_float(lexeme):
    value = float(lexeme)
    if value in (float("inf"), float("-inf")):  # 1e400: a valid lexeme, never an infinite float here
        raise ValueError("a number outside the double range (RFC 8259 section 9 limit)")
    return value


MAX_DEPTH = 64  # containers; the 65th is refused (requisition-ts src/json.ts MAX_DEPTH; lab_key_rule.ex decode_bounded/1)
MAX_INTEGER = 9_007_199_254_740_991  # CanonicalPayload v3's integer range (canonical.MAX_INTEGER)


def _check_depth(text):
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting deeper than %d" % MAX_DEPTH)
        elif ch in "]}":
            depth -= 1


def _bounded_int(lexeme):
    value = int(lexeme)
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        raise ValueError("an integer outside +-(2^53-1), the canonical form's range")
    return value


def loads_strict(data):
    """requisition_aws.client.loads_strict's rule, copied (this file runs under -I and cannot import the
    package; tests/test_cli_strict_json.py pins the two equal): duplicate members, NaN/Infinity/-Infinity
    and numbers that are not finite doubles refused; bytes decoded as strict UTF-8 (no UTF-16/32 detection,
    no surrogatepass); a BOM refused; nesting deeper than MAX_DEPTH (64) containers and an integer outside
    +-(2^53-1) refused. Every refusal is a ValueError."""
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    _check_depth(data)
    return json.loads(data, object_pairs_hook=_no_dupes, parse_constant=_no_constant, parse_float=_finite_float, parse_int=_bounded_int)


def _json(text):
    return loads_strict(text)


def _is_envelope(obj):
    return isinstance(obj, dict) and all(isinstance(obj.get(k), str) for k in ENVELOPE)


def _row(obj):
    """A row/record form -> {"record", "cosignature"} or None."""
    if _is_envelope(obj):
        return {"record": {k: obj[k] for k in ENVELOPE}, "cosignature": None}
    if isinstance(obj, dict):
        for name in ("record", "statement", "decision"):
            if _is_envelope(obj.get(name)):
                cos = obj.get("cosignature")
                return {"record": {k: obj[name][k] for k in ENVELOPE},
                        "cosignature": {k: cos[k] for k in ENVELOPE} if _is_envelope(cos) else None}
    return None


def _rows_of(obj, where, allow_evidence):
    if isinstance(obj, dict) and "records" in obj and isinstance(obj["records"], list):
        obj = obj["records"]
    elif allow_evidence and isinstance(obj, dict) and isinstance(obj.get("evidence"), list):
        obj = obj["evidence"]
    items = obj if isinstance(obj, list) else [obj]
    rows = []
    for item in items:
        if allow_evidence and isinstance(item, dict) and _is_envelope(item.get("held")) and _is_envelope(item.get("presented")):
            rows += [_row(item["held"]), _row(item["presented"])]
            continue
        row = _row(item)
        if row is None:
            raise Usage("%s: an item is not a signed record form" % where)
        rows.append(row)
    return rows


def read_export(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        text = handle.read()
    if text.lstrip().startswith(("{", "[")):
        try:
            return _rows_of(_json(text), path, allow_evidence=False)
        except ValueError as error:
            raise Usage("%s: not JSON (%s)" % (path, error)) from None
    reader = csv.DictReader(io.StringIO(text, newline=""))  # newlines inside quoted payloads kept
    need = {"signature", "key_id", "signed_payload", "receipt_hash"}
    if reader.fieldnames is None or not need <= set(reader.fieldnames):
        raise Usage("%s: neither the JSON form nor the export CSV (header %s)" % (path, ",".join(sorted(need))))
    rows = []
    for line in reader:
        record = {k: line[k] for k in ENVELOPE}
        cos = None
        if line.get("cosignature"):
            cos = {"signature": line["cosignature"], "key_id": line.get("cosignature_key_id") or "",
                   "signed_payload": record["signed_payload"], "receipt_hash": record["receipt_hash"]}
        rows.append({"record": record, "cosignature": cos})
    return rows


def read_held(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return _rows_of(_json(handle.read()), path, allow_evidence=True)
    except ValueError as error:
        raise Usage("%s: not JSON (%s)" % (path, error)) from None


# --- the checks ----------------------------------------------------------------------------------


class Item:
    """One record as read: its position from the signed bytes, its checks."""

    def __init__(self, row, source, verifiers, require_pq):
        self.record, self.cosignature, self.source = row["record"], row["cosignature"], source
        self.hash = self.record["receipt_hash"]
        self.actual_hash = hashlib.sha256(self.record["signed_payload"].encode("utf-8")).hexdigest()
        self.scope = self.sequence = self.previous_hash = None
        self.signed = None
        try:
            signed = _json(self.record["signed_payload"])
            if isinstance(signed, dict):
                self.signed = signed
                self.scope = signed.get("chain_scope") if isinstance(signed.get("chain_scope"), str) else None
                seq = signed.get("sequence")
                self.sequence = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
                self.previous_hash = signed.get("previous_hash")
        except ValueError:
            pass
        self.valid, self.algorithm, self.why, self.refusal = verifiers.check_ex(self.record)
        if self.valid and (self.scope is None or self.sequence is None):
            self.valid, self.why = False, "the signed payload carries no chain position"
        md = self.signed.get("metadata") if self.signed and isinstance(self.signed.get("metadata"), dict) else {}
        if self.valid and md.get("key_id") is not None and md.get("key_id") != self.record["key_id"]:
            self.valid, self.why = False, "the signed metadata key_id is not the envelope's key_id"
        self.cosign = md.get("cosign") if isinstance(md.get("cosign"), dict) else None
        self.agent_tool = self.cosign is not None
        self.pq, self.pq_why = self._pq(verifiers) if (require_pq and self.valid) else (None, None)

    def _pq(self, verifiers):
        if self.algorithm == "mldsa87":
            return True, None
        if not self.agent_tool:
            return None, "Ed25519 only (not an agent-tool record)"
        status = self.cosign.get("status")
        if status != "signed":
            return False, "the signed cosign.status is %r: Ed25519 only" % status
        cos = self.cosignature
        if cos is None:
            return False, "the signed cosign.status is 'signed' but no co-signature came with the record (stripped)"
        if cos["signed_payload"] != self.record["signed_payload"] or cos["receipt_hash"] != self.record["receipt_hash"]:
            return False, "the co-signature does not cover the record's own bytes"
        if cos["key_id"] != self.cosign.get("key_id"):
            return False, "the co-signature's key_id is not the signed cosign.key_id"
        ok, algorithm, why = verifiers.check(cos)
        if not ok or algorithm != "mldsa87":
            return False, why or "the co-signature's key is not an mldsa87 key"
        return True, None

    def brief(self):
        return {**self.record, **({"cosignature": self.cosignature} if self.cosignature else {}),
                "source": self.source}


class Report:
    def __init__(self):
        self.failures = []
        self.notes = []
        self._pairs = set()

    def fail(self, code, sequence, detail, items):
        self.failures.append({"code": code, "sequence": sequence, "detail": detail,
                              "records": [i.brief() for i in items]})

    def equivocation(self, sequence, a, b, where):
        key = frozenset((a.hash, b.hash))
        if key in self._pairs:
            return
        self._pairs.add(key)
        self.fail("equivocation", sequence, "two valid records signed at sequence %d (%s): the signer signed two "
                  "histories" % (sequence, where), [a, b])


def verify(export_rows, held_rows, verifiers, require_pq):
    report = Report()
    export = [Item(r, "export", verifiers, require_pq) for r in export_rows]
    if not export:
        raise Usage("the export holds no record")
    scopes = {i.scope for i in export if i.scope is not None}
    if len(scopes) != 1:
        raise Usage("the export must hold exactly one chain scope (found %d)" % len(scopes))
    (scope,) = scopes
    if not ACCOUNT_SCOPE.match(scope):
        raise Usage("chain scope %r is not an account chain (requisition-lab:account:<id>); permit chains may skip "
                    "sequences, so this check refuses them" % scope)

    for item in export:
        if not item.valid:
            report.fail(item.refusal or "signature_invalid", item.sequence, item.why, [item])
        elif item.pq is False:
            report.fail("pq_missing", item.sequence, item.pq_why, [item])
        elif item.pq is None and item.pq_why:
            report.notes.append("sequence %s: %s" % (item.sequence, item.pq_why))

    placed = sorted((i for i in export if i.sequence is not None), key=lambda i: i.sequence)
    if not placed:
        raise Usage("no export row carries a signed chain position")
    by_seq = {}
    for item in placed:
        by_seq.setdefault(item.sequence, []).append(item)
    first = placed[0]
    if first.sequence != 1 or first.previous_hash is not None:
        report.fail("export_not_from_genesis", first.sequence,
                    "the export starts at sequence %s with previous_hash %s, not at 1 with null"
                    % (first.sequence, "null" if first.previous_hash is None else first.previous_hash[:16] + "..."),
                    [first])
    sequences = sorted(by_seq)
    for before, seq in zip(sequences, sequences[1:]):
        if seq > before + 1:
            report.fail("sequence_gap", before + 1, "no record at sequence %d..%d" % (before + 1, seq - 1),
                        [by_seq[before][-1], by_seq[seq][0]])
    for seq in sequences:
        group = by_seq[seq]
        if len(group) > 1:
            report.fail("sequence_duplicate", seq, "%d rows at sequence %d" % (len(group), seq), group)
            valid = [i for i in group if i.valid]
            for a_index, a in enumerate(valid):
                for b in valid[a_index + 1:]:
                    if a.hash != b.hash:
                        report.equivocation(seq, a, b, "within the export")
        previous = by_seq.get(seq - 1)
        if previous:
            linked = {p.actual_hash for p in previous}
            for item in group:
                if item.previous_hash not in linked:
                    report.fail("link_broken", seq, "sequence %d names previous_hash %s, which is not the SHA-256 of "
                                "the row before it" % (seq, str(item.previous_hash)[:16] + "..."), previous + [item])

    held, seen = [], set()
    for path, rows in held_rows:
        for row in rows:
            same = json.dumps(row["record"], sort_keys=True)  # identical copies of one record are one
            if same in seen:
                continue
            seen.add(same)
            held.append(Item(row, "held:" + os.path.basename(path), verifiers, require_pq))
    good = []
    for item in held:
        if not item.valid:
            report.fail("held_record_invalid", item.sequence, item.why + " (it accuses nothing)", [item])
            continue
        if item.scope != scope:
            report.fail("held_other_scope", item.sequence, "held record of scope %r, not the export's %r"
                        % (item.scope, scope), [item])
            continue
        if item.pq is False:
            report.fail("pq_missing", item.sequence, item.pq_why, [item])
        good.append(item)
    head = sequences[-1]
    for item in good:
        if item.sequence > head:
            report.fail("export_short", item.sequence, "the export ends at sequence %d, before this held record's %d"
                        % (head, item.sequence), [item])
            continue
        there = by_seq.get(item.sequence, [])
        if any(i.hash == item.hash and i.valid for i in there):
            continue
        report.fail("held_record_differs", item.sequence, "the export's record at sequence %d is not the held one"
                    % item.sequence if there else "the export has no record at held sequence %d" % item.sequence,
                    [item] + there)
        for other in there:
            if other.valid:
                report.equivocation(item.sequence, item, other, "held + export")
    for a_index, a in enumerate(good):
        for b in good[a_index + 1:]:
            if a.sequence == b.sequence and a.hash != b.hash:
                report.equivocation(a.sequence, a, b, "within held")
    return scope, report


# --- main ----------------------------------------------------------------------------------------


def _signer_label(value):
    if not value:
        raise argparse.ArgumentTypeError("an empty signer label is a configuration error")
    return value


def main(argv):
    parser = argparse.ArgumentParser(prog="verify_chain.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--registry", required=True)
    parser.add_argument("--export", required=True)
    parser.add_argument("--held", action="append", default=[])
    parser.add_argument("--require-pq", action="store_true")
    parser.add_argument("--accept-signer", action="append", default=None, metavar="LABEL", type=_signer_label)
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return EXIT_USAGE if exit_.code else EXIT_OK
    try:
        with open(args.registry, "r", encoding="utf-8") as handle:
            registry = _json(handle.read())
        verifiers = Verifiers(registry, None if args.accept_signer is None else frozenset(args.accept_signer))
        export_rows = read_export(args.export)
        held_rows = [(path, read_held(path)) for path in args.held]
        scope, report = verify(export_rows, held_rows, verifiers, args.require_pq)
    except (Usage, OSError, ValueError) as error:
        sys.stderr.write("verify_chain: %s\n" % error)
        return EXIT_USAGE
    except Exception as error:  # noqa: BLE001 - an input this file did not foresee: never exit 1 (FAIL) on it
        sys.stderr.write("verify_chain: unreadable input (%s: %s)\n" % (type(error).__name__, error))
        return EXIT_USAGE
    result = "ok" if not report.failures else "FAIL"
    if args.json:
        sys.stdout.write(json.dumps({"result": result, "chain_scope": scope, "failures": report.failures,
                                     "notes": report.notes, "export_rows": len(export_rows),
                                     "held_records": sum(len(r) for _, r in held_rows),
                                     "require_pq": args.require_pq}, indent=1) + "\n")
    else:
        print("chain scope: %s (%d export rows, %d held records)" % (scope, len(export_rows),
                                                                      sum(len(r) for _, r in held_rows)))
        for note in report.notes:
            print("note: " + note)
        for f in report.failures:
            print("FAIL %s at sequence %s: %s" % (f["code"], f["sequence"], f["detail"]))
            for r in f["records"]:
                print("    %s receipt_hash %s (%s)" % (f["code"], r["receipt_hash"], r["source"]))
        print("RESULT " + result)
    return EXIT_OK if result == "ok" else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
