# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Builders for the key-rule vector tests: ONE vector file (tests/vectors/key_rule_vectors.v1.json, a byte copy
of requisition's key-rule vector file; the pin is tests/test_key_rule.py) becomes real signed
records under real keys, so every verifier is asked the same question with a signature that is valid."""

import base64
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

VECTOR_FILE = pathlib.Path(__file__).parent / "vectors" / "key_rule_vectors.v1.json"
SCOPE = "requisition-lab:account:vec"


def load_vectors():
    return json.loads(VECTOR_FILE.read_text())["vectors"]


_KEYS = {}


def _key(algorithm):
    """One key per algorithm per process: ML-DSA-87 key generation is not free."""
    if algorithm not in _KEYS:
        if algorithm == "ed25519":
            private = Ed25519PrivateKey.generate()
            _KEYS[algorithm] = (private, private.public_key().public_bytes_raw())
        else:
            private = MLDSA87PrivateKey.generate()
            _KEYS[algorithm] = (private, private.public_key().public_bytes_raw())
    return _KEYS[algorithm]


def build(vector, algorithm="ed25519", key_id=None):
    """(registry_dict, envelope) for one vector. A null member of the vector's entry is ABSENT from the key entry."""
    private, raw = _key(algorithm)
    key_id = key_id or ("requisition_lab_vec_%s_v0" % algorithm)
    entry = {"key_id": key_id, "algorithm": algorithm, "public_key": base64.b64encode(raw).decode("ascii"),
             "public_key_fingerprint": hashlib.sha256(raw).hexdigest(), "profile": "lab"}
    for name, value in vector["entry"].items():
        if name == "valid_to" or value is not None:
            entry[name] = value
    payload = {"chain_scope": SCOPE, "sequence": 1, "previous_hash": None,
               "receipt_type": "requisition.lab.statement.v0", "subject_type": "x", "subject_id": "x",
               "status": "ok", "payload_hash": None, "schema_version": "agent_receipt.v1",
               "metadata": {"key_id": key_id, "signer": vector["entry"].get("signer")}}
    if vector["occurred_at"] is not None:
        payload["occurred_at"] = vector["occurred_at"]
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    envelope = {"signature": base64.b64encode(private.sign(text.encode("utf-8"))).decode("ascii"), "key_id": key_id,
                "signed_payload": text, "receipt_hash": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    return {"schema": "requisition_lab_key_file.v1", "entries": [entry]}, envelope
