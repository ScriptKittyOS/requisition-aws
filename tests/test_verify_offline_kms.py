# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Requisition's lab records signed by AWS KMS keys: bin/verify_offline.py over a record whose signed metadata says signer kms.

Requisition's bin/lab-verify answers such a record verdict_code lab_kms_key, and a
signer-dev record lab_dev_key. This file's claims:

  * a signer-kms record passes only with lab_kms_key, and its PASS line prints the record's signed
    kms_key_arn as a key the key file pins as an AWS KMS key, saying KMS custody is the key file's
    statement, not checked offline -- never "dev keys served by the lab";
  * the code must match the record's signed signer: lab_dev_key for a signer-kms record, or
    lab_kms_key for a signer-dev record, is a FAIL (exit 3);
  * a signer-dev record is unchanged (lab_dev_key, its PASS line as before).

The KMS-labelled record is the fake's own statement re-signed by the fake's Ed25519 key with the KMS
labels (signer kms, kms_key_arn, a KMS key id), the key file given an entry for that id with signer
kms: the shape Requisition's LabRecords writes under REQUISITION_LAB_SIGNER=kms (lab_records.ex
labels/1). The real-lab-verify test runs the committed copy of Requisition's bin/lab-verify
(tests/fixtures/requisition/); the two mismatch tests use a stub lab-verify.
"""

import base64
import copy
import hashlib
import json
import subprocess
import sys

import pytest

from requisition_aws.gate import arguments_object

from .conftest import ACT_TYPE, refund_args
from .test_verify_offline import LAB_VERIFY, SCRIPT, vo

ARN = "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
KMS_KEY_ID = "requisition_lab_kms_ed25519_1234abcd-12ab-34cd-56ef-1234567890ab"

@pytest.fixture
def kms(gate, fake, tmp_path):
    """A statement and a key file: the fake's, and the same statement re-signed as a KMS record."""
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    envelope = vo.envelope_of(s.statement)

    signed = json.loads(envelope["signed_payload"])
    signed["metadata"].update({"signer": "kms", "kms_key_arn": ARN, "key_id": KMS_KEY_ID})
    payload = vo.encode(signed).decode("utf-8")
    kms_envelope = {
        "signature": base64.b64encode(fake.key.sign(payload.encode("utf-8"))).decode(),
        "key_id": KMS_KEY_ID,
        "signed_payload": payload,
        "receipt_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }
    registry = copy.deepcopy(fake.registry)
    entry = dict(registry["entries"][0], key_id=KMS_KEY_ID, signer="kms")
    registry["entries"].append(entry)

    paths = {}
    for name, obj in {"args": args, "dev": envelope, "kms": kms_envelope, "registry": registry}.items():
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(obj))
    return paths


def stub(tmp_path, code):
    """A lab-verify that answers exit 5 with `code`, whatever it is given."""
    path = tmp_path / f"stub-{code}.py"
    path.write_text("import sys\nprint('stub\\n\\nverdict_code: %s')\nsys.exit(5)\n" % code)
    return path


def run(paths, record, lab_verify):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(paths["args"]), "--act-type", ACT_TYPE,
         "--record", str(paths[record]), "--lab-verify", str(lab_verify), "--registry", str(paths["registry"])],
        capture_output=True, text=True, timeout=120,
    )


def test_a_kms_record_passes_with_lab_kms_key_and_names_the_pinned_kms_key(kms):
    proc = run(kms, "kms", LAB_VERIFY)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "lab-verify exit 5, verdict_code lab_kms_key" in proc.stdout
    assert "the key file pins as AWS KMS keys %s" % ARN in proc.stdout
    assert "KMS custody is the key file's statement, not checked offline" in proc.stdout
    assert "dev keys" not in proc.stdout


def test_a_kms_record_answered_lab_dev_key_fails(kms, tmp_path):
    proc = run(kms, "kms", stub(tmp_path, "lab_dev_key"))
    assert proc.returncode == 3, proc.stdout
    assert "verdict: FAIL (lab-verify did not answer lab_kms_key" in proc.stdout


def test_a_dev_record_answered_lab_kms_key_fails(kms, tmp_path):
    proc = run(kms, "dev", stub(tmp_path, "lab_kms_key"))
    assert proc.returncode == 3, proc.stdout
    assert "verdict: FAIL (lab-verify did not answer lab_dev_key" in proc.stdout


def test_a_dev_record_answered_lab_dev_key_passes_as_before(kms, tmp_path):
    proc = run(kms, "dev", stub(tmp_path, "lab_dev_key"))
    assert proc.returncode == 0, proc.stdout
    assert "dev keys served by the lab" in proc.stdout and "AWS KMS" not in proc.stdout


# the signer read must not crash on a record the
# binding already refused. Two shapes: (a) a receipt_hash that does not match and
# a signed_payload with a duplicate member; (b) a signed_payload that is a JSON array. Each must end in
# the clean "verdict: FAIL" with exit 1, never a traceback (with and without --require-pq).
@pytest.mark.parametrize(
    "payload, matching_hash, extra",
    [
        ('{"metadata":{"signer":"kms","signer":"dev"}}', False, []),
        ('{"metadata":{"signer":"kms","signer":"dev"}}', False, ["--require-pq"]),
        ("[]", True, []),
    ],
    ids=["dup-member-hash-mismatch", "dup-member-hash-mismatch-require-pq", "array-payload"],
)
def test_a_record_the_binding_refuses_fails_cleanly_never_a_traceback(kms, tmp_path, payload, matching_hash, extra):
    record = {
        "signature": base64.b64encode(b"\0" * 64).decode(),
        "key_id": KMS_KEY_ID,
        "signed_payload": payload,
        "receipt_hash": hashlib.sha256(payload.encode()).hexdigest() if matching_hash else "0" * 64,
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(record))
    proc = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(kms["args"]), "--act-type", ACT_TYPE,
         "--record", str(path), "--lab-verify", str(stub(tmp_path, "lab_kms_key")),
         "--registry", str(kms["registry"])] + extra,
        capture_output=True, text=True, timeout=120,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "verdict: FAIL" in proc.stdout, out
    assert "Traceback" not in out, out
