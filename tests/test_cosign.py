# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""ML-DSA-87 co-signatures and outcome records, against FIXTURES BUILT FROM THE PLANNED SHAPES:
the fake signs them (cosign="signed", "seat_absent", "signed_bytes_over_bound")."""

import base64
import copy
import hashlib
import json
import subprocess
import sys

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate, RecordInvalid, arguments_object
from requisition_aws.keys import KeyRegistry
from requisition_aws.store import Store

from .conftest import ACT_TYPE, refund_args
from .fake_requisition import FakeRequisition, MLDSA_KEY_ID
from .test_canonical import SEED_SCHEMA
from .test_key_rule import _sources
from .test_pass_lines import PASS_LINE
from .test_verify_offline import LAB_VERIFY, SCRIPT, vo

pytestmark = pytest.mark.skipif(
    not hasattr(__import__("cryptography.hazmat.primitives.asymmetric", fromlist=["mldsa"]), "mldsa"),
    reason="cryptography without ML-DSA")


def server_for(clock, cosign, newer_routes=True):
    s = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=newer_routes, cosign=cosign)
    s.base_url = s.start()
    return s


def gate_for(server, tmp_path, clock, **kw):
    client = Client(server.base_url, server.credential, server.principal, timeout=5)
    return Gate(client, Store(str(tmp_path / "store.json"), clock=clock), approval_base_url="http://x",
                keys=KeyRegistry.from_bytes(client.keys()), clock=clock, **kw)


def flow(server, gate):
    args = arguments_object("refund-agent", "s-co", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    server.approve(s.request_id)
    s = gate.read(s, args)
    d = gate.execute(s, args, "nonce-co")
    return args, s, d


@pytest.fixture
def signed(tmp_path, clock):
    server = server_for(clock, "signed")
    try:
        gate = gate_for(server, tmp_path, clock, require_pq=True)
        args, s, d = flow(server, gate)
        assert d.allowed and d.pq_checked
        assert gate.report_outcome(d, True, "REFUND SENT") == "recorded"
        paths = {"args": args, "registry": server.registry, "decision": d.response,
                 "statement": {"statement": s.statement, "cosignature": s.cosignature},
                 "outcome": {"record": gate.outcome_records[0]["record"], "cosignature": gate.outcome_records[0]["cosignature"]}}
        out = {}
        for name, obj in paths.items():
            out[name] = tmp_path / f"{name}.json"
            out[name].write_text(json.dumps(obj))
        yield out, server
    finally:
        server.stop()


def pass_verdict(stdout):
    """The verdict line of a pass: the line the fixed sentence follows. After the sentence come only the lines about
    the deadline the record signs (tests/test_pass_lines.py pins each of them)."""
    lines = stdout.splitlines()
    assert lines.count(PASS_LINE) == 1, stdout
    said = lines[lines.index(PASS_LINE) + 1:]
    assert all(line.startswith(("This decision allowed execution until ", "No time was compared")) for line in said), stdout
    return lines[lines.index(PASS_LINE) - 1]


def run(paths, record, *extra, registry=None):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(paths["args"]), "--act-type", ACT_TYPE,
         "--record", str(paths[record] if record in paths else record), "--lab-verify", str(LAB_VERIFY),
         "--registry", str(registry or paths["registry"]), *extra],
        capture_output=True, text=True, timeout=120)


# --- verify_offline ----------------------------------------------------------------------------


@pytest.mark.parametrize("record", ["decision", "statement", "outcome"])
def test_a_cosigned_record_passes_with_pq_required(signed, record):
    paths, _ = signed
    proc = run(paths, record, "--require-pq")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "verdict_code: lab_dev_key" in proc.stdout  # the primary stays Ed25519, lab-verify unchanged
    assert "co-signature covers the same bytes: signed_payload and receipt_hash byte-equal" in proc.stdout
    assert f"ML-DSA-87 signature: valid under {MLDSA_KEY_ID}" in proc.stdout
    assert "post-quantum REQUIRED (--require-pq): met" in proc.stdout
    assert "AND its ML-DSA-87 (post-quantum) co-signature over the same bytes are valid" in proc.stdout


def test_with_require_pq_the_met_line_names_the_flag(signed):
    paths, _ = signed
    proc = run(paths, "decision", "--require-pq")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "post-quantum REQUIRED (--require-pq): met" in proc.stdout
    assert "key file" not in "".join(line for line in proc.stdout.splitlines() if "post-quantum REQUIRED" in line)


def test_required_by_the_key_file_alone_the_met_line_names_the_key_file_not_a_flag_nobody_gave(signed):
    paths, _ = signed
    proc = run(paths, "decision")  # no flag: the key file holds an ML-DSA-87 key of the record's signer
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "post-quantum REQUIRED by the key file" in proc.stdout
    assert "post-quantum REQUIRED (key file policy): met" in proc.stdout
    assert "--require-pq" not in proc.stdout


# --- a co-signature by a lab KMS key -------------------------------------------
# What Requisition signs: signer kms and kms_key_arn in the metadata of a record a KMS
# seat signs; the co-signing seat's key_id in the signed cosign member and, when that seat is a
# KMS seat, signer kms and its kms_key_arn. Under REQUISITION_LAB_SIGNER=kms the co-signing seat is the KMS ML-DSA-87
# key, or the dev ML-DSA-87 seat when only its variable is set: the signed cosign member
# then carries neither signer nor kms_key_arn.

KMS_ED = "requisition_lab_kms_ed25519_1234abcd-12ab-34cd-56ef-1234567890ab"
KMS_PQ = "requisition_lab_kms_mldsa87_9876fedc-98fe-76dc-54ba-9876543210fe"
ARN_ED = "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
ARN_PQ = "arn:aws:kms:us-east-2:111122223333:key/9876fedc-98fe-76dc-54ba-9876543210fe"
ARN_OTHER = "arn:aws:kms:eu-west-1:999999999999:key/00000000-0000-0000-0000-000000000000"
KMS_COSIGN = {"algorithm": "mldsa87", "key_id": KMS_PQ, "kms_key_arn": ARN_PQ, "signer": "kms", "status": "signed"}
DEV_COSIGN = {"algorithm": "mldsa87", "key_id": MLDSA_KEY_ID, "status": "signed"}
NO_ARN = {k: v for k, v in KMS_COSIGN.items() if k != "kms_key_arn"}
PREFIX_PLUS_ID = "requisition_lab_kms_mldsa87_<the KMS key's resource id>"
# name: (the signed cosign member, the signer its key file entry says, what the one refusing line must name)
NOT_THAT_KMS_KEY = {
    "the signed ARN is another key's": (dict(KMS_COSIGN, kms_key_arn=ARN_OTHER), "kms", repr(ARN_OTHER)),
    "the signed ARN is not a KMS one": (dict(KMS_COSIGN, kms_key_arn=ARN_PQ.replace(":kms:", ":iam:")), "kms", ":iam:"),
    "the signed ARN does not begin arn:": (dict(KMS_COSIGN, kms_key_arn="x" + ARN_PQ), "kms", repr("x" + ARN_PQ)),
    "the signed ARN is an alias of that id": (dict(KMS_COSIGN, kms_key_arn=ARN_PQ.replace(":key/", ":alias/")), "kms", ":alias/"),
    "no ARN is signed": (NO_ARN, "kms", "kms_key_arn None"),
    "the entry says signer dev": (KMS_COSIGN, "dev", "entry signer 'dev'"),
    "the entry says signer dev and no ARN is signed": (NO_ARN, "dev", "entry signer 'dev'"),
    "the key id lacks the prefix": (dict(KMS_COSIGN, key_id="lab_mldsa87_9876fedc-98fe-76dc-54ba-9876543210fe"), "kms",
                                    PREFIX_PLUS_ID),
    "the key id is the prefix alone": (dict(KMS_COSIGN, key_id="requisition_lab_kms_mldsa87_",
                                            kms_key_arn=ARN_PQ[:ARN_PQ.index("key/") + 4]), "kms", PREFIX_PLUS_ID),
    "an ARN is signed, signer kms is not": ({k: v for k, v in KMS_COSIGN.items() if k != "signer"}, "kms",
                                            "cosign.signer None"),
    "an ARN is signed for the dev co-signing key": (dict(DEV_COSIGN, kms_key_arn=ARN_PQ), "dev", repr(ARN_PQ)),
    "a null ARN is signed for the dev co-signing key": (dict(DEV_COSIGN, kms_key_arn=None), "dev", "kms_key_arn None"),
}
KMS_KEYS = ("the key file pins as AWS KMS keys %s (lab profile, lab keys, not a trust root; KMS custody is the key "
            "file's statement, not checked offline)")
PASS_BOTH = ("verdict: PASS -- the record is bound to these arguments and its Ed25519 signature AND its ML-DSA-87 "
             "(post-quantum) co-signature over the same bytes are valid under the LAB key(s) %s. What it decided is its "
             "signed verdict, above.")
PASS_NO_KMS_KEY_NAMED = (
    "verdict: PASS -- the record is bound to these arguments and its Ed25519 signature AND its ML-DSA-87 (post-quantum) "
    "co-signature over the same bytes are valid under the LAB key(s): the record's key, which the key file pins as AWS KMS "
    "key %s, and the co-signing key %s (key file entry signer %r), for which the signed bytes name no KMS key (lab "
    "profile, lab keys, not a trust root; KMS custody is the key file's statement, not checked offline). What it decided "
    "is its signed verdict, above.")
PASS_ED = ("verdict: PASS -- the record is bound to these arguments and its Ed25519 signature is valid under the LAB "
           "key(s) %s. What it decided is its signed verdict, above.")
FAIL_KEY = "verdict: FAIL (the ML-DSA-87 signature, the co-signature or its key entry does not check out)"


def test_the_kms_key_id_prefixes_are_lab_verifys_own():
    names = {"KMS_KEY_ID_PREFIX", "KMS_SIGNER"}
    assert len(_sources(SCRIPT, names)) == 2
    assert _sources(SCRIPT, names) == _sources(LAB_VERIFY, names)


@pytest.mark.parametrize("cosign, signer", [(KMS_COSIGN, "kms"), (DEV_COSIGN, "dev")], ids=["a KMS key", "the dev seat"])
def test_the_co_signing_key_rule_refuses_neither_seat_requisition_co_signs_with(cosign, signer):
    assert vo.cosigning_kms_key(cosign, cosign["key_id"], {"algorithm": "mldsa87", "signer": signer}) is None


@pytest.mark.parametrize("case", sorted(NOT_THAT_KMS_KEY))
def test_the_co_signing_key_rule_refuses_a_key_marked_kms_that_is_not_that_kms_key(case):
    cosign, signer, named = NOT_THAT_KMS_KEY[case]
    line = vo.cosigning_kms_key(cosign, cosign["key_id"], {"algorithm": "mldsa87", "signer": signer})
    assert isinstance(line, str) and line.startswith("co-signature key %r" % cosign["key_id"]) and named in line, line


def kms_record(signed, tmp_path, cosign, pq_signer="kms", cosigned=True):
    """The fixture's decision re-signed, by the fake's own two keys, as a record of a KMS Ed25519 seat whose signed
    cosign member is `cosign`, and a key file with the KMS Ed25519 entry and, for a co-signing key id that is not the
    dev seat's, an ML-DSA-87 entry of that id whose signer is `pq_signer`. Returns (record path, key file path)."""
    paths, server = signed
    fields = json.loads(json.loads(paths["decision"].read_text())["decision"]["signed_payload"])
    fields["metadata"].update({"signer": "kms", "kms_key_arn": ARN_ED, "key_id": KMS_ED, "cosign": cosign})
    payload = canonical.encode(fields).decode()
    digest = hashlib.sha256(payload.encode()).hexdigest()
    record = {"decision": {"signature": base64.b64encode(server.key.sign(payload.encode())).decode(),
                           "key_id": KMS_ED, "signed_payload": payload, "receipt_hash": digest}}
    registry = copy.deepcopy(server.registry)
    ed, pq = (next(e for e in server.registry["entries"] if e["algorithm"] == a) for a in ("ed25519", "mldsa87"))
    registry["entries"].append(dict(ed, key_id=KMS_ED, signer="kms"))
    if cosigned:
        record["cosignature"] = {"signature": base64.b64encode(server.mldsa_key.sign(payload.encode())).decode(),
                                 "key_id": cosign["key_id"], "signed_payload": payload, "receipt_hash": digest}
        if cosign["key_id"] != MLDSA_KEY_ID:
            registry["entries"].append(dict(pq, key_id=cosign["key_id"], signer=pq_signer))
    out = tmp_path / "kms-record.json", tmp_path / "kms-keys.json"
    out[0].write_text(json.dumps(record))
    out[1].write_text(json.dumps(registry))
    return out


@pytest.mark.parametrize("flags", [(), ("--require-pq", "--accept-signer", "kms")], ids=["no flag", "the kit's flags"])
def test_a_kms_co_signature_whose_signed_arn_is_its_keys_passes_and_the_line_names_both_arns(signed, tmp_path, flags):
    record, keys = kms_record(signed, tmp_path, KMS_COSIGN)
    proc = run(signed[0], record, *flags, registry=keys)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "lab-verify exit 5, verdict_code lab_kms_key" in proc.stdout
    assert pass_verdict(proc.stdout) == PASS_BOTH % (KMS_KEYS % (ARN_ED + ", " + ARN_PQ))


@pytest.mark.parametrize("case", ["the signed ARN is another key's", "no ARN is signed", "the entry says signer dev",
                                  "the key id lacks the prefix"])
def test_a_record_co_signed_by_a_key_marked_kms_that_is_not_that_kms_key_fails_with_one_line(signed, tmp_path, case):
    cosign, pq_signer, named = NOT_THAT_KMS_KEY[case]
    record, keys = kms_record(signed, tmp_path, cosign, pq_signer)
    proc = run(signed[0], record, "--require-pq", registry=keys)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    why = [line for line in proc.stdout.splitlines() if line.startswith("  co-signature key ")]
    assert len(why) == 1 and repr(cosign["key_id"]) in why[0] and named in why[0], proc.stdout
    assert "ML-DSA-87 signature: valid" not in proc.stdout  # the refusal is named before any signature is judged
    assert ("post-quantum REQUIRED (--require-pq): NOT MET -- the ML-DSA-87 signature, the co-signature or its key entry "
            "does not check out (above)") in proc.stdout  # no signature was judged, so the reason names none alone
    assert proc.stdout.splitlines()[-1] == FAIL_KEY and "verdict: PASS" not in proc.stdout


@pytest.mark.parametrize("cosign, signer", [(DEV_COSIGN, "dev"), (dict(DEV_COSIGN, key_id=KMS_PQ), "kms")],
                         ids=["the dev seat", "a key only the key file calls kms"])
def test_a_kms_record_co_signed_by_a_key_the_signed_bytes_name_no_kms_key_for_passes_and_the_line_says_so(
        signed, tmp_path, cosign, signer):
    record, keys = kms_record(signed, tmp_path, cosign, signer)
    proc = run(signed[0], record, "--require-pq", registry=keys)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert pass_verdict(proc.stdout) == PASS_NO_KMS_KEY_NAMED % (ARN_ED, cosign["key_id"], signer)


def test_an_arn_in_the_signed_cosign_of_a_record_with_no_co_signature_is_not_named(signed, tmp_path):
    absent = {"algorithm": "mldsa87", "key_id": None, "status": "seat_absent", "kms_key_arn": ARN_PQ}
    record, keys = kms_record(signed, tmp_path, absent, cosigned=False)
    proc = run(signed[0], record, registry=keys)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "co-signature: none" in proc.stdout
    assert pass_verdict(proc.stdout) == PASS_ED % (KMS_KEYS % ARN_ED)


def test_a_kms_record_with_no_co_signature_names_no_co_signing_key(signed, tmp_path):
    absent = {"algorithm": "mldsa87", "key_id": None, "status": "seat_absent"}
    record, keys = kms_record(signed, tmp_path, absent, cosigned=False)
    proc = run(signed[0], record, registry=keys)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert pass_verdict(proc.stdout) == PASS_ED % (KMS_KEYS % ARN_ED)


def test_a_dev_records_pass_line_names_no_key(signed):
    proc = run(signed[0], "decision", "--require-pq")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert pass_verdict(proc.stdout) == PASS_BOTH % "(DEGRADED (lab): dev keys served by the lab, not a trust root)"


def test_an_outcome_is_the_callers_report_not_proof(signed):
    paths, _ = signed
    proc = run(paths, "outcome", "--require-pq")
    assert "outcome reported by the caller (not proof the effect happened): succeeded" in proc.stdout
    assert "signed verdict: none" in proc.stdout and "evidence caller_report" in proc.stdout
    assert "not proof the effect happened." in pass_verdict(proc.stdout)


def test_an_outcome_carrying_a_verdict_is_a_mismatch():
    args = arguments_object("a", "s", ACT_TYPE, refund_args())
    md = {"act_hash": canonical.act_hash(ACT_TYPE, args), "act_type": ACT_TYPE, "act_hash_alg": canonical.ACT_HASH_ALG,
          "outcome": "succeeded", "verdict": "allow"}
    payload = canonical.encode({"receipt_type": "requisition.lab.outcome.v0", "metadata": md}).decode()
    import hashlib

    env = {"signature": "", "key_id": "k", "signed_payload": payload, "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}
    lines, ok, _ = vo.check_binding(args, ACT_TYPE, env)
    assert not ok and any("PRESENT on an outcome record" in line for line in lines)


def binding_of(metadata):
    args = arguments_object("a", "s", ACT_TYPE, refund_args())
    md = dict({"act_hash": canonical.act_hash(ACT_TYPE, args), "act_type": ACT_TYPE, "act_hash_alg": canonical.ACT_HASH_ALG,
               "verdict": "deny"}, **metadata)
    payload = json.dumps({"receipt_type": "requisition.lab.decision.v0", "metadata": md}, sort_keys=True, separators=(",", ":"))
    env = {"signature": "", "key_id": "k", "signed_payload": payload, "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}
    lines, ok, _ = vo.check_binding(args, ACT_TYPE, env)
    return ok, [line for line in lines if line.startswith(("signed verdict: ", "code: "))]


@pytest.mark.parametrize("code", [7, 0, 1.5, True, False, ["x"], [], {"x": 1}, {}], ids=repr)
def test_a_signed_code_that_is_not_text_is_one_refusing_line_of_the_binding(code):
    assert binding_of({"code": code}) == (False, ["signed verdict: deny", "code: NOT TEXT (signed %r)" % (code,)])


def test_a_signed_code_that_is_text_is_printed_and_a_null_or_absent_one_is_not():
    assert binding_of({"code": "policy_denied"}) == (True, ["signed verdict: deny policy_denied"])
    assert binding_of({"code": ""}) == (True, ["signed verdict: deny"])
    assert binding_of({"code": None}) == (True, ["signed verdict: deny"])
    assert binding_of({}) == (True, ["signed verdict: deny"])


def test_a_record_whose_signed_code_is_not_text_fails_as_a_mismatch_with_no_traceback(signed, tmp_path):
    paths, server = signed
    fields = json.loads(json.loads(paths["decision"].read_text())["decision"]["signed_payload"])
    fields["metadata"]["code"] = 7
    payload = canonical.encode(fields).decode()
    record = {"decision": {"signature": base64.b64encode(server.key.sign(payload.encode())).decode(),
                           "key_id": fields["metadata"]["key_id"], "signed_payload": payload,
                           "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}}
    (tmp_path / "code.json").write_text(json.dumps(record))
    proc = run(paths, str(tmp_path / "code.json"))
    assert proc.returncode == 1 and "Traceback" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    assert "  code: NOT TEXT (signed 7)" in proc.stdout.splitlines()
    assert proc.stdout.splitlines()[-1] == "verdict: FAIL (the signed record does not bind these arguments)"


NO_MEMBER = "no cosign member"


def alone(signed, tmp_path, cosign):
    """The fixture's decision re-signed by the fake's Ed25519 key with `cosign` as its signed cosign member (none
    for NO_MEMBER), and no co-signature beside it. Returns the record's path."""
    paths, server = signed
    fields = json.loads(json.loads(paths["decision"].read_text())["decision"]["signed_payload"])
    del fields["metadata"]["cosign"]
    if cosign != NO_MEMBER:
        fields["metadata"]["cosign"] = cosign
    payload = canonical.encode(fields).decode()
    record = {"decision": {"signature": base64.b64encode(server.key.sign(payload.encode())).decode(),
                           "key_id": fields["metadata"]["key_id"], "signed_payload": payload,
                           "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}}
    (tmp_path / "alone.json").write_text(json.dumps(record))
    return tmp_path / "alone.json"


@pytest.mark.parametrize("status", [["x"], [], {"x": 1}, {}, 7, "paused"], ids=repr)
def test_a_signed_cosign_status_the_reasons_do_not_name_is_printed_as_signed_with_no_traceback(signed, tmp_path, status):
    record = alone(signed, tmp_path, {"algorithm": "mldsa87", "key_id": None, "status": status})
    # no flag: the fixture's key file holds an ML-DSA-87 key of the record's signer, so the key file requires it
    for flags, by in ((("--require-pq",), "--require-pq"), ((), "key file policy")):
        proc = run(signed[0], record, *flags)
        assert proc.returncode == 4 and "Traceback" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr
        why = "the record's signed cosign.status is %r" % (status,)
        assert "  post-quantum REQUIRED (%s): NOT MET -- %s" % (by, why) in proc.stdout.splitlines(), proc.stdout
        assert proc.stdout.splitlines()[-1] == "verdict: FAIL (post-quantum required: %s)" % why


NO_STATUS = ("the record's signed cosign.status is absent or null, no co-signature is beside it, and the key file "
             "holds no single ML-DSA-87 entry for the record's own key")


@pytest.mark.parametrize("cosign", [NO_MEMBER, {"algorithm": "mldsa87", "key_id": None},
                                    {"algorithm": "mldsa87", "key_id": None, "status": None}, 7],
                         ids=["no cosign member", "a member with no status", "a null status", "a member that is a number"])
def test_a_record_with_no_signed_cosign_status_and_no_co_signature_is_told_what_was_looked_for(signed, tmp_path, cosign):
    record = alone(signed, tmp_path, cosign)
    for flags, by in ((("--require-pq",), "--require-pq"), ((), "key file policy")):
        proc = run(signed[0], record, *flags)
        assert proc.returncode == 4, proc.stdout + proc.stderr
        assert "  post-quantum REQUIRED (%s): NOT MET -- %s" % (by, NO_STATUS) in proc.stdout.splitlines(), proc.stdout
        assert proc.stdout.splitlines()[-1] == "verdict: FAIL (post-quantum required: %s)" % NO_STATUS


UNBOUND = ("the record does not bind these arguments (above); no co-signature is beside it, and the key file holds "
           "no single ML-DSA-87 entry for the record's own key")


@pytest.mark.parametrize("cosign", [{"algorithm": "mldsa87", "key_id": None, "status": "seat_absent"}, NO_MEMBER],
                         ids=["seat_absent", "no cosign member"])
def test_a_record_that_does_not_bind_the_arguments_gets_no_reason_from_its_signed_cosign_status(signed, tmp_path, cosign):
    paths, _ = signed
    record = alone(signed, tmp_path, cosign)
    (tmp_path / "other.json").write_text(json.dumps(dict(json.loads(paths["args"].read_text()), session="another")))
    proc = run(dict(paths, args=tmp_path / "other.json"), record, "--require-pq")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "  post-quantum REQUIRED (--require-pq): NOT MET -- " + UNBOUND in proc.stdout.splitlines(), proc.stdout
    assert proc.stdout.splitlines()[-1] == "verdict: FAIL (the signed record does not bind these arguments)"
    bound = run(paths, record, "--require-pq")  # the control: the same record with the arguments it binds
    assert bound.returncode == 4 and "NOT MET -- the record's signed cosign.status is " in bound.stdout, bound.stdout


def test_a_co_signing_key_whose_entry_signer_is_a_list_is_refused_by_the_key_rule_with_no_traceback(signed, tmp_path):
    paths, _ = signed
    registry = json.loads(paths["registry"].read_text())
    next(e for e in registry["entries"] if e["algorithm"] == "mldsa87")["signer"] = ["dev"]
    (tmp_path / "list.json").write_text(json.dumps(registry))
    proc = run(paths, "decision", "--accept-signer", "dev", registry=tmp_path / "list.json")
    assert proc.returncode == 4 and "Traceback" not in proc.stdout + proc.stderr, proc.stdout + proc.stderr
    assert "refused by the key rule: signer_not_accepted" in proc.stdout
    assert "lab-verify exit 5, verdict_code lab_dev_key" in proc.stdout  # the record's own key entry says signer dev


def test_a_separate_cosignature_file(signed, tmp_path):
    paths, _ = signed
    answer = json.loads(paths["decision"].read_text())
    (tmp_path / "env.json").write_text(json.dumps(answer["decision"]))
    (tmp_path / "cos.json").write_text(json.dumps(answer["cosignature"]))
    proc = run(paths, str(tmp_path / "env.json"), "--require-pq", "--cosignature", str(tmp_path / "cos.json"))
    assert proc.returncode == 0, proc.stdout
    stripped = run(paths, str(tmp_path / "env.json"), "--require-pq")  # cosign says signed, and none is beside it
    assert stripped.returncode == 4, stripped.stdout
    assert ("post-quantum REQUIRED (--require-pq): NOT MET -- the record's signed cosign.status is signed, and no "
            "co-signature is beside it (stripped, above)") in stripped.stdout


@pytest.mark.parametrize("mutate, said", [
    (lambda a: a.pop("cosignature"), "MISSING, yet the signed bytes say it exists: stripped"),
    (lambda a: a["cosignature"].update(signed_payload=a["cosignature"]["signed_payload"] + " "),
     "does NOT cover the record's own bytes"),
    (lambda a: a["cosignature"].update(key_id="requisition_lab_dev_mldsa87_v1"), "is not the signed cosign.key_id"),
    (lambda a: a["cosignature"].update(signature=base64.b64encode(b"\0" * 4627).decode()), "ML-DSA-87 signature: INVALID"),
])
def test_cosignature_defects_fail(signed, mutate, said):
    paths, _ = signed
    answer = json.loads(paths["decision"].read_text())
    mutate(answer)
    paths["decision"].write_text(json.dumps(answer))
    proc = run(paths, "decision")  # even without --require-pq: a present or announced co-signature must check out
    assert proc.returncode == 4 and said in proc.stdout, proc.stdout


@pytest.mark.parametrize("status", ["seat_absent", "signed_bytes_over_bound", None])
def test_require_pq_fails_without_a_cosignature_and_says_why(tmp_path, clock, status):
    server = server_for(clock, status)
    try:
        gate = gate_for(server, tmp_path, clock, allow_classical_only=True)  # the premise: an Ed25519-only record
        args, s, d = flow(server, gate)
        assert d.allowed and not d.pq_checked
        paths = {"args": tmp_path / "a.json", "registry": tmp_path / "k.json", "decision": tmp_path / "d.json"}
        paths["args"].write_text(json.dumps(args))
        paths["registry"].write_text(json.dumps(server.registry))
        paths["decision"].write_text(json.dumps(d.response))
        why = {"seat_absent": "seat was not running", "signed_bytes_over_bound": "4,096-byte bound",
               None: NO_STATUS}[status]
        proc = run(paths, "decision", "--require-pq")
        assert proc.returncode == 4 and "NOT MET" in proc.stdout and why in proc.stdout, proc.stdout
        assert "verdict: FAIL (post-quantum required:" in proc.stdout
        by_policy = run(paths, "decision")  # no flag, and the key file holds an ML-DSA-87 key: still required
        if status is None:
            assert by_policy.returncode == 0 and "its Ed25519 signature is valid" in by_policy.stdout
        else:
            assert by_policy.returncode == 4 and "post-quantum REQUIRED by the key file" in by_policy.stdout, by_policy.stdout
            assert "post-quantum REQUIRED (key file policy): NOT MET -- " in by_policy.stdout and why in by_policy.stdout
        relaxed = run(paths, "decision", "--allow-classical-only")
        assert relaxed.returncode == 0 and "its Ed25519 signature is valid" in relaxed.stdout
    finally:
        server.stop()


# --- the gate (the target runs a tool only on what the gate accepted) ----------------------------


def test_the_gate_refuses_a_stripped_cosignature(tmp_path, clock):
    server = server_for(clock, "signed")
    server.cosign_tamper = lambda cos: None
    try:
        with pytest.raises(RecordInvalid, match="stripped"):
            flow(server, gate_for(server, tmp_path, clock))
    finally:
        server.stop()


def test_the_gate_refuses_a_cosignature_over_other_bytes(tmp_path, clock):
    server = server_for(clock, "signed")
    server.cosign_tamper = lambda cos: {**cos, "signed_payload": cos["signed_payload"].replace("lab", "1ab", 1)}
    try:
        with pytest.raises(RecordInvalid, match="own bytes"):
            flow(server, gate_for(server, tmp_path, clock))
    finally:
        server.stop()


def test_the_gate_with_require_pq_refuses_seat_absent(tmp_path, clock):
    server = server_for(clock, "seat_absent")
    try:
        with pytest.raises(RecordInvalid, match="seat_absent"):
            flow(server, gate_for(server, tmp_path, clock, require_pq=True))
    finally:
        server.stop()


def test_require_pq_needs_a_key_file(fake, clock, tmp_path):
    client = Client(fake.base_url, fake.credential, fake.principal)
    with pytest.raises(ValueError, match="pinned key file"):
        Gate(client, Store(str(tmp_path / "s.json")), approval_base_url="x", require_pq=True)


def test_accept_signer_is_applied_to_the_cosignature_key_too(signed):
    paths, _server = signed
    proc = run(paths, "decision", "--accept-signer", "kms")
    assert proc.returncode != 0, proc.stdout
    section = proc.stdout.split("== 3.")[1]
    assert "refused by the key rule: signer_not_accepted" in section, section  # the co-signature's ML-DSA-87 key (signer dev)
