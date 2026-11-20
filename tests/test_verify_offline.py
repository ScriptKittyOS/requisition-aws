# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""bin/verify_offline.py: its encoder equals the package's; end to end with Requisition's own
bin/lab-verify (the committed copy, tests/fixtures/requisition/) over records the fake signed."""

import base64
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

import pytest

from requisition_aws import canonical
from requisition_aws.gate import arguments_object

from .conftest import ACT_TYPE, refund_args
from .fake_requisition import FakeRequisition
from .test_canonical import REQ_TREE

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin" / "verify_offline.py"
LAB_VERIFY = REQ_TREE / "bin" / "lab-verify"
DIFF = pathlib.Path(__file__).parent / "fixtures" / "elixir_differential"


def _module():
    spec = importlib.util.spec_from_file_location("verify_offline", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vo = _module()


def test_script_imports_only_the_standard_library():
    text = SCRIPT.read_text()
    imports = sorted({line.split()[1] for line in text.splitlines() if line.startswith("import ")})
    assert imports == ["base64", "binascii", "hashlib", "json", "os", "subprocess", "sys", "tempfile", "types"]
    # the one non-stdlib file it may reach is the vendored verifier, loaded by path under a pin
    assert 'os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "mldsa.py")' in text
    assert "from " not in "".join(l for l in text.splitlines() if l.startswith("from "))


def test_encoder_parity_with_the_package_on_the_elixir_corpus():
    for term, answer in zip(json.loads((DIFF / "enc_cases.json").read_text()), json.loads((DIFF / "enc_out.json").read_text())):
        assert vo.encode(term) == canonical.encode(term) == base64.b64decode(answer)


# A value the version 3 encoder refuses, and the name the package's encoder gives the refusal. The verifier's copy
# gives the same name: a caller that reads the code gets one vocabulary from both.
V3_REFUSALS = [
    ({"amount": 12.5}, "float_refused"),
    ({"amounts": [1, 2.0]}, "float_refused"),
    ({"a": {"b": float("nan")}}, "float_refused"),
    ({1: "a number as a member name"}, "non_string_key"),
    ({"when": object()}, "unencodable"),
    ({"note": "\ud800"}, "invalid_string"),
    ({"\udfff": 1}, "invalid_string"),
]


@pytest.mark.parametrize("value, code", V3_REFUSALS, ids=[code + " " + str(n) for n, (_, code) in enumerate(V3_REFUSALS)])
def test_a_version_3_refusal_carries_the_name_the_package_gives_it(value, code):
    with pytest.raises(canonical.CanonicalRefusal) as package:
        canonical.encode(value)
    with pytest.raises(vo.Refused) as verifier:
        vo.encode(value)
    assert package.value.code == code and verifier.value.code == code


def test_demo_args_hash_and_digest_match_the_package():
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    assert vo.act_hash(ACT_TYPE, args) == canonical.act_hash(ACT_TYPE, args)
    assert vo.display_digest(args) == canonical.display_digest(args)


# --- end to end with the real bin/lab-verify ------------------------------------------------------


@pytest.fixture
def records(gate, fake, tmp_path):
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    allow = gate.execute(s, args, "nonce-allow")
    spent = gate.execute_fresh(s, args, "nonce-replay")
    paths = {}
    for name, obj in {"args": args, "statement": s.statement, "allow": {"decision": allow.decision},
                      "spent": spent.decision, "registry": fake.registry}.items():
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(obj))
    return paths


def run(paths, record, args=None, registry=None):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(args or paths["args"]), "--act-type", ACT_TYPE,
         "--record", str(paths[record]), "--lab-verify", str(LAB_VERIFY), "--registry", str(registry or paths["registry"])],
        capture_output=True, text=True, timeout=120,
    )


@pytest.mark.parametrize("record", ["statement", "allow", "spent"])
def test_pass_with_the_real_lab_verify(records, record):
    proc = run(records, record)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "verdict_code: lab_dev_key" in proc.stdout
    assert "act_hash: equal" in proc.stdout and "verdict: PASS" in proc.stdout
    if record == "spent":
        assert "signed verdict: deny statement_spent" in proc.stdout


def test_other_arguments_are_a_mismatch(records, tmp_path):
    other = tmp_path / "other.json"
    other.write_text(json.dumps(arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args(amount_minor=999999))))
    proc = run(records, "allow", args=other)
    assert proc.returncode == 1 and "act_hash: MISMATCH" in proc.stdout


def test_a_foreign_key_is_not_lab_dev_key(records, tmp_path, clock):
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps(FakeRequisition(now=clock.now).registry))
    proc = run(records, "allow", registry=foreign)
    assert proc.returncode == 3 and "lab-verify exit 4" not in proc.stdout  # its own exit, reported as it came


def test_a_changed_byte_fails(records):
    env = json.loads(records["statement"].read_text())
    env["signed_payload"] = env["signed_payload"].replace('"high"', '"low"')
    records["statement"].write_text(json.dumps(env))
    proc = run(records, "statement")
    assert proc.returncode == 1


def test_usage():
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
    assert proc.returncode == 2


# --- ML-DSA-87 records (the lab's post-quantum seat; the fake signs with cryptography's ML-DSA-87) ---

needs_mldsa_fake = pytest.mark.skipif(
    not hasattr(__import__("cryptography.hazmat.primitives.asymmetric", fromlist=["mldsa"]), "mldsa"),
    reason="cryptography without ML-DSA")


@pytest.fixture
def pq_records(tmp_path, clock):
    from requisition_aws.client import Client
    from requisition_aws.gate import Gate
    from requisition_aws.keys import KeyRegistry
    from requisition_aws.store import Store

    from .test_canonical import SEED_SCHEMA

    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now,
                             mldsa87_kinds=("decision",))
    server.base_url = server.start()
    try:
        client = Client(server.base_url, server.credential, server.principal, timeout=5)
        gate = Gate(client, Store(str(tmp_path / "store.json"), clock=clock), approval_base_url="http://x",
                    keys=KeyRegistry.from_bytes(client.keys()), clock=clock,
                    allow_classical_only=True)  # this fixture signs only the decision post-quantum: statements stay Ed25519
        args = arguments_object("refund-agent", "s-pq", ACT_TYPE, refund_args())
        s = gate.file_or_find(ACT_TYPE, args)
        server.approve(s.request_id)
        s = gate.read(s, args)
        allow = gate.execute(s, args, "nonce-pq")
        assert allow.allowed and allow.signature_checked  # KeyRegistry checked ML-DSA-87 in process
        paths = {}
        objs = {"args": args, "allow": allow.response, "envelope": allow.decision,
                "form": allow.response["receipt"], "registry": server.registry}
        for name, obj in objs.items():
            paths[name] = tmp_path / f"{name}.json"
            paths[name].write_text(json.dumps(obj))
        yield paths
    finally:
        server.stop()


@needs_mldsa_fake
@pytest.mark.parametrize("record", ["allow", "envelope", "form"])
def test_an_mldsa87_record_passes_all_three_halves(pq_records, record):
    proc = run(pq_records, record)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "verdict_code: lab_signature_unchecked_mldsa87" in proc.stdout  # lab-verify cannot check it
    assert "== 3. the post-quantum signature" in proc.stdout
    assert "ML-DSA-87 signature: valid under requisition_lab_dev_mldsa87_v0" in proc.stdout
    assert "verdict: PASS" in proc.stdout and "ML-DSA-87 (post-quantum)" in proc.stdout


@needs_mldsa_fake
def test_an_mldsa87_record_under_another_key_fails_the_signature(pq_records, tmp_path, clock):
    other = FakeRequisition(now=clock.now, mldsa87_kinds=("decision",)).registry
    registry = json.loads(pq_records["registry"].read_text())
    registry["entries"] = [e for e in registry["entries"] if e["algorithm"] != "mldsa87"] + \
        [e for e in other["entries"] if e["algorithm"] == "mldsa87"]
    foreign = tmp_path / "foreign-pq.json"
    foreign.write_text(json.dumps(registry))
    proc = run(pq_records, "allow", registry=foreign)
    assert proc.returncode == 4 and "ML-DSA-87 signature: INVALID" in proc.stdout
    required = run_with(dict(pq_records, registry=foreign), "allow", "--require-pq")
    assert required.returncode == 4 and "ML-DSA-87 signature: INVALID" in required.stdout
    # the record carries an ML-DSA-87 signature, and it failed: the reason must not say it carries none
    assert ("post-quantum REQUIRED (--require-pq): NOT MET -- the ML-DSA-87 signature, the co-signature or its key entry "
            "does not check out (above)") in required.stdout, required.stdout


@needs_mldsa_fake
def test_an_mldsa87_form_with_one_changed_value_fails(pq_records):
    form = json.loads(pq_records["form"].read_text())
    form["metadata"]["verdict"] = "deny"
    pq_records["form"].write_text(json.dumps(form))
    proc = run(pq_records, "form")
    assert proc.returncode == 4 and "INVALID" in proc.stdout  # the rebuilt bytes are not what was signed


@needs_mldsa_fake
def test_a_form_beside_a_different_envelope_is_refused(pq_records):
    answer = json.loads(pq_records["allow"].read_text())
    answer["receipt"]["sequence"] += 1
    pq_records["allow"].write_text(json.dumps(answer))
    proc = run(pq_records, "allow")
    assert proc.returncode == 1 and "name different bytes" in proc.stdout


@needs_mldsa_fake
def test_the_form_re_encodes_to_the_envelopes_signed_payload(pq_records):
    form = json.loads(pq_records["form"].read_text())
    envelope = json.loads(pq_records["envelope"].read_text())
    assert vo.envelope_from_form(form) == envelope
    assert json.loads(envelope["signed_payload"])["schema_version"] == "agent_receipt.v1"


# --- --accept-signer (the relying party's signer policy) through the real bin/lab-verify ------------------


def run_with(paths, record, *extra):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(paths["args"]), "--act-type", ACT_TYPE,
         "--record", str(paths[record]), "--lab-verify", str(LAB_VERIFY), "--registry", str(paths["registry"]), *extra],
        capture_output=True, text=True, timeout=120)


def test_accept_signer_kms_refuses_a_dev_signed_record_through_lab_verify(records):
    assert run_with(records, "allow").returncode == 0  # control: no policy, a dev key verifies (and says DEGRADED)
    proc = run_with(records, "allow", "--accept-signer", "kms")
    assert proc.returncode == 3, proc.stdout  # lab-verify did not answer lab_dev_key: its own refusal, reported as it came
    assert "verdict_code: lab_signer_not_accepted" in proc.stdout, proc.stdout
    assert "verdict: FAIL" in proc.stdout


def test_accept_signer_dev_lets_the_dev_record_through(records):
    proc = run_with(records, "allow", "--accept-signer", "dev", "--accept-signer", "kms")
    assert proc.returncode == 0 and "verdict: PASS" in proc.stdout, proc.stdout


@needs_mldsa_fake
def test_accept_signer_governs_the_mldsa87_half_too(pq_records):
    assert run_with(pq_records, "allow").returncode == 0
    proc = run_with(pq_records, "allow", "--accept-signer", "kms")
    assert proc.returncode in (3, 4), proc.stdout
    assert "signer_not_accepted" in proc.stdout, proc.stdout


def test_verify_offline_expects_pq_only_of_a_pq_key_usable_at_the_signed_instant_and_checks_the_cosignature_signer():
    import copy
    from .key_rule_harness import build, load_vectors
    vector = next(v for v in load_vectors() if v["name"] == "active_open_inside")
    ed_registry, envelope = build(vector, "ed25519")
    ml_registry, ml_envelope = build(vector, "mldsa87")
    both = {"entries": ed_registry["entries"] + ml_registry["entries"]}
    assert vo.pq_expected(both, envelope) is True
    outside = copy.deepcopy(both)
    outside["entries"][1].update(status="retired", valid_to="2026-11-02T00:00:00Z")
    assert vo.pq_expected(outside, envelope) is False  # the ML-DSA-87 key was retired before the record was signed
    # the co-signature's own key is held to the accepted signers (the reason is named before any signature is judged)
    import hashlib as _h
    ml_id = ml_envelope["key_id"]
    payload = json.dumps({"occurred_at": "2026-11-05T00:00:00Z", "metadata": {"cosign": {"algorithm": "mldsa87", "status": "signed", "key_id": ml_id}}})
    record = {"signature": envelope["signature"], "key_id": envelope["key_id"], "signed_payload": payload,
              "receipt_hash": _h.sha256(payload.encode()).hexdigest()}
    cosig = {**ml_envelope, "signed_payload": payload, "receipt_hash": record["receipt_hash"]}
    lines, ok, present = vo.check_cosignature(record, cosig, both, accept_signers=frozenset({"nobody"}))
    assert ok is False and present is True and "signer_not_accepted" in " ".join(lines), lines


# --- the NOT-checked line never sits inside a PASS of a tool that DID check the co-signature ---------------


def test_a_passing_cosigned_record_says_both_signatures_were_verified_and_never_not_checked(tmp_path, clock):
    from .test_cosign import flow, gate_for, server_for
    server = server_for(clock, "signed")
    try:
        args, _s, d = flow(server, gate_for(server, tmp_path, clock, require_pq=True))
        files = {"args": args, "registry": server.registry, "decision": d.response}
        paths = {}
        for name, obj in files.items():
            paths[name] = tmp_path / f"{name}.json"
            paths[name].write_text(json.dumps(obj))
        proc = run_with(paths, "decision", "--require-pq")
    finally:
        server.stop()
    out = proc.stdout
    assert proc.returncode == 0 and "verdict: PASS" in out, out
    assert "NOT checked by this tool" not in out, out
    assert "both signatures verified: the Ed25519 signature (by bin/lab-verify) and the ML-DSA-87 co-signature (by this tool)" in out, out
    for kept in ("lab-verify exit 5, verdict_code lab_dev_key", "post-quantum REQUIRED (--require-pq): met"):
        assert kept in out, kept  # the strings the rehearsal scripts match


def test_an_empty_accept_signer_label_is_a_usage_error_never_any(records):
    proc = run_with(records, "allow", "--accept-signer", "")
    assert proc.returncode == 2 and "usage" in proc.stderr, (proc.returncode, proc.stdout, proc.stderr)


def test_both_signatures_verified_is_not_said_when_lab_verify_did_not_pass(tmp_path, clock):
    """The line states the Ed25519 half was verified: a lab-verify that failed (here a stub that answers nothing) must not get it."""
    from .test_cosign import flow, gate_for, server_for
    stub = tmp_path / "lab-verify-stub"
    stub.write_text("import sys\nsys.exit(1)\n")
    server = server_for(clock, "signed")
    try:
        args, _s, d = flow(server, gate_for(server, tmp_path, clock, require_pq=True))
        paths = {}
        for name, obj in {"args": args, "registry": server.registry, "decision": d.response}.items():
            paths[name] = tmp_path / f"{name}.json"
            paths[name].write_text(json.dumps(obj))
        proc = subprocess.run([sys.executable, "-I", str(SCRIPT), "--arguments", str(paths["args"]), "--act-type", ACT_TYPE,
                               "--record", str(paths["decision"]), "--lab-verify", str(stub), "--registry", str(paths["registry"]),
                               "--require-pq"], capture_output=True, text=True, timeout=120)
    finally:
        server.stop()
    assert proc.returncode == 3, proc.stdout
    assert "both signatures verified" not in proc.stdout, proc.stdout


@needs_mldsa_fake
@pytest.mark.parametrize("status", [5, 0])
def test_an_unchecked_answer_with_another_status_fails_the_lab_half(pq_records, tmp_path, status):
    """bin/lab-verify's answer for an ML-DSA-87 record whose signature it did not check is lab_signature_unchecked_mldsa87
    with exit 7; the same code with any other status (5, the status of a checked pass; 0) is not that answer: exit 3,
    and the FAIL line names the status it came with."""
    stand_in = tmp_path / "lab-verify"
    stand_in.write_text("import sys\nprint('verdict_code: lab_signature_unchecked_mldsa87')\nsys.exit(%d)\n" % status)
    proc = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(pq_records["args"]), "--act-type", ACT_TYPE,
         "--record", str(pq_records["allow"]), "--lab-verify", str(stand_in), "--registry", str(pq_records["registry"])],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 3, proc.stdout
    assert ("verdict: FAIL (lab-verify answered lab_signature_unchecked_mldsa87 with exit %d, not 7, for this record's "
            "signed signer" % status) in proc.stdout, proc.stdout
