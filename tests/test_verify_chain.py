# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""F1b: bin/verify_chain.py, a
stranger's offline check of one ACCOUNT chain export against records held outside it. The interface:

    python3 -I bin/verify_chain.py --registry KEYS.json --export EXPORT [--held FILE]... [--require-pq] [--json]

* EXPORT: the CSV ``bin/export_chain.sh`` writes (header ``chain_scope,sequence,signature,key_id,
  signed_payload,receipt_hash,cosignature,cosignature_key_id``: the stored rows of
  ``authority_lab_receipts``, ordered by sequence), or JSON ``{"records": [row, ...]}`` whose rows are
  a four-field envelope or ``{"record": envelope, "cosignature": envelope}`` (the fake's export).
  Position is read from the SIGNED payload only. Account scopes only (``requisition-lab:account:<id>``):
  any other scope is refused, exit 2.
* --held FILE: one envelope; ``{"record"|"statement"|"decision": envelope, "cosignature": ...}``; a list
  of those; ``{"records": [...]}``; or a relying party's equivocation evidence entry
  ``{"held": envelope, "presented": envelope, ...}`` (or ``{"evidence": [entries]}``). Identical copies
  of one record are one record.
* Signatures: Ed25519 by a pinned copy of verify_receipt.py's RFC 8032 routine (requisition
  bench/holytrinity-v2/verifier/verify_receipt.py, sha256 6414bcb3...86db8c, as published in receipt-verification r4, recorded in
  bin/vendor/VENDORED.md); ML-DSA-87 by the vendored mldsa. --require-pq: every agent-tool record (the
  ones whose signed metadata carries ``cosign``) needs a valid ML-DSA-87
  signature over its own bytes; other records are reported "Ed25519 only".
* Codes: ``ok``, ``link_broken``, ``sequence_gap``, ``sequence_duplicate``, ``held_record_differs``,
  ``export_short``, ``equivocation``, ``signature_invalid``, ``pq_missing``, ``held_other_scope``,
  ``held_record_invalid``, ``export_not_from_genesis``. Each FAIL names its records (both, for a pair).
* --json: ``{"result": "ok" | "FAIL", "chain_scope", "failures": [{"code", "sequence", "detail",
  "records": [envelope, ...]}]}``. Text: a line per check, then ``RESULT ok`` or ``RESULT FAIL``; after
  ``RESULT ok`` comes the one sentence a pass ends with (tests/test_pass_lines.py).
* Exit 0 ok, 1 FAIL, 2 usage or refusal.

Fixtures: chains signed by tests/fake_requisition.py at test time (labelled: the export carries the
fake's provenance member) AND the real lab records under tests/fixtures/real_lab_chain/ (PROVENANCE.md),
which are windows of real account chains (they start at sequence 3, so as an export they are never
"from genesis": that FAIL is correct and asserted).
"""

import base64
import csv
import io
import json
import os
import pathlib
import stat
import subprocess
import sys

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate, arguments_object
from requisition_aws.keys import KeyRegistry
from requisition_aws.store import Store

from .conftest import ACT_TYPE, refund_args
from .fake_requisition import FAKE_PROVENANCE, FakeRequisition
from .test_canonical import SEED_SCHEMA
from .test_pass_lines import PASS_LINE

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin" / "verify_chain.py"
EXPORT_SCRIPT = ROOT / "bin" / "export_chain.sh"
REAL = pathlib.Path(__file__).parent / "fixtures" / "real_lab_chain"
VERIFY_RECEIPT_SHA256 = "6414bcb3f4a4a02c14a70ffe7e74dc6bb5b5725d6dc9f83ead38f5bd5286db8c"
CSV_COLUMNS = ["chain_scope", "sequence", "signature", "key_id", "signed_payload", "receipt_hash", "cosignature",
               "cosignature_key_id"]


# --- running it ---------------------------------------------------------------------------------


def run(tmp_path, registry, export, held=(), *flags, as_json=True):
    reg = tmp_path / "registry.json"
    if isinstance(registry, dict):
        reg.write_text(json.dumps(registry))
    else:
        reg = registry
    args = [sys.executable, "-I", str(SCRIPT), "--registry", str(reg), "--export", str(export)]
    for h in held:
        args += ["--held", str(h)]
    args += list(flags)
    if as_json:
        args.append("--json")
    cwd = tmp_path / "cwd"
    cwd.mkdir(exist_ok=True)
    proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd, env={"PATH": os.environ.get("PATH", "")},
                          timeout=120)
    report = json.loads(proc.stdout) if as_json and proc.returncode in (0, 1) else None
    return proc, report


def codes(report):
    return {f["code"] for f in report["failures"]}


def failure(report, code):
    found = [f for f in report["failures"] if f["code"] == code]
    assert found, report["failures"]
    return found


def write(tmp_path, name, obj):
    path = tmp_path / name
    path.write_text(json.dumps(obj))
    return path


def signed(envelope):
    return json.loads(envelope["signed_payload"])


def seq(envelope):
    return signed(envelope)["sequence"]


def rows_of(export):
    return [dict(r) for r in export["records"]]


def export_of(rows, provenance=FAKE_PROVENANCE):
    return {"provenance": provenance, "records": rows}


def to_csv(rows):
    """The fake's rows as the SQL export writes them (cosignature: the detached signature text)."""
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
    w.writeheader()
    for row in rows:
        env = row["record"]
        s = signed(env)
        cos = row.get("cosignature")
        w.writerow({"chain_scope": s["chain_scope"], "sequence": s["sequence"], "signature": env["signature"],
                    "key_id": env["key_id"], "signed_payload": env["signed_payload"], "receipt_hash": env["receipt_hash"],
                    "cosignature": cos["signature"] if cos else "", "cosignature_key_id": cos["key_id"] if cos else ""})
    return out.getvalue()


def tamper_one_char(envelope):
    """One character of the signed payload changed (a letter of the signed "statement_id_label" key)."""
    t = dict(envelope)
    i = t["signed_payload"].index("statement_id_label")  # any position inside the signed bytes
    ch = t["signed_payload"][i]
    t["signed_payload"] = t["signed_payload"][:i] + ("T" if ch != "T" else "U") + t["signed_payload"][i + 1:]
    return t


# --- a chain the fake signs (labelled) ----------------------------------------------------------


class Chain:
    """One account chain driven through the adapter's own gate against the fake: other traffic (two
    pumped denies), then a refund statement S, its allow D, the replay attempt's deny, the outcome O.
    ``snap``/``h0``: the database after the approvals and before the first GET."""

    def __init__(self, clock, tmp_path, *, cosign=None, scope=None):
        kw = {"chain_scope": scope} if scope else {}
        self.clock = clock
        self.fake = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now,
                                    newer_routes=True, cosign=cosign, **kw)
        self.fake.base_url = self.fake.start()
        client = Client(self.fake.base_url, self.fake.credential, self.fake.principal, timeout=5)
        self.gate = Gate(client, Store(str(tmp_path / f"chain-{id(self)}.json"), clock=clock),
                         approval_base_url="http://127.0.0.1:4000", keys=KeyRegistry.from_bytes(client.keys()),
                         clock=clock, allow_classical_only=True)  # seat_absent / over-bound chains are the premise
        self.args = arguments_object("refund-agent", "s-chain", ACT_TYPE, refund_args())
        self.fake.pump_denies(2)
        s = self.gate.file_or_find(ACT_TYPE, self.args)
        self.fake.approve(s.request_id)
        self.h0, self.snap = self.fake.head(), self.fake.snapshot()
        s = self.gate.read(s, self.args)
        self.request_id = s.request_id
        self.S = s.statement
        allow = self.gate.execute(s, self.args, "nonce-1")
        self.D = allow.decision
        self.deny = self.gate.execute_fresh(s, self.args, "nonce-2").decision
        assert self.gate.report_outcome(allow, True, "REFUND SENT") == "recorded"
        self.O = self.gate.outcome_records[-1]["record"]
        self.export = self.fake.export()

    def remint(self):
        """Restore the snapshot; the caller's GET re-mints S' at S's position. Returns S'."""
        self.clock.advance(5)
        self.fake.restore(self.snap)
        assert self.fake.head() == self.h0
        status, answer, _ = self.fake.fetch(self.request_id)
        s_prime = answer["statement"]
        assert seq(s_prime) == seq(self.S) and s_prime["receipt_hash"] != self.S["receipt_hash"]
        return s_prime

    def stop(self):
        self.fake.stop()


@pytest.fixture
def chain(clock, tmp_path):
    c = Chain(clock, tmp_path)
    yield c
    c.stop()


# --- the script itself -------------------------------------------------------------------------


def test_script_is_standard_library_only_and_runs_isolated(chain, tmp_path):
    text = SCRIPT.read_text()
    imports = set()
    for line in text.splitlines():
        if line.startswith("import "):
            imports.update(m.strip().split(".")[0] for m in line[7:].split(","))
        elif line.startswith("from "):
            imports.add(line.split()[1].split(".")[0])
    assert imports and imports <= set(sys.stdlib_module_names), imports - set(sys.stdlib_module_names)
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export))
    assert proc.returncode == 0, proc.stderr


def test_the_ed25519_routine_is_a_pinned_copy_of_verify_receipt():
    vendored = (ROOT / "bin" / "vendor" / "VENDORED.md").read_text()
    assert "verify_receipt.py" in vendored and VERIFY_RECEIPT_SHA256 in vendored


def test_a_good_export_with_held_records_is_ok(chain, tmp_path):
    held = write(tmp_path, "held.json", [chain.D, chain.O])
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export), [held])
    assert proc.returncode == 0 and report["result"] == "ok" and report["failures"] == []
    assert report["chain_scope"] == signed(chain.S)["chain_scope"]
    text, _ = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export), [held], as_json=False)
    assert text.returncode == 0 and text.stdout.strip().splitlines()[-2:] == ["RESULT ok", PASS_LINE]


def test_the_sql_export_csv_form_is_read(chain, tmp_path):
    path = tmp_path / "export.csv"
    path.write_text(to_csv(rows_of(chain.export)))
    proc, report = run(tmp_path, chain.fake.registry, path, [write(tmp_path, "h.json", chain.O)])
    assert proc.returncode == 0 and report["result"] == "ok"


def test_export_short_when_the_export_ends_before_a_held_record(chain, tmp_path):
    chain.fake.restore(chain.snap)  # the restored database, exported before anything is re-minted
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.fake.export()),
                       [write(tmp_path, "h.json", chain.O)])
    assert proc.returncode == 1 and report["result"] == "FAIL"
    (f,) = failure(report, "export_short")
    assert f["records"][0]["receipt_hash"] == chain.O["receipt_hash"]


def test_the_remint_is_held_record_differs_and_equivocation_with_both_records(chain, tmp_path):
    chain.remint()
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.fake.export()),
                       [write(tmp_path, "h.json", [chain.S, chain.D])])
    assert proc.returncode == 1
    assert {"held_record_differs", "equivocation"} <= codes(report)
    for code in ("held_record_differs", "equivocation"):
        (f,) = [f for f in failure(report, code) if f["sequence"] == seq(chain.S)]
        hashes = {r["receipt_hash"] for r in f["records"]}
        assert chain.S["receipt_hash"] in hashes and len(hashes) == 2


def test_a_relying_partys_evidence_entry_is_a_held_input(chain, tmp_path):
    s_prime = chain.remint()
    entry = {"code": "authority_equivocated", "chain_scope": signed(chain.S)["chain_scope"], "sequence": seq(chain.S),
             "held": chain.S, "presented": s_prime}
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export),
                       [write(tmp_path, "evidence.json", {"evidence": [entry]})])
    assert proc.returncode == 1 and "equivocation" in codes(report)


def test_a_broken_previous_hash_link(chain, tmp_path):
    rows = rows_of(chain.export)
    s_prime = chain.remint()
    i = next(k for k, r in enumerate(rows) if r["record"]["receipt_hash"] == chain.S["receipt_hash"])
    rows[i] = {"record": s_prime}  # two histories spliced: the next row names S, not S'
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", export_of(rows)))
    assert proc.returncode == 1 and "link_broken" in codes(report)
    assert "signature_invalid" not in codes(report)  # every row is validly signed; only the link is wrong
    assert any(f["sequence"] == seq(chain.S) + 1 for f in failure(report, "link_broken"))


def test_a_sequence_gap(chain, tmp_path):
    rows = rows_of(chain.export)
    del rows[3]
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", export_of(rows)))
    assert proc.returncode == 1 and "sequence_gap" in codes(report)


def test_a_duplicate_position_is_sequence_duplicate_and_equivocation(chain, tmp_path):
    rows = rows_of(chain.export)
    s_prime = chain.remint()
    i = next(k for k, r in enumerate(rows) if r["record"]["receipt_hash"] == chain.S["receipt_hash"])
    rows.insert(i + 1, {"record": s_prime})
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", export_of(rows)))
    assert proc.returncode == 1 and {"sequence_duplicate", "equivocation"} <= codes(report)
    (f,) = failure(report, "equivocation")
    assert {r["receipt_hash"] for r in f["records"]} == {chain.S["receipt_hash"], s_prime["receipt_hash"]}


def test_an_export_not_from_genesis(chain, tmp_path):
    rows = rows_of(chain.export)[1:]
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", export_of(rows)))
    assert proc.returncode == 1 and "export_not_from_genesis" in codes(report)


def test_a_one_character_tamper_in_the_export_is_signature_invalid(chain, tmp_path):
    rows = rows_of(chain.export)
    rows[3] = {"record": tamper_one_char(rows[3]["record"])}
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", export_of(rows)))
    assert proc.returncode == 1 and "signature_invalid" in codes(report)
    sig = rows_of(chain.export)
    r = dict(sig[2]["record"])
    raw = bytearray(base64.b64decode(r["signature"]))
    raw[0] ^= 1
    r["signature"] = base64.b64encode(bytes(raw)).decode()
    sig[2] = {"record": r}
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e2.json", export_of(sig)))
    assert proc.returncode == 1 and "signature_invalid" in codes(report)


def test_a_tampered_held_record_is_held_record_invalid_and_accuses_nothing(chain, tmp_path):
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export),
                       [write(tmp_path, "h.json", tamper_one_char(chain.D))])
    assert proc.returncode == 1 and codes(report) == {"held_record_invalid"}


def test_a_held_record_of_another_scope(clock, tmp_path, chain):
    chain.fake.chain_scope = "requisition-lab:account:00000000-0000-4000-8000-0000000000f2"
    (other,) = chain.fake.pump_denies(1)
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export),
                       [write(tmp_path, "h.json", other)])
    assert proc.returncode == 1 and "held_other_scope" in codes(report)


def test_a_non_account_scope_is_refused(clock, tmp_path):
    c = Chain(clock, tmp_path, scope="requisition-lab:permit:00000000-0000-4000-8000-0000000000f3")
    try:
        proc, report = run(tmp_path, c.fake.registry, write(tmp_path, "e.json", c.export))
        assert proc.returncode == 2 and "account" in (proc.stderr + proc.stdout)
    finally:
        c.stop()


@pytest.mark.parametrize("cosign,ok", [("signed", True), ("seat_absent", False), ("signed_bytes_over_bound", False)])
def test_require_pq_on_agent_tool_records(clock, tmp_path, cosign, ok):
    c = Chain(clock, tmp_path, cosign=cosign)
    try:
        export = write(tmp_path, "e.json", c.export)
        proc, report = run(tmp_path, c.fake.registry, export, [], "--require-pq")
        if ok:
            assert proc.returncode == 0 and report["result"] == "ok", report
        else:
            assert proc.returncode == 1 and codes(report) == {"pq_missing"}
        # without --require-pq an Ed25519-only agent-tool record is not a failure
        proc, report = run(tmp_path, c.fake.registry, export)
        assert proc.returncode == 0
    finally:
        c.stop()


def test_require_pq_a_stripped_cosignature_is_pq_missing(clock, tmp_path):
    c = Chain(clock, tmp_path, cosign="signed")
    try:
        rows = rows_of(c.export)
        i = next(k for k, r in enumerate(rows) if r["record"]["receipt_hash"] == c.D["receipt_hash"])
        rows[i] = {"record": rows[i]["record"]}
        proc, report = run(tmp_path, c.fake.registry, write(tmp_path, "e.json", export_of(rows)), [], "--require-pq")
        assert proc.returncode == 1 and "pq_missing" in codes(report)
        csv_path = tmp_path / "e.csv"
        csv_path.write_text(to_csv(rows_of(c.export)))
        proc, report = run(tmp_path, c.fake.registry, csv_path, [], "--require-pq")
        assert proc.returncode == 0, report
    finally:
        c.stop()


def test_require_pq_does_not_apply_to_records_without_a_cosign_member(chain, tmp_path):
    # the fake without cosign signs no cosign member: like every non-agent-tool record, Ed25519 only
    proc, report = run(tmp_path, chain.fake.registry, write(tmp_path, "e.json", chain.export), [], "--require-pq")
    assert proc.returncode == 0 and report["result"] == "ok"


# --- the real lab records (tests/fixtures/real_lab_chain, PROVENANCE.md) -------------------------


def real_rows(paths):
    rows = []
    for p in paths:
        obj = json.loads(p.read_text())
        env = obj.get("record") or obj.get("statement") or obj.get("decision")
        rows.append({"record": env, "cosignature": obj["cosignature"]})
    return rows


AWS_INSTANCE_RUN = [REAL / "aws-instance/20261109T213617Z/statement.json", REAL / "aws-instance/20261109T213617Z/v0-4.json",
         REAL / "aws-instance/20261109T214355Z/statement.json", REAL / "aws-instance/20261109T214355Z/v0-6.json"]
AWS_INSTANCE_KEYS = REAL / "aws-instance/instance-lab-keys.json"
DRESS = [REAL / "dress-1/1-strands/01-statement.record.json", REAL / "dress-1/1-strands/02-decision.record.json",
         REAL / "dress-1/1-strands/03-outcome.record.json", REAL / "dress-1/1-strands/04-decision.record.json",
         REAL / "dress-1/2-interceptor/01-decision.record.json", REAL / "dress-1/3-target/01-statement.record.json",
         REAL / "dress-1/3-target/02-decision.record.json", REAL / "dress-1/3-target/03-outcome.record.json"]
DRESS_KEYS = REAL / "dress-1/lab-keys.json"
REAL_LABEL = "assembled in the test from real lab records (tests/fixtures/real_lab_chain/PROVENANCE.md); a window, not a whole export"


def test_real_aws_instance_window_verifies_every_signature_and_link_pq_included(tmp_path):
    export = write(tmp_path, "e.json", export_of(real_rows(AWS_INSTANCE_RUN), REAL_LABEL))
    proc, report = run(tmp_path, AWS_INSTANCE_KEYS, export, [REAL / "aws-instance/20261109T214355Z/v0-6.json"], "--require-pq")
    # sequences 3..6 only: correctly not from genesis; nothing else is wrong with the real bytes
    assert proc.returncode == 1 and codes(report) == {"export_not_from_genesis"}, report["failures"]


def test_real_dress_window_shows_the_real_gap_at_7(tmp_path):
    export = write(tmp_path, "e.json", export_of(real_rows(DRESS), REAL_LABEL))
    held = [REAL / "dress-1/2-interceptor/01-decision.record.json", REAL / "dress-1/2-interceptor/02-decision.record.json"]
    proc, report = run(tmp_path, DRESS_KEYS, export, held, "--require-pq")
    assert proc.returncode == 1
    assert {"export_not_from_genesis", "sequence_gap"} <= codes(report) <= {"export_not_from_genesis", "sequence_gap",
                                                                            "link_broken"}
    assert any(f["sequence"] in (7, 8) for f in failure(report, "sequence_gap"))
    # the reused-id replay saved the same record twice: one record, not an equivocation, and the export agrees


def test_real_held_record_past_a_truncated_window_is_export_short(tmp_path):
    export = write(tmp_path, "e.json", export_of(real_rows(AWS_INSTANCE_RUN[:3]), REAL_LABEL))
    proc, report = run(tmp_path, AWS_INSTANCE_KEYS, export, [AWS_INSTANCE_RUN[3]])
    assert proc.returncode == 1 and "export_short" in codes(report)


def test_real_one_character_tamper_is_signature_invalid(tmp_path):
    rows = real_rows(AWS_INSTANCE_RUN)
    rows[1] = {"record": tamper_one_char(rows[1]["record"]), "cosignature": rows[1]["cosignature"]}
    proc, report = run(tmp_path, AWS_INSTANCE_KEYS, write(tmp_path, "e.json", export_of(rows, REAL_LABEL)))
    assert proc.returncode == 1 and "signature_invalid" in codes(report)
    held = json.loads(AWS_INSTANCE_RUN[3].read_text())
    held["decision"] = tamper_one_char(held["decision"])
    proc, report = run(tmp_path, AWS_INSTANCE_KEYS, write(tmp_path, "e2.json", export_of(real_rows(AWS_INSTANCE_RUN), REAL_LABEL)),
                       [write(tmp_path, "h.json", held)])
    assert "held_record_invalid" in codes(report)


# --- bin/export_chain.sh: the read-only SQL export ----------------------------------------------


def fake_psql(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "psql.log"
    script = bindir / "psql"
    script.write_text("#!/bin/sh\n{ printf '%s\\n' \"$@\"; echo '--- stdin'; cat; } >> " + str(log) + "\n"
                      "echo 'chain_scope,sequence,signature,key_id,signed_payload,receipt_hash,cosignature,cosignature_key_id'\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return bindir, log


def test_export_script_is_read_only_ordered_and_passes_the_scope_as_a_variable(tmp_path):
    bindir, log = fake_psql(tmp_path)
    scope = "requisition-lab:account:8979bed4-d48f-4552-98fd-b479e90ef061"
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "PGDATABASE": "scratch_db"}
    proc = subprocess.run(["bash", str(EXPORT_SCRIPT), scope], capture_output=True, text=True, env=env, input="", timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines()[0] == ",".join(CSV_COLUMNS)
    seen = log.read_text()
    sql = seen + EXPORT_SCRIPT.read_text()
    assert f"scope={scope}" in seen  # the scope reaches psql as a variable, never spliced into the SQL
    low = sql.lower()
    assert "authority_lab_receipts" in low and "order by sequence" in low and "read only" in low
    for column in CSV_COLUMNS:
        assert column in low
    for verb in ("insert ", "update ", "delete ", "drop ", "truncate ", "alter ", "grant "):
        assert verb not in seen.lower()  # what psql was given


def test_export_script_refuses_a_non_account_scope_before_psql(tmp_path):
    bindir, log = fake_psql(tmp_path)
    env = {"PATH": f"{bindir}:/usr/bin:/bin"}
    for bad in ("requisition-lab:permit:x", "x'; drop table authority_lab_receipts; --", ""):
        proc = subprocess.run(["bash", str(EXPORT_SCRIPT), bad], capture_output=True, text=True, env=env, input="",
                              timeout=30)
        assert proc.returncode == 2
    assert not log.exists()
