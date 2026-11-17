# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""bin/verify_offline.py's own part of the log checkpoint checks (CHECKPOINTS.md): it hands the flags to bin/lab-verify
as given, with the co-signature beside the record; it FAILS with exit 6 on a checkpoint_ verdict, and on a pass that
does not say every checkpoint check held; without the flags it hands on nothing new. The checks themselves are
Requisition's verify_receipt.py's, run over the evaluation environment's vectors by Requisition's
checkpoint_verifiers_parity_test.exs. Here bin/lab-verify is a stand-in that records what it was given and answers as
told, so each part of this file is seen alone."""

import json
import subprocess
import sys

from .test_verify_offline import SCRIPT, records  # noqa: F401 (the fixture)

from .conftest import ACT_TYPE

HELD = "log checkpoint: all checks held: inclusion, witness quorum, not older than the held size"
FLAGS = ["--checkpoint", "n", "--inclusion-proof", "p.json", "--witness-policy", "w", "--held-size", "3",
         "--held-root", "r", "--consistency-proof", "c.json", "--key-transition", "t.json"]

STAND_IN = r'''
import json, sys
args = sys.argv[1:]
with open(sys.argv[0] + ".seen", "w") as handle:
    json.dump({"args": args, "record": json.load(open(args[args.index("--receipt") + 1]))}, handle)
answer = open(sys.argv[0] + ".answer").read()
print(answer)
sys.exit(5)
'''


def _stand_in(tmp_path, answer):
    script = tmp_path / "lab-verify"
    script.write_text(STAND_IN)
    (tmp_path / "lab-verify.answer").write_text(answer)
    return script


def _run(paths, record, lab_verify, extra):
    proc = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--arguments", str(paths["args"]), "--act-type", ACT_TYPE,
         "--record", str(paths[record]), "--lab-verify", str(lab_verify), "--registry", str(paths["registry"])] + extra,
        capture_output=True, text=True, timeout=120,
    )
    return proc, json.loads((lab_verify.parent / "lab-verify.seen").read_text())


def _with_cosignature(paths, tmp_path):
    decision = json.loads(paths["allow"].read_text())["decision"]
    cosignature = dict(decision, signature="AAAA", key_id="a-co-signing-key")
    path = tmp_path / "cosigned.json"
    path.write_text(json.dumps({"decision": decision, "cosignature": cosignature}))
    return path, cosignature


def test_the_flags_and_the_co_signature_are_handed_on_only_with_the_checkpoint(records, tmp_path):  # noqa: F811
    lab_verify = _stand_in(tmp_path, "lab checks.\n" + HELD + "\n\nverdict_code: lab_dev_key")
    records["cosigned"], cosignature = _with_cosignature(records, tmp_path)
    _proc, seen = _run(records, "cosigned", lab_verify, FLAGS + ["--write-held-state"])
    assert seen["args"][-len(FLAGS) - 1:] == FLAGS + ["--write-held-state"]
    assert seen["record"]["cosignature"] == cosignature
    _proc, seen = _run(records, "cosigned", lab_verify, [])
    assert not any(flag in seen["args"] for flag in FLAGS[::2])
    assert "cosignature" not in seen["record"]


def test_a_checkpoint_refusal_fails_with_exit_6_naming_it(records, tmp_path):  # noqa: F811
    lab_verify = _stand_in(tmp_path, "TRUST NOT ESTABLISHED -- the log checkpoint.\n\nverdict_code: checkpoint_quorum_not_met")
    proc, _seen = _run(records, "allow", lab_verify, FLAGS)
    assert proc.returncode == 6, proc.stdout
    assert "verdict: FAIL (the log checkpoint: checkpoint_quorum_not_met)" in proc.stdout


def test_a_pass_that_does_not_say_every_check_held_fails_with_exit_6(records, tmp_path):  # noqa: F811
    lab_verify = _stand_in(tmp_path, "lab checks.\n\nverdict_code: lab_dev_key")
    proc, _seen = _run(records, "allow", lab_verify, FLAGS)
    assert proc.returncode == 6, proc.stdout
    assert "verdict: FAIL (the log checkpoint: bin/lab-verify did not say every check held)" in proc.stdout


def test_a_pass_with_every_check_held_says_what_the_checkpoint_shows(records, tmp_path):  # noqa: F811
    lab_verify = _stand_in(tmp_path, "lab checks.\n" + HELD + "\n\nverdict_code: lab_dev_key")
    proc, _seen = _run(records, "allow", lab_verify, FLAGS)
    assert proc.returncode == 0, proc.stdout
    assert "== 4. the log checkpoint" in proc.stdout and "  " + HELD in proc.stdout
    assert "not older than the tree size given (section 4)." in proc.stdout
    proc, _seen = _run(records, "allow", lab_verify, [])
    assert proc.returncode == 0 and "== 4." not in proc.stdout and "section 4" not in proc.stdout


def test_a_usage_error_in_the_checkpoint_inputs_is_exit_2(records, tmp_path):  # noqa: F811
    lab_verify = _stand_in(tmp_path, "usage: --held-size and --held-root go together")
    (tmp_path / "lab-verify").write_text(STAND_IN.replace("sys.exit(5)", "sys.exit(2)"))
    proc, _seen = _run(records, "allow", lab_verify, FLAGS)
    assert proc.returncode == 2, proc.stdout
    assert "verdict: FAIL (usage: the log checkpoint's inputs, as bin/lab-verify reports them above)" in proc.stdout
