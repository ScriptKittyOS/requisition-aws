# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The offline verifier a stranger runs (bin/verify_offline.py) carries no workflow wording: no private path, no
name of who runs what, no review round or ruling number, no internal gap, issue, plan or finding id, no agent name or
trailer, no session link. The list is Requisition's verifier wording census's (its
test/autonomous_agency/authority/verifier_wording_census_test.exs), one pattern per name. One exception by value:
the hands label Requisition signs into every lab record.

Every pattern below is split into pieces, so that this file does not match itself."""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
FILES = ["bin/verify_offline.py", "CHECKPOINTS.md"]
SIGNED_LABEL = "one-person (G" + "-301)"
PATTERNS = {
    "private_path": re.compile(r"/ho" + r"me/|/Use" + r"rs/|\.scr" + r"atch-|project" + r"-sanction|script-kitty" + r"-projects|HAND"
                               + r"OFF|/run/u" + r"ser/"),
    "coordi" "nator": re.compile(r"\bcoordi" + r"nators?\b", re.I),
    "the_lead": re.compile(r"\bthe le" + r"ad\b", re.I),
    "lane": re.compile(r"\bla" + r"nes?\b", re.I),
    "builder": re.compile(r"\bbuil" + r"ders?\b", re.I),
    "reviewer": re.compile(r"\brevie" + r"wers?\b", re.I),
    "review_name": re.compile(r"\b(build|reds|crypto|delta|stack|landed|code) rev" + r"iews?\b|\brev" + r"iew (item|[0-9])|\bS[0-9]{2} rev"
                              + r"iew\b", re.I),
    "round": re.compile(r"\b(review|fix|delta|first|second|third|next|last) rou" + r"nds?\b|\brou" + r"nd[ -]?[0-9]+\b", re.I),
    "owners_go": re.compile(r"\bowner'?s (own-words )?(g" + r"o|o" + r"k)\b|\bgo from the own" + r"er\b", re.I),
    "ruling": re.compile(r"\brul" + r"ings?\b|\brul" + r"ed\b", re.I),
    "decision_number": re.compile(r"\bDecis" + r"ion [0-9a-f]{6,}\b|\bpublisher Decis" + r"ion\b"),
    "ruling_number": re.compile(r"\b" + r"D-?[0-9]{1,3}\b"),
    "plan": re.compile(r"\bPL" + r"AN\b|\bthe pl" + r"an'?s?\b", re.I),
    "hand_back": re.compile(r"\bhand-?ba" + r"cks?\b", re.I),
    "tracker_id": re.compile(r"\b(SC" + r"R|RE" + r"Q|PLA" + r"T)-[0-9]+\b"),
    "gap_id": re.compile(r"\bG" + r"-[0-9]{3}\b|\bG" + r"AP\b"),
    "finding_id": re.compile(r"\bL" + r"0\b|\bL" + r"0-|\bK" + r"1\b|\bW" + r"1-[0-9]|\bR1" + r"89-|\bR[0-9]-[0-9]\b|\b[FC]-[0-9]+\b|\bB[0-9]{1,2}\b"
                             + r"|\bthe re" + r"ds\b"),
    "agent": re.compile(r"\bsub-?age" + r"nts?\b|\bcla" + r"ude\b|anthr" + r"opic|\bsonn" + r"et\b|\bop" + r"us\b|\bfab" + r"le\b", re.I),
    "trailer": re.compile(r"co-autho" + r"red-by|assist" + r"ed-by|claude-se" + r"ssion|generated w" + r"ith", re.I),
    "session_link": re.compile(r"claude" + r"\.ai/|/sess" + r"ion_", re.I),
}


def _hits(label, text):
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.replace(SIGNED_LABEL, "")
        out += ["%s:%d (%s)" % (label, number, name) for name, rx in PATTERNS.items() if rx.search(line)]
    return out


def test_the_published_verifier_files_carry_no_workflow_wording():
    found = []
    for name in FILES:
        path = REPO / name
        assert path.is_file(), "%s is absent" % name
        found += _hits(name, path.read_text(encoding="utf-8"))
    assert found == [], found


def test_the_census_finds_each_pattern_and_spares_the_signed_label():
    planted = ["/ho" "me/x", "the coordi" "nator", "the le" "ad", "La" "ne 2a", "the buil" "der", "a revie" "wer",
               "build rev" "iew", "fix rou" "nd 1", "the owner's g" "o", "the rul" "ing", "Decis" "ion 5eed" "f00d", "D" "987",
               "PL" "AN r3", "the hand-ba" "ck", "RE" "Q-901", "G" "-901", "L" "0-Z9", "Cla" "ude", "Co-Autho" "red-By: x",
               "claude" ".ai/code"]
    for line in planted:
        assert _hits("planted", line), line
    assert _hits("planted", '"hands": "%s"' % SIGNED_LABEL) == []
