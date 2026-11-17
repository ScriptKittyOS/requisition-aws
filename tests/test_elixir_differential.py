# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The Python port against answers the compiled Elixir modules gave (see fixtures/elixir_differential/PROVENANCE.md)."""

import base64
import json
import pathlib

from requisition_aws import canonical

HERE = pathlib.Path(__file__).parent / "fixtures" / "elixir_differential"


def _load(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def test_redact_text_matches_elixir_on_4010_strings():
    cases, answers = _load("redact_cases.json"), _load("redact_out.json")
    assert len(cases) == len(answers) == 4010
    mismatches = [(c, a) for c, a in zip(cases, answers) if canonical.redact_text(c) != a]
    assert mismatches == []
    # the corpus exercises both sides
    assert sum(c != a for c, a in zip(cases, answers)) > 1000


def test_encode_matches_elixir_on_1500_terms():
    cases, answers = _load("enc_cases.json"), _load("enc_out.json")
    assert len(cases) == len(answers) == 1500
    for term, answer in zip(cases, answers):
        assert canonical.encode(term) == base64.b64decode(answer)
