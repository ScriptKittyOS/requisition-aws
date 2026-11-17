# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The shared intake vectors (tests/vectors/intake/intake.json, the same bytes requisition-ts replays), replayed
against this checkout's intake: every raw JSON text through ``loads_tool_call`` (the tool-call body reader) and
``check_arguments`` (its code and
path, or its canonical bytes), and every argument object through ``ArgsSchema.validate``."""

import base64
import hashlib
import json
import pathlib
import re

import pytest

from requisition_aws import canonical
from requisition_aws.client import loads_tool_call

HERE = pathlib.Path(__file__).resolve().parent / "vectors" / "intake"
VECTORS = json.loads((HERE / "intake.json").read_text(encoding="ascii"))


def test_the_vector_file_is_the_one_its_provenance_records():
    provenance = (HERE / "PROVENANCE.md").read_text(encoding="utf-8")
    recorded = re.search(r"^\| `intake\.json` \| `([0-9a-f]{64})` \|$", provenance, re.M).group(1)
    assert hashlib.sha256((HERE / "intake.json").read_bytes()).hexdigest() == recorded
    tree = re.search(r"^requisition_aws tree: `([0-9a-f]{40})`", provenance, re.M).group(1)
    assert VECTORS["meta"]["requisition_aws_tree"] == tree


@pytest.mark.parametrize("row", VECTORS["raw"], ids=lambda row: row["text"])
def test_raw_text_intake_answers_as_recorded(row):
    if row.get("parse") == "refused":
        with pytest.raises(ValueError):
            loads_tool_call(row["text"])
        return
    value = loads_tool_call(row["text"])
    if row["code"] is None:
        canonical.check_arguments(value)
        assert canonical.encode(value) == base64.b64decode(row["bytes_b64"])
        return
    with pytest.raises(canonical.IntakeRefusal) as err:
        canonical.check_arguments(value)
    assert (err.value.code, err.value.path) == (row["code"], row["path"])


@pytest.mark.parametrize("row", VECTORS["schema"], ids=lambda row: row["what"])
def test_schema_intake_answers_as_recorded(row):
    schema = canonical.ArgsSchema(VECTORS["schema_entries"])
    if row["code"] is None:
        schema.validate(row["args"])
        return
    with pytest.raises(canonical.IntakeRefusal) as err:
        schema.validate(row["args"])
    assert (err.value.code, err.value.path) == (row["code"], row["path"])


def test_the_vectors_carry_the_float_cases():
    floats = {row["text"] for row in VECTORS["raw"] if row.get("code") == "float_refused"}
    assert {'{"a":-0.0}', '{"a":1e5}', '{"a":{"b":[0,{"c":-1.25}]}}', '{"act_type":1.5}', '{"members":[0.5]}'} <= floats
    big = {row["text"]: (row.get("code"), row.get("path")) for row in VECTORS["raw"]}
    for text, path in (('{"a":9007199254740992}', "a"), ('{"a":-100000000000000000000000}', "a"),
                       ('{"a":{"b":[0,-9007199254740993]}}', "a.b.1")):
        assert big[text] == ("malformed_member", path), text
    assert sorted(row["what"] for row in VECTORS["schema"] if row["code"] == "float_refused") == [
        "account float", "amount -0.0", "amount float", "amount integral float", "extra float arg", "tool float"]
