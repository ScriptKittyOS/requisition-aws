# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""ONE explicit bound on every strict JSON reader -- nesting of at most 64 containers and
integers within +-(2^53-1), the range CanonicalPayload v3 allows -- the same in Python (these readers), TypeScript
(parseBounded) and Elixir (LabKeyRule.decode_bounded/1). The documents are the shared vector file's `documents` section.
A refusal is a ValueError, never a RecursionError or a traceback."""

import importlib.util
import json
import pathlib

import pytest

from requisition_aws import canonical
from requisition_aws.client import loads_strict as package_loads
from requisition_aws.keys import KeyRegistry

from . import key_rule_harness as H

BIN = pathlib.Path(__file__).resolve().parent.parent / "bin"
DOCS = json.loads(H.VECTOR_FILE.read_text())["documents"]


def _load(name):
    spec = importlib.util.spec_from_file_location(name + "_bounds_under_test", BIN / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


READERS = {"package": package_loads, "verify_chain": _load("verify_chain").loads_strict,
           "verify_offline": _load("verify_offline").loads_strict}


@pytest.mark.parametrize("reader", sorted(READERS))
@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d["name"])
def test_every_reader_applies_the_shared_bound(reader, doc):
    if doc["expect"] == "ok":
        READERS[reader](doc["text"])
    else:
        with pytest.raises(ValueError):
            READERS[reader](doc["text"])


@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_hundred_thousand_deep_document_is_a_refusal_not_a_recursion_error(reader):
    with pytest.raises(ValueError):
        READERS[reader]("[" * 100_000 + "]" * 100_000)


def test_a_deep_signed_payload_is_a_reasoned_refusal_of_the_gates_key_check():
    vector = next(v for v in H.load_vectors() if v["name"] == "active_open_inside")
    registry, envelope = H.build(vector, "ed25519")
    keys = KeyRegistry.from_bytes(json.dumps(registry).encode())
    deep = "[" * 100_000 + "]" * 100_000
    envelope = {**envelope, "signed_payload": deep}
    assert keys.check(envelope) == "signed_instant_unreadable"
    assert keys.pq_expected(envelope) is False


def test_the_canonical_range_is_the_bound():
    assert json.loads(H.VECTOR_FILE.read_text())["max_integer"] == canonical.MAX_INTEGER
