# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""bin/verify_offline.py and bin/verify_chain.py read JSON by the same
rule as requisition_aws.client.loads_strict: RFC 8259 only (section 6: no NaN, Infinity or
-Infinity), no number whose value is not a finite double, bytes as strict UTF-8 (section 8.1: no UTF-16/32,
no surrogatepass, no BOM), duplicate members refused. Both files run under ``python3 -I`` with the standard
library only (their own headers: verify_offline.py:62-65, verify_chain.py:5), so each carries its own copy of
the rule; this file pins every copy to the package's on the same vectors, and runs each CLI end to end.
The vendored crypto (bin/vendor/) is not involved."""

import importlib.util
import json
import pathlib

import pytest

from requisition_aws.client import loads_strict as package_loads

from .test_verify_chain import chain, run as run_chain, write  # noqa: F401  (chain is a fixture)
from .test_verify_offline import records, run as run_offline  # noqa: F401  (records: fixture)

BIN = pathlib.Path(__file__).resolve().parent.parent / "bin"


def _load(name):
    spec = importlib.util.spec_from_file_location(name + "_strict_json_under_test", BIN / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CLIS = {"verify_offline": _load("verify_offline"), "verify_chain": _load("verify_chain")}

REFUSED_TEXT = [
    "NaN", "Infinity", "-Infinity", '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}', '[1,NaN]',
    '{"a":{"b":[Infinity]}}', "1e400", "-1e400", '{"a":1E999}', "[10.0e308]", "﻿{}",
    '{"a":1,"a":2}', '{"a":{"b":1,"b":1}}',
    "12345678901234567890",  # an integer outside +-(2^53-1) is outside the canonical form: refused by every reader
    "nan", "inf", "01", "+1", ".5", "1.", "[1,]", "{'a':1}", '{"a":1} x', "", " ", "\x0b{}",
]
REFUSED_BYTES = [
    b"\xef\xbb\xbf{}", '{"a":1}'.encode("utf-16-le"), '{"a":1}'.encode("utf-16-be"), '{"a":1}'.encode("utf-16"),
    '{"a":1}'.encode("utf-32-le"), '{"a":1}'.encode("utf-32"), b'"\xed\xa0\x80"', b'{"a":"\xed\xb0\x80"}',
    b'{"a":"\xff"}', b'{"a":"\xc0\xaf"}',
]
ACCEPTED = [
    ('{"a":1}', {"a": 1}), ("[1.5,-0,1e308,-2.5E-3]", [1.5, 0, 1e308, -2.5e-3]), ('"\\u00e9"', "é"),
    (' \t\r\n{"a":[true,false,null]} \n', {"a": [True, False, None]}),
    ('{"a":"é€\U0001f600"}', {"a": "é€\U0001f600"}),
]


def outcome(fn, data):
    try:
        return ("value", fn(data))
    except ValueError:
        return ("refused", None)


@pytest.mark.parametrize("cli", sorted(CLIS))
@pytest.mark.parametrize("text", REFUSED_TEXT)
def test_each_cli_refuses_what_loads_strict_refuses(cli, text):
    reader = CLIS[cli].loads_strict
    for data in (text, text.encode("utf-8")):
        with pytest.raises(ValueError):
            reader(data)
        assert outcome(reader, data) == outcome(package_loads, data) == ("refused", None)


@pytest.mark.parametrize("cli", sorted(CLIS))
@pytest.mark.parametrize("data", REFUSED_BYTES, ids=bytes.hex)
def test_each_cli_refuses_bytes_that_are_not_utf8_json(cli, data):
    with pytest.raises(ValueError):
        CLIS[cli].loads_strict(data)
    assert outcome(package_loads, data) == ("refused", None)


@pytest.mark.parametrize("cli", sorted(CLIS))
@pytest.mark.parametrize("text, value", ACCEPTED)
def test_each_cli_still_reads_rfc_8259_json_as_the_package_does(cli, text, value):
    for data in (text, text.encode("utf-8")):
        assert CLIS[cli].loads_strict(data) == package_loads(data) == value


def test_every_json_read_in_the_clis_goes_through_the_strict_reader():
    for name in CLIS:
        source = (BIN / f"{name}.py").read_text()
        reads = [line.strip() for line in source.splitlines() if "json.load" in line]
        assert reads and all("json.loads(data, object_pairs_hook=" in line for line in reads), (name, reads)


# --- end to end: the CLI refuses the input as unreadable, never verifies past it ----------------------------


def nan_member(obj):
    text = json.dumps(obj)
    assert text.endswith("}")
    return text[:-1] + ', "x": NaN}'


def test_verify_chain_refuses_a_registry_or_an_export_carrying_nan(chain, tmp_path):
    export = write(tmp_path, "e.json", chain.export)
    proc, _ = run_chain(tmp_path, chain.fake.registry, export)
    assert proc.returncode == 0, proc.stderr  # the control: the same inputs without NaN
    registry = tmp_path / "registry-nan.json"
    registry.write_text(nan_member(chain.fake.registry))
    proc, report = run_chain(tmp_path, registry, export)
    assert proc.returncode == 2 and report is None and "verify_chain:" in proc.stderr
    bad_export = tmp_path / "e-nan.json"
    bad_export.write_text(nan_member(chain.export))
    proc, report = run_chain(tmp_path, chain.fake.registry, bad_export)
    assert proc.returncode == 2 and report is None and "verify_chain:" in proc.stderr


def test_verify_offline_refuses_a_registry_with_nan_or_arguments_with_a_bom(records, tmp_path):
    proc = run_offline(records, "allow")
    assert proc.returncode == 0, proc.stdout + proc.stderr  # the control
    registry = tmp_path / "registry-nan.json"
    registry.write_text(nan_member(json.loads(records["registry"].read_text())))
    proc = run_offline(records, "allow", registry=registry)
    assert proc.returncode == 1 and "binding: UNREADABLE" in proc.stdout and "verdict: PASS" not in proc.stdout
    args = tmp_path / "args-bom.json"
    args.write_bytes(b"\xef\xbb\xbf" + records["args"].read_bytes())
    proc = run_offline(records, "allow", args=args)
    assert proc.returncode == 1 and "binding: UNREADABLE" in proc.stdout and "verdict: PASS" not in proc.stdout
