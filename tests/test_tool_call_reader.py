# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""An integer outside +-(2^53-1) in a tool call's ARGUMENTS gets intake's answer, malformed_member, the name Requisition
and requisition-ts give it: tool-call bodies are read by ``client.loads_tool_call``, which is ``loads_strict`` without the
integer bound (duplicate members, NaN and Infinity, a number that is not a finite double, bytes that are not UTF-8, a
byte order mark and nesting deeper than 64 are still refused). The JSON-RPC id enters the call's idempotency key, so a
tools/call whose id is an integer outside the bound is refused as an invalid request, as requisition-ts refuses it. Any
other large integer in the body is not used for anything Requisition sees, and passes, as in requisition-ts.

Every read that used ``loads_strict`` before keeps it, pinned below by call site over every Python file of the
repository outside tests/. Reads with plain ``json.loads`` are not covered by this pin."""

import ast
import copy
import json
import pathlib

import pytest

from requisition_aws import client as rclient
from requisition_aws import interceptor as icp
from requisition_aws.client import loads_strict

from . import test_interceptor as ti
from . import test_mcp_target as tm
from .conftest import refund_args
from .test_interceptor import ic  # noqa: F401 (a fixture)

BIG = 2**53  # one past the bound
REPO = pathlib.Path(__file__).resolve().parent.parent


# --- the reader --------------------------------------------------------------------------------------


def test_the_tool_call_reader_keeps_a_large_integer_and_every_other_refusal():
    read = rclient.loads_tool_call
    assert read('{"a":9007199254740992,"b":[-100000000000000000000000]}') == {"a": BIG, "b": [-10**23]}
    assert read("1" + "0" * 300) == 10**300  # a finite double
    for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}', '{"a":1e400}',
                 '{"a":1' + "0" * 400 + "}", "﻿{}", "[" * 65 + "]" * 65):
        with pytest.raises(ValueError):
            read(text)
    with pytest.raises(ValueError):
        read(b'{"a":"\xff"}')


def test_loads_strict_keeps_the_bound():
    for text in ('{"a":9007199254740992}', '{"a":-9007199254740992}', '[1,{"b":100000000000000000000000}]'):
        with pytest.raises(ValueError):
            loads_strict(text)
    assert loads_strict('{"a":9007199254740991}') == {"a": 2**53 - 1}


# --- which read uses which reader: an exact list over every Python file outside tests/ -------------------

# (file, enclosing function, or "<module>") of every call; the unbounded reader is for a caller's tool-call body only
TOOL_CALL_READS = {
    ("requisition_aws/interceptor.py", "_raw_matches"),
    ("requisition_aws/mcp_target.py", "handle_http"),
}
BOUNDED_READS = {
    ("bin/verify_chain.py", "_json"),
    ("bin/verify_offline.py", "_occurred_at"),
    ("bin/verify_offline.py", "check_binding"),
    ("bin/verify_offline.py", "check_cosignature"),
    ("bin/verify_offline.py", "load"),
    ("bin/verify_offline.py", "main"),
    ("deploy/gateway/capture_tools_list.py", "live_pages"),
    ("deploy/gateway/capture_tools_list.py", "main"),
    ("deploy/registration/fill_gateway_digest.py", "main"),
    ("requisition_aws/caller.py", "_key"),
    ("requisition_aws/client.py", "_json"),
    ("requisition_aws/client.py", "_optional"),
    ("requisition_aws/fence.py", "position_of"),
    ("requisition_aws/gate.py", "_send"),
    ("requisition_aws/gate.py", "_signed"),
    ("requisition_aws/interceptor.py", "caller_from_env"),
    ("requisition_aws/keys.py", "_occurred_at"),
    ("requisition_aws/keys.py", "_parse"),
    ("requisition_aws/settings.py", "json_map"),
}


SKIPPED_PARTS = {"tests", ".venv", ".git", "__pycache__", ".pytest_cache", "node_modules"}


def _population():
    """Every .py file of the checkout outside tests/ (and the environment and caches): derived, never a folder list."""
    return sorted(p for p in REPO.rglob("*.py") if not SKIPPED_PARTS & set(p.relative_to(REPO).parts))


def _calls(name):
    found = set()

    def visit(node, where, rel):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else where
            if isinstance(child, ast.Call):
                f = child.func
                called = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
                if called == name:
                    found.add((rel, where))
            visit(child, inner, rel)

    for path in _population():
        visit(ast.parse(path.read_text(encoding="utf-8")), "<module>", str(path.relative_to(REPO)))
    return found


def test_the_census_reads_every_folder_that_holds_python_outside_tests():
    folders = {p.relative_to(REPO).parts[0] for p in _population()}
    assert {"bin", "demo", "deploy", "requisition_aws"} <= folders, folders


def test_only_the_tool_call_body_reads_drop_the_integer_bound():
    assert _calls("loads_tool_call") == TOOL_CALL_READS


def test_every_verifier_key_response_and_record_read_keeps_the_bound():
    assert _calls("loads_strict") == BOUNDED_READS


def test_a_record_and_a_key_file_with_a_large_integer_are_still_refused():
    from requisition_aws import fence, keys

    record = {"signed_payload": json.dumps({"chain_scope": "s", "sequence": BIG})}
    with pytest.raises(ValueError):
        fence.position_of(record)
    with pytest.raises(Exception):
        keys.KeyRegistry.from_bytes(json.dumps({"entries": [], "n": BIG}).encode())


# --- the MCP target ------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", [BIG, -BIG, 10**23])
def test_mcp_target_a_large_integer_argument_is_malformed_member(fake, tmp_path, clock, value):
    target, ledger, _ = tm.make_target(fake, tmp_path, clock)
    status, body = tm.call(target, 1, refund_args(amount_minor=value))
    assert status == 200 and body["result"]["isError"] is True, body
    assert "(malformed_member)" in body["result"]["content"][0]["text"]
    assert fake.requests == {} and ledger.entries() == []


def test_mcp_target_a_tools_call_with_a_large_integer_id_is_an_invalid_request(fake, tmp_path, clock):
    target, ledger, _ = tm.make_target(fake, tmp_path, clock)
    status, body = tm.call(target, BIG, refund_args())
    assert body["error"]["code"] == -32600 and "id" in body["error"]["message"], body
    assert fake.requests == {} and ledger.entries() == []


def test_mcp_target_a_large_integer_elsewhere_in_the_body_passes(fake, tmp_path, clock):
    target, _, _ = tm.make_target(fake, tmp_path, clock)
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": tm.TOOL, "arguments": refund_args(), "_meta": dict(tm.CLIENT_META, **{"x.example/n": BIG})}}
    status, body = tm.post(target, msg, {"mcp-protocol-version": tm.MODERN, "mcp-method": "tools/call", "mcp-name": tm.TOOL})
    assert status == 200 and "awaiting approval" in body["result"]["content"][0]["text"], body
    assert len(fake.requests) == 1


# --- the Gateway interceptor ---------------------------------------------------------------------------


def _event(mutate):
    ev = copy.deepcopy(ti.event("request_tools_call_refund.json"))
    mutate(ev["mcp"]["gatewayRequest"]["body"])
    ev["mcp"]["rawGatewayRequest"]["body"] = json.dumps(ev["mcp"]["gatewayRequest"]["body"])
    return ev


@pytest.mark.parametrize("value", [BIG, -(10**23)])
def test_interceptor_a_large_integer_argument_is_malformed_member(ic, fake, value):
    ev = _event(lambda b: b["params"]["arguments"].__setitem__("amount_minor", value))
    body = ti.body_of(ic.handle(ev))
    assert body["result"]["isError"] is True and "(malformed_member)" in body["result"]["content"][0]["text"], body
    assert ti.requisition_calls(fake) == []


@pytest.mark.parametrize("raw", [True, False])
def test_interceptor_a_tools_call_with_a_large_integer_id_is_an_invalid_request(ic, fake, raw):
    ev = _event(lambda b: b.__setitem__("id", BIG))
    if not raw:
        del ev["mcp"]["rawGatewayRequest"]
    body = ti.body_of(ic.handle(ev))
    assert body["error"]["code"] == icp.INVALID_REQUEST and "string or integer id" in body["error"]["message"], body
    assert ti.requisition_calls(fake) == []


def test_interceptor_a_large_integer_elsewhere_in_the_body_passes(ic, fake):
    ev = _event(lambda b: b["params"].setdefault("_meta", {}).__setitem__("x.example/n", BIG))
    body = ti.body_of(ic.handle(ev))
    assert body["result"]["content"][0]["text"].startswith("Requisition: awaiting approval"), body
    assert ti.posts(fake, "/v1/sanction-requests") == 1


# --- the id's bound, at its edges, and an id that is not a string or an integer ------------------------

EDGE = 2**53 - 1


@pytest.mark.parametrize("rpc_id", [EDGE, -EDGE])
def test_mcp_target_an_id_at_the_bound_is_taken(fake, tmp_path, clock, rpc_id):
    target, _, _ = tm.make_target(fake, tmp_path, clock)
    status, body = tm.call(target, rpc_id, refund_args())
    assert status == 200 and "awaiting approval" in body["result"]["content"][0]["text"], body
    assert len(fake.requests) == 1


@pytest.mark.parametrize("rpc_id", [-BIG, 1.5, True])
def test_mcp_target_an_id_past_the_bound_or_not_an_integer_is_an_invalid_request(fake, tmp_path, clock, rpc_id):
    target, _, _ = tm.make_target(fake, tmp_path, clock)
    status, body = tm.call(target, rpc_id, refund_args())
    assert body["error"]["code"] == -32600 and "string or integer id" in body["error"]["message"], body
    assert fake.requests == {}


@pytest.mark.parametrize("rpc_id", [EDGE, -EDGE])
def test_interceptor_an_id_at_the_bound_is_taken(ic, fake, rpc_id):
    body = ti.body_of(ic.handle(_event(lambda b: b.__setitem__("id", rpc_id))))
    assert body["result"]["content"][0]["text"].startswith("Requisition: awaiting approval"), body
    assert ti.posts(fake, "/v1/sanction-requests") == 1


@pytest.mark.parametrize("rpc_id", [-BIG, 1.5, -0.0, True, {"x": 1}, [1]])
def test_interceptor_an_id_past_the_bound_or_not_a_string_or_integer_is_an_invalid_request(ic, fake, rpc_id):
    body = ti.body_of(ic.handle(_event(lambda b: b.__setitem__("id", rpc_id))))
    assert body["error"]["code"] == icp.INVALID_REQUEST and "string or integer id" in body["error"]["message"], body
    assert "arguments" not in body["error"]["message"]
    assert ti.requisition_calls(fake) == []
