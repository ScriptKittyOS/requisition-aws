# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Four input rules, each with its source:

1. A 2026-07-28 tools/list result carries ttlMs and cacheScope. The 2026-07-28 changelog,
   minor change 5 ("Require ttlMs and cacheScope fields on results returned by tools/list ... via a new
   CacheableResult interface"), and the schema's ListToolsResult (ttlMs: number; cacheScope: "public" |
   "private"; neither optional): https://modelcontextprotocol.io/specification/2026-07-28/changelog and
   https://modelcontextprotocol.io/specification/2026-07-28/schema#listtoolsresult, both read 2026-11-10.
   The target answers ttlMs 0 ("SHOULD be considered immediately stale") and cacheScope "private" ("MUST
   NOT be shared across authorization contexts"), the values the TS proxy fills (requisition-ts
   src/mcp/proxy.ts:236-237). A legacy result is unchanged.
2. loads_strict accepts only RFC 8259 JSON text in UTF-8: NaN, Infinity and -Infinity are not
   JSON (RFC 8259 section 6: "Numeric values that cannot be represented in the grammar below (such as
   Infinity and NaN) are not permitted"); a number whose value overflows to an infinite float is refused (the
   range limit section 9 allows; never an inf reaching the program); bytes must be UTF-8 (section 8.1:
   "JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using
   UTF-8"), so Python's UTF-16/UTF-32 detection and its surrogatepass decoding are refused, and a byte order
   mark is refused as the TS reader refuses it (requisition-ts src/json.ts, ignoreBOM then no U+FEFF in the
   grammar).
3. An Ed25519 public key that is not a canonical point encoding (RFC 8032 section 5.1.3: y >= p,
   x = 0 with the sign bit, no square root) or is of small order ([8]A is the identity) is never held by a
   KeyRegistry: skipped at from_bytes (requisition-ts src/keys.ts:47-53, :86, @noble/curves 2.4.0
   Point.fromBytes(bytes, false).isSmallOrder()) and refused by the constructor. The small-order list is
   libsodium's (src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c, ge25519_has_small_order's
   blocklist: y in {0, 1, p-1, p, p+1} and the two order-8 y values), each with both sign bits. The key file
   is read with loads_strict, as keys.ts reads it with parseStrict.
4. Ambiguous credentials and headers: a second credential spelled in any case (``credential=``) is counted, so a
   value with two is no caller key; the legacy Mcp-Session-Id lookup refuses two case variants rather than
   take the first (caller.header's rule). The same class on the target: a header the target reads that
   arrives twice (case variants, or twice on the wire) is refused, never "the last one".
"""

import base64
import hashlib
import http.client
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from requisition_aws import interceptor as icp
from requisition_aws.client import loads_strict
from requisition_aws.keys import KeyError_, KeyRegistry
from requisition_aws.mcp_target import serve

from .conftest import refund_args
from .test_interceptor import requisition_calls
from .test_mcp_target import CLIENT_META, MODERN, TOOL, legacy, make_target, modern, post
from .test_stateless_interceptor import AKID_A, AKID_B, body_of, build_ic, call_event, sic, sigv4, sigv4_caller  # noqa: F401  (fixtures)

P = 2**255 - 19


# --- 1. CacheableResult on the modern tools/list -----------------------------------


@pytest.fixture
def target(fake, tmp_path, clock):
    return make_target(fake, tmp_path, clock)


def test_a_modern_tools_list_carries_ttl_ms_and_cache_scope(target):
    t, _, _ = target
    status, body = modern(t, "tools/list")
    result = body["result"]
    assert status == 200 and result["resultType"] == "complete" and result["tools"][0]["name"] == TOOL
    assert "ttlMs" in result and "cacheScope" in result
    assert type(result["ttlMs"]) is int and result["ttlMs"] == 0  # a number, never a bool; immediately stale
    assert result["cacheScope"] == "private"  # never shared across authorization contexts


def test_a_legacy_tools_list_is_unchanged(target):
    t, _, _ = target
    status, body = legacy("tools/list", t=t)
    assert status == 200 and set(body["result"]) == {"tools"}


# --- 2. loads_strict is RFC 8259 in UTF-8 -------------------------------------------


@pytest.mark.parametrize("text", [
    "NaN", "Infinity", "-Infinity",
    '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}', '[1,NaN]', '{"a":{"b":[Infinity]}}',
    "1e400", "-1e400", '{"a":1E999}', '[10.0e308]',  # valid lexemes whose value is not a finite double
    "﻿{}",  # a BOM in text
    # already refused by Python's json, pinned so a looser loader never comes back:
    "nan", "inf", "01", "+1", ".5", "1.", "[1,]", "{'a':1}", '{"a":1} x', "", " ", "\x0b{}",
])
def test_loads_strict_refuses_what_rfc_8259_does_not_allow(text):
    with pytest.raises(ValueError):
        loads_strict(text)
    with pytest.raises(ValueError):
        loads_strict(text.encode("utf-8"))


@pytest.mark.parametrize("data", [
    b"\xef\xbb\xbf{}",  # UTF-8 BOM (Python's json would read it as utf-8-sig)
    '{"a":1}'.encode("utf-16-le"), '{"a":1}'.encode("utf-16-be"), '{"a":1}'.encode("utf-16"),
    '{"a":1}'.encode("utf-32-le"), '{"a":1}'.encode("utf-32"),
    b'"\xed\xa0\x80"',  # a UTF-8-encoded surrogate (Python's json decodes bytes with surrogatepass)
    b'{"a":"\xed\xb0\x80"}', b'{"a":"\xff"}', b'{"a":"\xc0\xaf"}',  # not UTF-8
])
def test_loads_strict_refuses_bytes_that_are_not_utf8_json(data):
    with pytest.raises(ValueError):
        loads_strict(data)


@pytest.mark.parametrize("text, value", [
    ('{"a":1}', {"a": 1}), ("[1.5,-0,1e308,-2.5E-3]", [1.5, 0, 1e308, -2.5e-3]), ('"\\u00e9"', "é"),
    (' \t\r\n{"a":[true,false,null]} \n', {"a": [True, False, None]})
])
def test_loads_strict_still_reads_rfc_8259_json(text, value):
    assert loads_strict(text) == value
    assert loads_strict(text.encode("utf-8")) == value


def test_loads_strict_still_refuses_duplicates_and_reads_utf8_bytes():
    with pytest.raises(ValueError):
        loads_strict('{"a":1,"a":2}')
    assert loads_strict('{"a":"é€\U0001f600"}'.encode("utf-8")) == {"a": "é€\U0001f600"}


def test_a_nan_argument_is_a_parse_error_at_the_target_and_nothing_runs(target, fake):
    t, ledger, _ = target
    args = json.dumps(refund_args()).replace('"amount_minor": 1250', '"amount_minor": NaN', 1)
    assert "NaN" in args
    raw = ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s,"_meta":%s}}'
           % (TOOL, args, json.dumps(CLIENT_META))).encode()
    status, _, data = t.handle_http("POST", "/mcp", {"content-type": "application/json",
                                    "accept": "application/json, text/event-stream", "mcp-protocol-version": MODERN,
                                    "mcp-method": "tools/call", "mcp-name": TOOL}, raw)
    assert status == 400 and json.loads(data)["error"]["code"] == -32700
    assert requisition_calls(fake) == [] and ledger.entries() == []


# --- 3. no small-order or non-canonical Ed25519 key is held ---------------------------


def enc(y: int, sign: int) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


ORDER8 = [int.from_bytes(bytes.fromhex(h), "little") for h in (
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")]
SMALL_ORDER = [enc(y, s) for y in [0, 1, P - 1, P, P + 1] + ORDER8 for s in (0, 1)]  # libsodium's, both signs
NON_CANONICAL = [enc(y, s) for y in range(P, 2**255) for s in (0, 1)]  # every y >= p (RFC 8032 5.1.3 step 1)
NOT_ON_CURVE = [enc(2, 0), enc(7, 0), enc(8, 1)]  # no square root (step 3); noble refuses each (probe)
# canonical, on the curve, not small order -- but MIXED order (none of y = 2..18 is in the prime-order subgroup):
# refused; y=3's sibling p+3 is NON_CANONICAL
MIXED_ORDER_LOW = [enc(3, 0), enc(4, 0), enc(9, 0), enc(3, 1)]
RFC8032_TEST1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
MESSAGE = b'{"occurred_at":"2026-11-09T12:00:00Z"}'  # a signed payload: the key rule reads its occurred_at
SIG_IDENTITY = bytes.fromhex("01" + "00" * 63)  # R = identity, S = 0 (requisition-ts test/vectors/python/ed25519.json)


def keys_ok():
    from requisition_aws.keys import ed25519_key_acceptable  # the small-order rule

    return ed25519_key_acceptable


def key_file(*pairs, status="active") -> bytes:
    return json.dumps({"entries": [
        {"key_id": key_id, "algorithm": "ed25519", "public_key": base64.b64encode(raw).decode(),
         "public_key_fingerprint": hashlib.sha256(raw).hexdigest(), "status": status,
         "valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "signer": "dev"} for key_id, raw in pairs]}).encode()


def envelope(key_id: str, signature: bytes, payload: str = MESSAGE.decode()) -> dict:
    return {"key_id": key_id, "signature": base64.b64encode(signature).decode(), "signed_payload": payload,
            "receipt_hash": hashlib.sha256(payload.encode()).hexdigest()}


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_the_small_order_list_is_fourteen_encodings_and_every_y_at_or_above_p_is_listed():
    assert len(SMALL_ORDER) == 14 and len(set(SMALL_ORDER)) == 14
    assert len(NON_CANONICAL) == 38


WRONG_LENGTH = [b"", b"\x00" * 31, b"\x00" * 33, RFC8032_TEST1 + b"\x00", RFC8032_TEST1[:31]]  # never a 32-byte read


@pytest.mark.parametrize("raw", SMALL_ORDER + NON_CANONICAL + NOT_ON_CURVE + WRONG_LENGTH, ids=bytes.hex)
def test_a_small_order_or_non_canonical_key_is_not_acceptable(raw):
    assert keys_ok()(raw) is False


def test_real_keys_are_acceptable_and_low_y_mixed_order_points_are_not():
    ok = keys_ok()
    assert ok(RFC8032_TEST1) is True
    for raw in MIXED_ORDER_LOW:
        assert ok(raw) is False
    for _ in range(32):
        assert ok(raw_public(Ed25519PrivateKey.generate())) is True


@pytest.mark.parametrize("raw, what", [
    (enc(1, 0), "identity"), (enc(1, 1), "identity with the sign bit (x=0)"), (enc(P + 1, 0), "y = p+1"),
    (bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "order 8"),
    (enc(P + 3, 0), "y = p+3 (a large-order point, non-canonical)"), (enc(2, 0), "not on the curve"),
], ids=lambda v: v.hex() if isinstance(v, bytes) else "")
def test_from_bytes_skips_the_key_and_keeps_the_others(raw, what):
    good = Ed25519PrivateKey.generate()
    registry = KeyRegistry.from_bytes(key_file(("bad", raw), ("good", raw_public(good))))
    assert registry.algorithm("bad") is None, what
    assert registry.verify(envelope("bad", SIG_IDENTITY)) is False
    assert registry.algorithm("good") == "ed25519"
    assert registry.verify(envelope("good", good.sign(MESSAGE))) is True


def test_the_identity_key_no_longer_verifies_r_identity_s_zero_for_any_message():
    registry = KeyRegistry.from_bytes(key_file(("id", enc(1, 0)), ("id-retired", enc(P + 1, 0))))
    for key_id in ("id", "id-retired"):
        for payload in ("anything", "{\"decision\":\"allow\"}"):
            assert registry.verify(envelope(key_id, SIG_IDENTITY, payload)) is False


@pytest.mark.parametrize("raw", [enc(1, 0), enc(P + 3, 0), SMALL_ORDER[-1], enc(2, 0)], ids=bytes.hex)
def test_the_constructor_refuses_an_unacceptable_key(raw):
    with pytest.raises(KeyError_):
        KeyRegistry({"k": raw})


def test_the_key_file_is_read_with_the_strict_loader():
    good = raw_public(Ed25519PrivateKey.generate())
    one = key_file(("k", good)).decode()
    with pytest.raises((KeyError_, ValueError)):
        KeyRegistry.from_bytes(('{"entries":[],' + one[1:]).encode())  # "entries" twice: never "the last one"
    with pytest.raises((KeyError_, ValueError)):
        KeyRegistry.from_bytes(one.replace('"active"', "NaN").encode())


# --- 4. ambiguous credentials and session headers -------------------------------------------------


@pytest.mark.parametrize("second", ["credential=", "CREDENTIAL=", "Credential=", "cReDeNtIaL="])
def test_a_second_credential_in_any_case_is_no_caller_key(sigv4_caller, sic, fake, second):
    value = sigv4(AKID_A) + ", " + second + AKID_B + "/20261110/us-west-2/bedrock-agentcore/aws4_request"
    assert sigv4_caller().key({"Authorization": value}) is None
    assert sigv4_caller().key({"Authorization": sigv4(AKID_A)}) == "sigv4:" + AKID_A
    error = body_of(sic().handle(call_event(value, 7)))["error"]
    assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"
    assert requisition_calls(fake) == []


@pytest.mark.parametrize("first, second", [("Mcp-Session-Id", "mcp-session-id"), ("mcp-session-id", "MCP-SESSION-ID")])
def test_the_legacy_session_lookup_refuses_two_case_variants(gate, fake, first, second):
    for a, b in ((first, second), (second, first)):
        interceptor = build_ic(gate)  # the default source: legacy_session
        ev = call_event(sigv4(AKID_A), 1, modern=False)
        headers = ev["mcp"]["gatewayRequest"]["headers"]
        headers[a], headers[b] = "mcp-session-a", "mcp-session-b"
        error = body_of(interceptor.handle(ev))["error"]
        assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"
        assert requisition_calls(fake) == []
    single = call_event(sigv4(AKID_A), 1, modern=False, session="mcp-session-a")
    assert "request_id" in body_of(build_ic(gate).handle(single))["result"]["_meta"]["requisition"]


def test_a_mcp_standard_header_twice_on_the_target_is_a_header_mismatch(target, fake):
    t, ledger, _ = target
    for name in ("Mcp-Method", "MCP-Protocol-Version"):
        value = "tools/call" if name == "Mcp-Method" else MODERN
        status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()}, headers={name: value})
        assert status == 400 and body["error"]["code"] == -32020, name
    status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()}, headers={"MCP-NAME": TOOL})
    assert status == 400 and body["error"]["code"] == -32020
    assert requisition_calls(fake) == [] and ledger.entries() == []


def test_a_session_or_caller_header_twice_on_the_target_is_refused(fake, tmp_path, clock):
    t, ledger, _ = make_target(fake, tmp_path, clock, session_header="x-session", caller_header="x-caller")
    params = {"name": TOOL, "arguments": refund_args()}
    for extra in ({"x-session": "s-1", "X-Session": "s-2", "x-caller": "agent-a"},
                  {"x-session": "s-1", "x-caller": "agent-a", "X-CALLER": "agent-b"},
                  {"x-session": "s-1", "x-caller": "agent-a", "mcp-session-id": "m-1", "Mcp-Session-Id": "m-2"}):
        status, body = modern(t, "tools/call", params, headers=extra)
        assert status == 400 and body["error"]["code"] == -32600, extra
    assert requisition_calls(fake) == [] and ledger.entries() == []


def test_an_origin_twice_on_the_target_is_refused(fake, tmp_path, clock):
    t, _, _ = make_target(fake, tmp_path, clock, allowed_origins=("https://ok.example",))
    for pair in ({"Origin": "https://evil.example", "origin": "https://ok.example"},  # "the last one" would pass
                 {"origin": "https://ok.example", "Origin": "https://evil.example"}):
        status, body = modern(t, "tools/list", headers=pair)
        assert status == 400 and body["error"]["code"] == -32600, pair
    status, body = modern(t, "tools/list", headers={"origin": "https://ok.example"})
    assert status == 200


def test_a_header_twice_on_the_wire_is_refused_by_the_served_target(target, fake):
    t, ledger, _ = target
    server = serve(t, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": TOOL, "arguments": refund_args(), "_meta": CLIENT_META}}).encode()
        conn.putrequest("POST", "/mcp")
        for name, value in (("content-type", "application/json"), ("accept", "application/json, text/event-stream"),
                            ("mcp-protocol-version", MODERN), ("mcp-method", "tools/call"), ("mcp-name", TOOL),
                            ("mcp-name", TOOL), ("content-length", str(len(body)))):
            conn.putheader(name, value)
        conn.endheaders(body)
        resp = conn.getresponse()
        assert resp.status == 400 and json.loads(resp.read())["error"]["code"] == -32020
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
    assert requisition_calls(fake) == [] and ledger.entries() == []


def test_a_single_set_of_headers_still_runs_on_the_target(target, fake):
    t, _, _ = target
    status, body = modern(t, "tools/call", {"name": TOOL, "arguments": refund_args()})
    assert status == 200 and "awaiting approval" in body["result"]["content"][0]["text"]
    status, body = post(t, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                        {"Accept": "application/json", "mcp-protocol-version": "2025-11-25"})
    assert status == 200  # a duplicate of a header the target does not read (accept/Accept) is not refused


def test_loads_strict_refuses_an_integer_outside_the_canonical_range():
    """+-(2^53-1) is CanonicalPayload v3's range; a reader that kept a larger integer would disagree with the TS reader."""
    for text in ("12345678901234567890", "9007199254740992", "-9007199254740992"):
        with pytest.raises(ValueError):
            loads_strict(text)
