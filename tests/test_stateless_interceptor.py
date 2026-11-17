# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""G1: the Gateway REQUEST interceptor under stateless MCP 2026-07-28.

Measured: the interceptor refuses any tools/call without
``Mcp-Session-Id`` (interceptor.py:203-206 in the version before stateless MCP), puts that session into the signed act (:207)
and keys the call on it (:212). MCP 2026-07-28 removes the header ("An Mcp-Session-Id header on a
request: ignore it", transports/streamable-http#backward-compatibility, read 2026-11-10).

G1:
* the caller key: under ``AWS_IAM`` inbound (the deployed Gateway) the SigV4
  access-key id parsed from the forwarded ``Authorization`` header (passRequestHeaders; the Gateway
  authenticated it before invoking the interceptor; the Lambda cannot re-verify it); under
  ``CUSTOM_JWT`` the JWKS-verified ``iss|sub`` (``client_id`` for M2M); never ``clientInfo``;
* the signed ``session`` member: a stable caller-scoped id, the client's own id (``Mcp-Session-Id``
  on a legacy request; ``params._meta["requisition/session"]`` on a 2026-07-28 request) namespaced
  by the caller key, else the caller key alone; stable across the pending call and the re-call; a
  rotation of temporary credentials between them is a new act (fail closed: availability, not safety);
* the call key: (gateway id, caller key, JSON-RPC id, act_hash);
* fail-closed refusals use a code outside the JSON-RPC reserved range (-32768..-32000;
  basic/#error-codes: new codes "SHOULD be allocated outside").

Decided:
* that the Gateway forwards the SigV4 ``Authorization`` to an interceptor under AWS_IAM is NOT
  measured. The caller-key source is configuration (``legacy_session``, the pre-G1 behaviour and the
  default until measured; ``sigv4``; ``jwt``); a missing key is FAIL_CLOSED with
  ``data.code = "caller_identity_absent"``; every tools/call logs the request's header NAMES (never a
  value), so one live call measures it.
* deny by default kept: an allowlist of methods, everything else -32601; a gated tools/call
  carrying MRTR ``inputResponses``/``requestState`` is refused (the act hashes only ``arguments``).
* stated in LIMITS: any principal with ``lambda:InvokeFunction`` on the interceptor can invoke it
  directly with a forged header; an access-key id names a credential, not a principal.

Events are built from the AWS-documented fixture (tests/fixtures/interceptor/) plus the 2026-07-28
request metadata the MCP spec defines; the SigV4 ``Authorization`` value is a placeholder in the
documented SigV4 form, the JWT is minted here with a key generated here; not a live Gateway.
"""

import base64
import copy
import hashlib
import json
import pathlib
import re
import time

import pytest
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from requisition_aws import canonical
from requisition_aws import interceptor as icp
from requisition_aws.interceptor import Interceptor
from requisition_aws.registry import ToolRegistry
from requisition_aws.store import idempotency_key

from .conftest import ACT_TYPE
from .test_canonical import SEED_SCHEMA
from .test_interceptor import GATEWAY_TOOL, body_of, event, posts, requisition_calls

ISSUER = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_FIXTURE"
AUDIENCE = "requisition-gateway-fixture"
KID = "fixture-key-1"
MODERN = "2026-07-28"
GW = "gw-fixture-0001"
AKID_A, AKID_B = "ASIAFIXTURENOTREAL0A", "ASIAFIXTURENOTREAL0B"
CLIENT_META = "requisition/session"


def sigv4(akid: str) -> str:
    return (f"AWS4-HMAC-SHA256 Credential={akid}/20261110/us-west-2/bedrock-agentcore/aws4_request, "
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=" + "0" * 64)


# --- a JWT minted here, signed with a key generated here (never a real token) -----------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_int(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(rsa_key):
    pub = rsa_key.public_key().public_numbers()
    return {"keys": [{"kty": "RSA", "kid": KID, "alg": "RS256", "use": "sig", "n": b64u_int(pub.n), "e": b64u_int(pub.e)}]}


def sign_jwt(key, claims: dict, header: dict | None = None, raw_payload: str | None = None) -> str:
    head = b64u(json.dumps(header or {"alg": "RS256", "kid": KID, "typ": "JWT"}).encode())
    body = b64u((raw_payload if raw_payload is not None else json.dumps(claims)).encode())
    signing_input = f"{head}.{body}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()) if key is not None else b""
    return f"{head}.{body}.{b64u(sig)}"


def claims_for(now, sub="agent-alpha", **over):
    claims = {"iss": ISSUER, "sub": sub, "aud": AUDIENCE, "iat": int(now), "nbf": int(now) - 5,
              "exp": int(now) + 600, "token_use": "access"}
    claims.update(over)
    return {k: v for k, v in claims.items() if v is not None}


def bearer(jwt):
    return f"Bearer {jwt}"


def jwt_key(sub):
    return f"jwt:{ISSUER}|{sub}"


@pytest.fixture
def jwt_caller(jwks, clock):
    """A factory, called inside each test, so a missing interface fails the test (not its setup)."""

    def build(**kw):
        from requisition_aws.caller import JwtCaller  # the interface G1 adds

        return JwtCaller(ISSUER, jwks, **({"audiences": (AUDIENCE,)} | kw), clock=clock)

    return build


@pytest.fixture
def sigv4_caller():
    def build():
        from requisition_aws.caller import SigV4Caller  # the interface G1 adds

        return SigV4Caller()

    return build


# --- events -------------------------------------------------------------------------------------


def call_event(authorization: str | None, rpc_id=7, *, modern=True, session: str | None = None,
               client_session: str | None = None, mcp_name=GATEWAY_TOOL, mcp_method="tools/call", client_info=None):
    """The documented REQUEST shape carrying a tools/call. ``modern``: the 2026-07-28 metadata, no
    Mcp-Session-Id unless one is given (a client-chosen one, which a 2026-07-28 server ignores)."""
    ev = copy.deepcopy(event("request_tools_call_refund.json"))
    body = ev["mcp"]["gatewayRequest"]["body"]
    body["id"] = rpc_id
    headers = {"Accept": "application/json, text/event-stream", "User-Agent": "fixture-client/1.0"}
    if modern:
        meta = {"io.modelcontextprotocol/protocolVersion": MODERN, "io.modelcontextprotocol/clientCapabilities": {}}
        if client_session is not None:
            meta[CLIENT_META] = client_session
        if client_info is not None:
            meta["io.modelcontextprotocol/clientInfo"] = client_info
        body["params"]["_meta"] = meta
        headers.update({"MCP-Protocol-Version": MODERN, "Mcp-Method": mcp_method, "Mcp-Name": mcp_name})
    if authorization is not None:
        headers["Authorization"] = authorization
    if session is not None:
        headers["Mcp-Session-Id"] = session
    ev["mcp"]["gatewayRequest"]["headers"] = headers
    ev["mcp"]["rawGatewayRequest"]["body"] = json.dumps(body)
    return ev


def passed_through(out, ev):
    return out == {"interceptorOutputVersion": "1.0",
                   "mcp": {"transformedGatewayRequest": {"body": ev["mcp"]["gatewayRequest"]["body"]}}}


def meta_of(out):
    return body_of(out)["result"]["_meta"]["requisition"]


def filed_display(fake, request_id):
    return fake.requests[request_id]["body"]["display"]


def build_ic(gate, caller=None):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    if caller is None:
        return Interceptor(gate, reg, gateway_id=GW, agent_name="agentcore-gateway")
    return Interceptor(gate, reg, gateway_id=GW, agent_name="agentcore-gateway", caller=caller)


@pytest.fixture
def sic(gate, sigv4_caller):
    """The interceptor as deployed (AWS_IAM inbound): the SigV4 caller key (a factory)."""
    return lambda: build_ic(gate, sigv4_caller())


# --- the caller key: SigV4 ----------------------------------------------------------------------


def test_the_sigv4_access_key_id_is_the_caller_key(sigv4_caller):
    c = sigv4_caller()
    assert c.key({"Authorization": sigv4(AKID_A)}) == f"sigv4:{AKID_A}"
    assert c.key({"authorization": sigv4("AKIAFIXTURENOTREAL0C")}) == "sigv4:AKIAFIXTURENOTREAL0C"


@pytest.mark.parametrize("value", [
    None, "", "Bearer abc.def.ghi", "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=00",
    "AWS4-HMAC-SHA256 Credential=, SignedHeaders=host, Signature=00",
    "AWS4-HMAC-SHA256 Credential=asiafixturenotreal0a/20261110/us-west-2/bedrock-agentcore/aws4_request, Signature=00",
    "AWS4-HMAC-SHA256 Credential=ASIAFIXTURE/../x/aws4_request, Signature=00",
    "AWS4-HMAC-SHA256 Credential=ASIAFIXTURENOTREAL0A/20261110/us-west-2/bedrock-agentcore, Signature=00",
    "AWS4-ECDSA-P256-SHA256 Credential=ASIAFIXTURENOTREAL0A/20261110/bedrock-agentcore/aws4_request, Signature=00",
])
def test_anything_but_a_sigv4_credential_is_no_caller_key(sigv4_caller, value):
    headers = {} if value is None else {"Authorization": value}
    assert sigv4_caller().key(headers) is None


# --- the caller key: JWT (CUSTOM_JWT inbound) ----------------------------------------------------


def test_a_token_signed_by_the_pinned_key_is_the_caller_key(jwt_caller, rsa_key, clock):
    c = jwt_caller()
    assert c.key({"Authorization": bearer(sign_jwt(rsa_key, claims_for(clock())))}) == jwt_key("agent-alpha")
    assert c.key({"authorization": bearer(sign_jwt(rsa_key, claims_for(clock(), "agent-beta")))}) == jwt_key("agent-beta")


@pytest.mark.parametrize("case", [
    "no header", "sigv4 header", "alg none", "alg HS256 keyed by the public modulus", "another key, same kid",
    "unknown kid", "expired", "not yet valid", "another issuer", "another audience", "neither sub nor client_id",
    "empty sub", "not three parts", "payload not base64url", "duplicate claim member", "sub not a string",
])
def test_anything_but_a_verified_token_is_no_caller_key(jwt_caller, rsa_key, other_key, jwks, clock, case):
    now = clock()
    good = claims_for(now)
    head = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    tok = None
    if case == "sigv4 header":
        headers = {"Authorization": sigv4(AKID_A)}
    elif case == "no header":
        headers = {}
    else:
        if case == "alg none":
            tok = sign_jwt(None, good, {"alg": "none", "kid": KID})
        elif case == "alg HS256 keyed by the public modulus":
            h = b64u(json.dumps({"alg": "HS256", "kid": KID}).encode())
            p = b64u(json.dumps(good).encode())
            mac = hmac.HMAC(base64.urlsafe_b64decode(jwks["keys"][0]["n"] + "=="), hashes.SHA256())
            mac.update(f"{h}.{p}".encode())
            tok = f"{h}.{p}.{b64u(mac.finalize())}"
        elif case == "another key, same kid":
            tok = sign_jwt(other_key, good, head)
        elif case == "unknown kid":
            tok = sign_jwt(rsa_key, good, {**head, "kid": "not-pinned"})
        elif case == "expired":
            tok = sign_jwt(rsa_key, claims_for(now, exp=int(now) - 3600))
        elif case == "not yet valid":
            tok = sign_jwt(rsa_key, claims_for(now, nbf=int(now) + 3600))
        elif case == "another issuer":
            tok = sign_jwt(rsa_key, claims_for(now, iss="https://evil.example"))
        elif case == "another audience":
            tok = sign_jwt(rsa_key, claims_for(now, aud="someone-else"))
        elif case == "neither sub nor client_id":
            tok = sign_jwt(rsa_key, claims_for(now, sub=None))
        elif case == "empty sub":
            tok = sign_jwt(rsa_key, claims_for(now, sub=""))
        elif case == "not three parts":
            tok = "abc.def"
        elif case == "payload not base64url":
            t = sign_jwt(rsa_key, good).split(".")
            tok = f"{t[0]}.!!!.{t[2]}"
        elif case == "duplicate claim member":
            tok = sign_jwt(rsa_key, good, raw_payload=json.dumps(good)[:-1] + ', "sub": "agent-mallory"}')
        elif case == "sub not a string":
            tok = sign_jwt(rsa_key, claims_for(now, sub=42))
        headers = {"Authorization": bearer(tok)}
    assert jwt_caller().key(headers) is None


def test_an_m2m_token_is_keyed_on_its_client_id_when_clients_are_pinned(jwt_caller, rsa_key, clock):
    c = jwt_caller(audiences=(), clients=("client-a",))
    ok = sign_jwt(rsa_key, claims_for(clock(), sub=None, aud=None, client_id="client-a"))
    other = sign_jwt(rsa_key, claims_for(clock(), sub=None, aud=None, client_id="client-b"))
    assert c.key({"Authorization": bearer(ok)}) == jwt_key("client-a")
    assert c.key({"Authorization": bearer(other)}) is None


def test_a_jwt_caller_pinning_neither_audiences_nor_clients_refuses_to_build(jwt_caller):
    with pytest.raises(ValueError):
        jwt_caller(audiences=(), clients=())


# --- the signed session member --------------------------------------------------------------------


def test_caller_session_is_stable_namespaced_bounded_and_never_raw():
    s = icp.caller_session
    a = s(f"sigv4:{AKID_A}", None)
    assert a == s(f"sigv4:{AKID_A}", None)
    assert a == "caller-" + hashlib.sha256(
        canonical.encode(["requisition-aws/caller-session", f"sigv4:{AKID_A}", None])).hexdigest()[:48]
    assert s(f"sigv4:{AKID_A}", "conv-1") != s(f"sigv4:{AKID_B}", "conv-1")  # the client id is namespaced
    assert s(f"sigv4:{AKID_A}", "conv-1") != s(f"sigv4:{AKID_A}", "conv-2") != a
    for v in (a, s(jwt_key("alice@example.com"), "conv-1")):
        assert re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", v) and "ASIA" not in v and "alice" not in v


# --- the flow -------------------------------------------------------------------------------------


@pytest.mark.parametrize("modern", [True, False], ids=["2026-07-28", "legacy-without-session"])
def test_a_stateless_request_runs_pending_then_approved_recall(sic, fake, modern):
    sic = sic()
    ev = call_event(sigv4(AKID_A), 7, modern=modern)
    out = sic.handle(ev)
    assert body_of(out)["id"] == 7 and meta_of(out)["status"] == "pending"
    request_id = meta_of(out)["request_id"]
    assert filed_display(fake, request_id)["session"] == icp.caller_session(f"sigv4:{AKID_A}", None)
    # a Gateway retry of the same invocation files nothing new
    assert meta_of(sic.handle(ev))["request_id"] == request_id and posts(fake, "/v1/sanction-requests") == 1
    # approved; the agent calls again with a NEW JSON-RPC id: the same act, passed through unchanged
    fake.approve(request_id)
    ev2 = call_event(sigv4(AKID_A), 8, modern=modern)
    assert passed_through(sic.handle(ev2), ev2)
    assert posts(fake, "/v1/sanction-requests") == 1 and posts(fake, "/v1/execute") == 1 and len(fake.spent) == 1


def test_the_clients_own_id_is_kept_and_namespaced_by_the_caller(sic, fake):
    sic = sic()
    rid = meta_of(sic.handle(call_event(sigv4(AKID_A), 1, client_session="conv-42")))["request_id"]
    assert filed_display(fake, rid)["session"] == icp.caller_session(f"sigv4:{AKID_A}", "conv-42")
    fake.approve(rid)
    ev = call_event(sigv4(AKID_A), 2, client_session="conv-42")
    assert passed_through(sic.handle(ev), ev)
    # the same client id from another caller is another act: never this approval
    out = sic.handle(call_event(sigv4(AKID_B), 3, client_session="conv-42"))
    assert meta_of(out)["status"] == "pending" and meta_of(out)["request_id"] != rid


def test_a_legacy_session_id_is_the_clients_own_id_namespaced_by_the_caller(sic, fake):
    sic = sic()
    rid = meta_of(sic.handle(call_event(sigv4(AKID_A), 1, modern=False, session="mcp-session-0b1c2d3e")))["request_id"]
    assert filed_display(fake, rid)["session"] == icp.caller_session(f"sigv4:{AKID_A}", "mcp-session-0b1c2d3e")


def test_two_callers_with_the_same_jsonrpc_id_never_collide(sic, fake):
    sic = sic()
    rid_a = meta_of(sic.handle(call_event(sigv4(AKID_A), 1)))["request_id"]
    fake.approve(rid_a)
    ev_a = call_event(sigv4(AKID_A), 2)
    assert passed_through(sic.handle(ev_a), ev_a)
    for rpc_id in (1, 2):  # bob: the same JSON-RPC ids, the same arguments
        out = sic.handle(call_event(sigv4(AKID_B), rpc_id))
        assert "transformedGatewayRequest" not in out["mcp"]
        assert meta_of(out)["status"] == "pending" and meta_of(out)["request_id"] != rid_a
        assert filed_display(fake, meta_of(out)["request_id"])["session"] == icp.caller_session(f"sigv4:{AKID_B}", None)
    assert len(fake.spent) == 1 and posts(fake, "/v1/execute") == 1


def test_a_retry_within_one_caller_is_the_same_claim(sic, fake):
    sic = sic()
    rid = meta_of(sic.handle(call_event(sigv4(AKID_A), 1)))["request_id"]
    fake.approve(rid)
    ev = call_event(sigv4(AKID_A), 2)
    assert passed_through(sic.handle(ev), ev)
    key = idempotency_key("agentcore-gateway", GW, f"sigv4:{AKID_A}", 2,
                          canonical.act_hash(ACT_TYPE, filed_display(fake, rid)))
    assert sic.gate.store.get("executes", key) is not None
    # the same invocation again (a Gateway retry, or id 2 reused after its response, which MCP
    # allows: basic/#requests): the same key, the claim refuses a second pass-through
    out = sic.handle(call_event(sigv4(AKID_A), 2))
    assert "transformedGatewayRequest" not in out["mcp"] and "already used" in body_of(out)["result"]["content"][0]["text"]
    assert len(fake.spent) == 1 and len(fake.claims) == 1


def test_a_credential_rotation_between_pending_and_recall_is_a_new_act_fail_closed(sic, fake):
    sic = sic()
    rid = meta_of(sic.handle(call_event(sigv4(AKID_A), 1)))["request_id"]
    fake.approve(rid)
    # the temporary credentials rotated (a new ASIA key id): the approval is not reached; a new request is filed
    out = sic.handle(call_event(sigv4("ASIAFIXTURENOTREAL0R"), 2))
    assert "transformedGatewayRequest" not in out["mcp"]
    assert meta_of(out)["status"] == "pending" and meta_of(out)["request_id"] != rid
    assert fake.spent == set()


def test_a_client_chosen_session_id_on_a_modern_request_is_ignored(sic, fake):
    sic = sic()
    forged = "mcp-session-0b1c2d3e"
    rid_a = meta_of(sic.handle(call_event(sigv4(AKID_A), 1, session=forged)))["request_id"]
    assert filed_display(fake, rid_a)["session"] == icp.caller_session(f"sigv4:{AKID_A}", None)
    fake.approve(rid_a)
    ev_a = call_event(sigv4(AKID_A), 2, session=forged)
    assert passed_through(sic.handle(ev_a), ev_a)
    out = sic.handle(call_event(sigv4(AKID_B), 2, session=forged))  # same forged session, same id
    assert "transformedGatewayRequest" not in out["mcp"] and meta_of(out)["request_id"] != rid_a
    assert len(fake.spent) == 1


def test_client_info_never_names_the_caller(sic, fake):
    sic = sic()
    a = meta_of(sic.handle(call_event(sigv4(AKID_A), 1, client_info={"name": "victim", "version": "1"})))["request_id"]
    b = meta_of(sic.handle(call_event(sigv4(AKID_B), 1, client_info={"name": "victim", "version": "1"})))["request_id"]
    assert a != b and filed_display(fake, a)["session"] != filed_display(fake, b)["session"]


@pytest.mark.parametrize("how", ["no Authorization", "a bearer under AWS_IAM", "a malformed SigV4 header"])
def test_no_caller_key_is_refused_fail_closed_caller_identity_absent(sic, fake, how):
    sic = sic()
    auth = {"no Authorization": None, "a bearer under AWS_IAM": "Bearer FIXTURE-NOT-A-REAL-TOKEN",
            "a malformed SigV4 header": "AWS4-HMAC-SHA256 Signature=00"}[how]
    for modern in (True, False):
        error = body_of(sic.handle(call_event(auth, 7, modern=modern)))["error"]
        assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"
        # the message names what to measure: the forwarded Authorization header (passRequestHeaders)
        assert "Authorization" in error["message"] and "passRequestHeaders" in error["message"]
        assert "fail closed" in error["message"]
    assert requisition_calls(fake) == []


@pytest.fixture
def lambda_root_logger():
    """The Lambda Python runtime with Text logs and no application log level: the root logger stays at
    WARNING (awslambdaric bootstrap.py:455-477 sets a level only when one is configured; the
    deployed stack's template configures none). The test sets NO level of its own on the module logger."""
    import logging

    root = logging.getLogger()
    before = root.level
    root.setLevel(logging.WARNING)
    yield root
    root.setLevel(before)


def test_every_tools_call_logs_the_header_names_and_never_a_value(sic, fake, caplog, lambda_root_logger):
    # the header-names line the live measurement depends on must reach the runtime's root
    # handler with the root at WARNING; caplog's handler sits on the root, as the runtime's does
    sic = sic()
    sic.handle(call_event(sigv4(AKID_A), 7, session="mcp-session-0b1c2d3e"))
    sic.handle(call_event(None, 8))
    lines = [r.getMessage() for r in caplog.records if "header names" in r.getMessage()]
    assert len(lines) == 2
    assert "authorization" in lines[0].lower() and "mcp-session-id" in lines[0].lower() and "mcp-name" in lines[0].lower()
    assert "authorization" not in lines[1].lower()
    every = "\n".join(r.getMessage() for r in caplog.records)
    for value in (AKID_A, "Signature=", "0" * 64, "mcp-session-0b1c2d3e", "fixture-client", "bedrock-agentcore/aws4_request"):
        assert value not in every


def test_jwt_inbound_runs_the_flow_and_refuses_an_unverified_token(gate, fake, jwt_caller, rsa_key, other_key, clock):
    ic = build_ic(gate, jwt_caller())
    tok = sign_jwt(rsa_key, claims_for(clock(), "agent-alice"))
    rid = meta_of(ic.handle(call_event(bearer(tok), 1)))["request_id"]
    assert filed_display(fake, rid)["session"] == icp.caller_session(jwt_key("agent-alice"), None)
    fake.approve(rid)
    ev = call_event(bearer(tok), 2)
    assert passed_through(ic.handle(ev), ev)
    forged = sign_jwt(other_key, claims_for(clock(), "agent-alice"))
    body = body_of(ic.handle(call_event(bearer(forged), 3)))
    assert body["error"]["code"] == icp.FAIL_CLOSED and len(fake.spent) == 1
    # a SigV4 header never counts under CUSTOM_JWT (the gateway did not authenticate it)
    assert body_of(ic.handle(call_event(sigv4(AKID_A), 4)))["error"]["code"] == icp.FAIL_CLOSED


def test_the_default_caller_source_is_the_pre_g1_legacy_session(gate, fake):
    # until the forwarded Authorization is measured live, the default stays the pre-G1 behaviour:
    # the raw Mcp-Session-Id is the signed session and part of the call key; no session: refused
    ic = build_ic(gate)
    out = ic.handle(call_event(sigv4(AKID_A), 1, modern=False, session="mcp-session-0b1c2d3e"))
    rid = meta_of(out)["request_id"]
    display = filed_display(fake, rid)
    assert display["session"] == "mcp-session-0b1c2d3e"
    fake.approve(rid)
    ev = call_event(sigv4(AKID_A), 2, modern=False, session="mcp-session-0b1c2d3e")
    assert passed_through(ic.handle(ev), ev)
    key = idempotency_key("agentcore-gateway", GW, "mcp-session-0b1c2d3e", 2, canonical.act_hash(ACT_TYPE, display))
    assert ic.gate.store.get("executes", key) is not None
    error = body_of(ic.handle(call_event(sigv4(AKID_A), 3)))["error"]  # 2026-07-28: no session
    assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"


def test_the_limits_state_direct_invocation_and_credential_not_principal():
    doc = " ".join(icp.__doc__.split())
    assert "lambda:InvokeFunction" in doc and "forged" in doc
    assert "access-key id names a credential, not a principal" in doc


def test_the_local_demo_uses_a_labelled_placeholder_header():
    import importlib.util

    path = pathlib.Path(__file__).resolve().parent.parent / "demo" / "run_interceptor_local.py"
    spec = importlib.util.spec_from_file_location("run_interceptor_local_for_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    headers = mod.event(1, "tools/call", {"name": "x", "arguments": {}})["mcp"]["gatewayRequest"]["headers"]
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=")
    assert "caller key from a placeholder header \u2014 local run, not authenticated (no Gateway)" in path.read_text()


# --- codes, methods, metadata ---------------------------------------------------------------------


def test_the_fail_closed_code_is_outside_the_reserved_range():
    assert icp.FAIL_CLOSED == -31000 and not (-32768 <= icp.FAIL_CLOSED <= -32000)
    assert icp.UNAVAILABLE == icp.FAIL_CLOSED  # the old name kept for the code paths that used it


ALLOWED = ["initialize", "ping", "notifications/initialized", "tools/list", "server/discover"]
REFUSED = ["resources/read", "prompts/get", "subscriptions/listen", "completion/complete", "resources/list",
           "logging/setLevel", "tools/call2", "x-invented/method", "Tools/List"]


def method_event(method, rpc_id=3):
    ev = copy.deepcopy(event("request_tools_list.json"))
    body = {"jsonrpc": "2.0", "method": method,
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN,
                                 "io.modelcontextprotocol/clientCapabilities": {}}}}
    if rpc_id is not None:
        body["id"] = rpc_id
    ev["mcp"]["gatewayRequest"]["body"] = body
    ev["mcp"]["rawGatewayRequest"] = {"body": json.dumps(body)}
    return ev


@pytest.mark.parametrize("method", ALLOWED)
def test_the_allowlisted_methods_pass_through(gate, fake, method):
    # initialize, ping, notifications/*: the legacy handshake (2025-11-25 lifecycle; ping and the
    # handshake are removed in 2026-07-28, changelog 2 and 5); tools/list: the catalog the agent must
    # see; server/discover: a MUST in 2026-07-28 (changelog 3). None reaches a tool's effect.
    plain = build_ic(gate)
    ev = method_event(method, None if method.startswith("notifications/") else 3)
    assert passed_through(plain.handle(ev), ev) and requisition_calls(fake) == []


@pytest.mark.parametrize("method", REFUSED)
def test_every_other_method_is_refused_deny_by_default(gate, fake, method):
    plain = build_ic(gate)
    out = plain.handle(method_event(method))
    assert "transformedGatewayRequest" not in out["mcp"]
    assert body_of(out)["error"]["code"] == -32601 and body_of(out)["id"] == 3 and requisition_calls(fake) == []


@pytest.mark.parametrize("member", ["inputResponses", "requestState"])
def test_a_gated_tools_call_carrying_mrtr_input_is_refused(sic, fake, member):
    # MRTR (2026-07-28 changelog 7): a retry carries inputResponses/requestState beside the arguments;
    # the act hashes only params.arguments, so that input would reach the tool unsigned
    sic = sic()
    ev = call_event(sigv4(AKID_A), 7)
    ev["mcp"]["gatewayRequest"]["body"]["params"][member] = {"elicit-1": {"action": "accept", "content": {"ok": True}}} \
        if member == "inputResponses" else "opaque-state"
    ev["mcp"]["rawGatewayRequest"]["body"] = json.dumps(ev["mcp"]["gatewayRequest"]["body"])
    error = body_of(sic.handle(ev))["error"]
    assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "mrtr_input_unsigned"
    assert requisition_calls(fake) == []


@pytest.mark.parametrize("change", [
    {"mcp_name": "refunds___other_tool"},
    {"mcp_name": "=?base64?" + base64.b64encode(b"refunds___other_tool").decode() + "?="},
    {"mcp_method": "tools/list"},
], ids=["other name", "other name base64", "other method"])
def test_a_header_contradicting_the_body_is_refused_before_anything_is_filed(sic, fake, change):
    sic = sic()
    out = sic.handle(call_event(sigv4(AKID_A), 7, **change))
    response = out["mcp"]["transformedGatewayResponse"]
    assert response["statusCode"] == 400 and response["body"]["error"]["code"] == -32020
    assert response["body"]["id"] == 7 and requisition_calls(fake) == []


def test_a_base64_sentinel_mcp_name_that_matches_is_accepted(sic, fake):
    sic = sic()
    name = "=?base64?" + base64.b64encode(GATEWAY_TOOL.encode()).decode() + "?="
    assert meta_of(sic.handle(call_event(sigv4(AKID_A), 7, mcp_name=name)))["status"] == "pending"


def test_a_signed_refusal_passes_a_response_interception_point_unchanged(gate, fake):
    # a REQUEST short-circuit's refusal, seen again at
    # RESPONSE, leaves byte for byte (a pin: today's RESPONSE branch, interceptor.py:137-141)
    plain = build_ic(gate)
    refusal = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "Requisition: signed deny x"}],
               "isError": True, "_meta": {"requisition": {"verdict": "deny", "code": "x", "decision": {"signed_payload": "AAAA"}}}}}
    ev = call_event(sigv4(AKID_A), 7)
    ev["mcp"]["gatewayResponse"] = {"statusCode": 200, "body": refusal}
    out = plain.handle(ev)
    assert out["mcp"]["transformedGatewayResponse"] == {"statusCode": 200, "body": refusal}


def test_no_caller_material_leaves_the_interceptor(sic, fake):
    sic = sic()
    rid = meta_of(sic.handle(call_event(sigv4(AKID_A), 1)))["request_id"]
    fake.approve(rid)
    outs = [sic.handle(call_event(sigv4(AKID_A), 2)), sic.handle(call_event(sigv4(AKID_A), 2))]
    with open(sic.gate.store.path) as handle:
        stored = handle.read()
    for blob in [json.dumps(o) for o in outs[1:]] + [stored, json.dumps(fake.requests)]:
        assert AKID_A not in blob and "Signature=" not in blob


def test_from_env_selects_the_caller_source(fake, tmp_path, jwks, rsa_key):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"schema": "requisition.lab.seed.v1", "act_types": [
        {"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384", "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    jwks_file = tmp_path / "jwks.json"
    jwks_file.write_text(json.dumps(jwks))
    base = {
        "REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
        "REQUISITION_GATEWAY_ID": "gw-1", "REQUISITION_TOOLS": json.dumps({GATEWAY_TOOL: ACT_TYPE}),
        "REQUISITION_SEED": str(seed), "REQUISITION_KEYS_FILE": str(keys), "REQUISITION_REQUIRE_PQ": "0",
    }
    text = lambda ic, ev: body_of(ic.handle(ev))  # noqa: E731
    legacy = icp.from_env({**base, "REQUISITION_STORE": str(tmp_path / "s0.json")})  # default: legacy_session
    assert text(legacy, call_event(sigv4(AKID_A), 7))["error"]["data"]["code"] == "caller_identity_absent"
    assert "awaiting approval" in text(legacy, call_event(None, 8, modern=False, session="s-1"))["result"]["content"][0]["text"]
    iam = icp.from_env({**base, "REQUISITION_STORE": str(tmp_path / "s1.json"), "REQUISITION_CALLER_SOURCE": "sigv4"})
    assert "awaiting approval" in text(iam, call_event(sigv4(AKID_A), 7))["result"]["content"][0]["text"]
    jwt = icp.from_env({**base, "REQUISITION_STORE": str(tmp_path / "s2.json"), "REQUISITION_CALLER_SOURCE": "jwt",
                        "REQUISITION_JWT_ISSUER": ISSUER, "REQUISITION_JWT_JWKS_FILE": str(jwks_file),
                        "REQUISITION_JWT_AUDIENCE": AUDIENCE})
    tok = sign_jwt(rsa_key, claims_for(time.time()))  # from_env's caller runs on the real clock
    assert "awaiting approval" in text(jwt, call_event(bearer(tok), 7))["result"]["content"][0]["text"]
    with pytest.raises(Exception):
        icp.from_env({**base, "REQUISITION_CALLER_SOURCE": "jwt"})  # no issuer/JWKS: refuses to start
    with pytest.raises(Exception):
        icp.from_env({**base, "REQUISITION_CALLER_SOURCE": "clientInfo"})  # unknown source: refuses to start


# --- ambiguity fails closed ------------------------------------------------


@pytest.mark.parametrize("pair", [("Authorization", "authorization"), ("authorization", "AUTHORIZATION")])
def test_duplicate_authorization_headers_are_no_caller_key(sigv4_caller, jwt_caller, sic, fake, pair):
    for first, second in (pair, pair[::-1]):
        headers = {first: sigv4(AKID_A), second: sigv4(AKID_B)}
        assert sigv4_caller().key(headers) is None
        assert jwt_caller().key({first: "Bearer a.b.c", second: "Bearer d.e.f"}) is None
    interceptor = sic()
    ev = call_event(sigv4(AKID_A), 7)
    ev["mcp"]["gatewayRequest"]["headers"]["authorization"] = sigv4(AKID_B)  # beside call_event's "Authorization"
    error = body_of(interceptor.handle(ev))["error"]
    assert error["code"] == icp.FAIL_CLOSED and error["data"]["code"] == "caller_identity_absent"
    assert requisition_calls(fake) == []


@pytest.mark.parametrize("value", [
    sigv4(AKID_A) + ", Credential=" + AKID_B + "/20261110/us-west-2/bedrock-agentcore/aws4_request",
    "AWS4-HMAC-SHA256 Credential=" + AKID_A + "/20261110/us-west-2/bedrock-agentcore/aws4_request, Credential="
    + AKID_B + "/20261110/us-west-2/bedrock-agentcore/aws4_request, SignedHeaders=host, Signature=00",
])
def test_a_value_with_more_than_one_credential_is_no_caller_key(sigv4_caller, value):
    assert sigv4_caller().key({"Authorization": value}) is None


def test_duplicate_mcp_name_headers_are_a_header_mismatch(sic, fake):
    interceptor = sic()
    ev = call_event(sigv4(AKID_A), 7)
    ev["mcp"]["gatewayRequest"]["headers"]["mcp-name"] = "refunds___other_tool"
    response = interceptor.handle(ev)["mcp"]["transformedGatewayResponse"]
    assert response["statusCode"] == 400 and response["body"]["error"]["code"] == -32020
    assert requisition_calls(fake) == []
