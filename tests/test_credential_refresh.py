# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The interceptor re-reads the caller credential on ``caller_credential_expired`` and retries exactly once.
If the fresh credential is also refused, it fails closed, and the one-pass-through-per-approval behaviour is
unchanged (pinned below).

Measured before these tests:
* the deployed Lambda reads the caller credential from Secrets Manager ONCE per execution environment
  (the deployed entry, now deploy/lambda/interceptor_entry.py: ``_load_caller``, ``_CALLER_LOADED``) into REQUISITION_CRED; the
  interceptor builds one ``Client`` from it per environment (interceptor.py ``from_env``/``_INTERCEPTOR``);
* every Requisition call the interceptor makes is in ``_tools_call``, through the gate:
  ``replay_stored`` (POST /v1/execute), ``file_or_find`` (GET /v1/sanction-requests?act_hash=, POST
  /v1/sanction-requests, GET /v1/sanction-requests/:id) and ``execute`` (POST /v1/execute, its body
  stored BEFORE the call); keys come from the pinned file, outcomes are not reported here;
* the claim (``gate.claim``) and the pass-through come AFTER the last Requisition call, so a refused
  credential always stops the flow before the claim: retrying the whole invocation can never claim twice.
* Requisition answers 401 ``caller_credential_expired`` / ``caller_credential_revoked`` (only after the
  secret matched) or ``caller_unauthenticated`` (codes.ex:39-40, caller_credentials.ex:24-25).

The interface the tests pin: ``Interceptor(..., credential_source=<callable returning the credential
read fresh from its source>, reread_interval=<seconds>, monotonic=<clock>)``.
"""

import copy
import json

import pytest

from requisition_aws import interceptor as icp
from requisition_aws.interceptor import Interceptor
from requisition_aws.registry import ToolRegistry

from .conftest import ACT_TYPE
from .test_canonical import SEED_SCHEMA
from .test_interceptor import GATEWAY_TOOL, body_of, event, posts, with_id

EXPIRED, REVOKED, UNAUTH = "caller_credential_expired", "caller_credential_revoked", "caller_unauthenticated"
FRESH = "rqc_fresh_credential_after_remint"


class Secret:
    """The caller secret as Secrets Manager holds it; ``reads`` counts the re-reads (cache bypassed)."""

    def __init__(self, credential):
        self.credential, self.reads, self.fail = credential, 0, False

    def __call__(self):
        self.reads += 1
        if self.fail:
            raise RuntimeError("secrets manager unavailable")
        return self.credential


class Mono:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def mono():
    return Mono()


@pytest.fixture
def secret(fake):
    return Secret(fake.credential)


@pytest.fixture
def ric(gate, secret, mono):
    """A factory, called inside each test, so a missing interface fails the test (not its setup)."""

    def build(**kw):
        reg = ToolRegistry()
        reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
        return Interceptor(gate, reg, gateway_id="gw-fixture-0001", agent_name="agentcore-gateway",
                           credential_source=secret, reread_interval=kw.pop("reread_interval", 60.0),
                           monotonic=mono, **kw)

    return build


def remint(fake, secret, fresh=FRESH):
    """The cached credential expires; the operator re-mints; the secret now holds the fresh one."""
    old = fake.credential
    fake.credential_states[old] = EXPIRED
    fake.also_valid.add(fresh)
    secret.credential = fresh
    return old


def presented(fake, credential):
    return [c for c in fake.auth_log if c[2] == credential]


def requisition_posts(fake, path):
    return posts(fake, path)


def meta(out):
    return body_of(out)["result"]["_meta"]["requisition"]


def passed(out, ev):
    return out == {"interceptorOutputVersion": "1.0",
                   "mcp": {"transformedGatewayRequest": {"body": ev["mcp"]["gatewayRequest"]["body"]}}}


# --- (a) expired cached credential: one re-read, the same request retried once, success ----------------


def test_a_expired_cached_credential_is_reread_and_the_same_request_retried_once(ric, fake, secret):
    ic = ric()
    old = remint(fake, secret)
    out = ic.handle(event("request_tools_call_refund.json"))
    assert meta(out)["status"] == "pending" and body_of(out)["id"] == 7
    assert secret.reads == 1
    refused = presented(fake, old)
    assert len(refused) == 1  # the first Requisition call, refused; nothing more with the old credential
    # the retry is the same request: the same first call again, now with the fresh credential
    assert presented(fake, FRESH)[0][:2] == refused[0][:2]
    assert requisition_posts(fake, "/v1/sanction-requests") == 1


# --- (b) the fresh credential also refused: fail closed, no second retry -----------------------------------


@pytest.mark.parametrize("fresh_state", [EXPIRED, REVOKED, UNAUTH, "unchanged"])
def test_b_a_refused_fresh_credential_fails_closed_without_a_second_retry(ric, fake, secret, fresh_state):
    ic = ric()
    old = fake.credential
    fake.credential_states[old] = EXPIRED
    if fresh_state == "unchanged":
        secret.credential = old  # the secret was not re-minted: re-reading gives the same credential
    elif fresh_state == UNAUTH:
        secret.credential = "rqc_unknown_to_requisition"
    else:
        secret.credential = FRESH
        fake.credential_states[FRESH] = fresh_state
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    want = EXPIRED if fresh_state == "unchanged" else fresh_state
    assert body["id"] == 7 and body["error"]["code"] == icp.FAIL_CLOSED
    assert want in body["error"]["message"] and "fail closed" in body["error"]["message"]
    assert secret.reads == 1
    assert len(presented(fake, old)) == 1  # never re-sent with the stale credential
    if fresh_state != "unchanged":
        assert len(presented(fake, secret.credential)) == 1  # exactly one retry, then stop
    assert len(fake.auth_log) == (1 if fresh_state == "unchanged" else 2)


def test_b_a_failing_secret_read_fails_closed(ric, fake, secret):
    ic = ric()
    fake.credential_states[fake.credential] = EXPIRED
    secret.fail = True
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    assert body["error"]["code"] == icp.FAIL_CLOSED and EXPIRED in body["error"]["message"]
    assert secret.reads == 1 and len(fake.auth_log) == 1


# --- (c) only caller_credential_expired triggers a re-read ---------------------------------------------------


@pytest.mark.parametrize("code", [REVOKED, UNAUTH, "caller_grant_not_live", "rate_limited"])
def test_c_no_other_refusal_triggers_a_reread(ric, fake, secret, code):
    ic = ric()
    old = fake.credential
    fake.credential_states[old] = code
    fake.also_valid.add(FRESH)
    secret.credential = FRESH
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    assert body["error"]["code"] == icp.FAIL_CLOSED and code in body["error"]["message"]
    assert secret.reads == 0 and presented(fake, FRESH) == []


def test_c_no_credential_source_means_no_reread(gate, fake):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    ic = Interceptor(gate, reg, gateway_id="gw-fixture-0001", agent_name="agentcore-gateway")
    fake.credential_states[fake.credential] = EXPIRED
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    assert body["error"]["code"] == icp.FAIL_CLOSED and EXPIRED in body["error"]["message"]
    assert len(fake.auth_log) == 1


# --- (d) one pass-through per approval, unchanged, with the retry around it -----------------------------------


@pytest.mark.parametrize("expire_on", [("POST", "/v1/execute"), ("GET", "/v1/sanction-requests/")],
                         ids=["expiry-at-execute", "expiry-at-the-mint-read"])
def test_d_an_approved_statement_passes_through_exactly_once_across_the_retry(ric, fake, secret, expire_on):
    ic = ric()
    ev = event("request_tools_call_refund.json")
    request_id = meta(ic.handle(ev))["request_id"]
    fake.approve(request_id)
    # the cached credential expires on the very call that mints (GET) or spends (POST /v1/execute)
    fake.also_valid.add(FRESH)
    secret.credential = FRESH
    fake.expire_on = expire_on
    ev2 = with_id(ev, 8)
    assert passed(ic.handle(ev2), ev2)
    assert secret.reads == 1
    assert len(fake.claims) == 1 and len(fake.spent) == 1
    assert len(fake.statements) == 1  # minted once
    stored = [k for k, v in json.loads(open(ic.gate.store.path).read())["executes"].items()]
    assert len(stored) == 1  # one execute body for this invocation, replayed by the retry, never a second
    # the same invocation again (a Gateway retry, or the client reusing id 8): refused, already used
    out = ic.handle(ev2)
    assert not passed(out, ev2) and "already used" in body_of(out)["result"]["content"][0]["text"]
    assert len(fake.claims) == 1 and len(fake.spent) == 1


def test_d_expiry_on_a_replay_after_the_pass_through_never_passes_again(ric, fake, secret):
    ic = ric()
    ev = event("request_tools_call_refund.json")
    fake.approve(meta(ic.handle(ev))["request_id"])
    ev2 = with_id(ev, 8)
    assert passed(ic.handle(ev2), ev2)
    # later the credential expires; the same invocation arrives again: re-read, retried once, still refused
    remint(fake, secret)
    out = ic.handle(ev2)
    assert not passed(out, ev2) and "already used" in body_of(out)["result"]["content"][0]["text"]
    assert secret.reads == 1 and len(fake.claims) == 1 and len(fake.spent) == 1


def test_d_the_claim_is_taken_once_even_if_both_attempts_reach_it(ric, fake, secret, monkeypatch):
    # a credential refusal can only come from a Requisition call, and every one precedes the claim;
    # pinned: the claim function runs exactly once per pass-through with the retry around it
    ic = ric()
    ev = event("request_tools_call_refund.json")
    fake.approve(meta(ic.handle(ev))["request_id"])
    calls = []
    original = ic.gate.claim
    monkeypatch.setattr(ic.gate, "claim", lambda *a, **k: calls.append(1) or original(*a, **k))
    fake.also_valid.add(FRESH)
    secret.credential = FRESH
    fake.expire_on = ("POST", "/v1/execute")
    ev2 = with_id(ev, 8)
    assert passed(ic.handle(ev2), ev2) and calls == [1]


# --- (e) the re-read is rate-limited per environment ----------------------------------------------------------


def test_e_at_most_one_reread_per_interval(ric, fake, secret, mono):
    ic = ric(reread_interval=60.0)
    fake.credential_states[fake.credential] = EXPIRED  # a broken secret: never re-minted
    for rpc_id in (7, 8, 9):
        body = body_of(ic.handle(with_id(event("request_tools_call_refund.json"), rpc_id)))
        assert body["error"]["code"] == icp.FAIL_CLOSED and EXPIRED in body["error"]["message"]
    assert secret.reads == 1
    mono.t += 59.0
    ic.handle(with_id(event("request_tools_call_refund.json"), 10))
    assert secret.reads == 1
    mono.t += 2.0  # past the interval since the last re-read
    ic.handle(with_id(event("request_tools_call_refund.json"), 11))
    assert secret.reads == 2


def test_e_the_interval_is_configured_and_never_zero(gate, secret, mono):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    with pytest.raises(ValueError):
        Interceptor(gate, reg, gateway_id="gw", agent_name="a", credential_source=secret, reread_interval=0)


# --- (f) the fresh credential replaces the cache ------------------------------------------------------------------


def test_f_the_fresh_credential_is_used_for_later_calls(ric, fake, secret):
    ic = ric()
    old = remint(fake, secret)
    ic.handle(event("request_tools_call_refund.json"))
    before = len(fake.auth_log)
    out = ic.handle(with_id(event("request_tools_call_refund.json"), 8))
    assert meta(out)["status"] == "pending"
    assert secret.reads == 1
    assert all(c[2] == FRESH for c in fake.auth_log[before:]) and len(presented(fake, old)) == 1
    assert ic.gate.client.credential == FRESH


def test_f_the_credential_never_appears_in_any_output_or_log(ric, fake, secret, caplog):
    ic = ric()
    remint(fake, secret)
    caplog.set_level("DEBUG")
    out = ic.handle(event("request_tools_call_refund.json"))
    text = json.dumps(out) + "\n".join(r.getMessage() for r in caplog.records)
    assert FRESH not in text and "rqc_" not in text
    assert any("re-read" in r.getMessage() for r in caplog.records)  # the re-read is logged, by name only


# --- the Lambda entry: from_env and lambda_handler take the source ---------------------------------------------


def test_from_env_takes_the_source_and_the_interval(fake, tmp_path, secret):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"schema": "requisition.lab.seed.v1", "act_types": [
        {"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384", "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    env = {
        "REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
        "REQUISITION_GATEWAY_ID": "gw-1", "REQUISITION_TOOLS": json.dumps({GATEWAY_TOOL: ACT_TYPE}),
        "REQUISITION_SEED": str(seed), "REQUISITION_STORE": str(tmp_path / "store.json"),
        "REQUISITION_KEYS_FILE": str(keys), "REQUISITION_REQUIRE_PQ": "0", "REQUISITION_CRED_REREAD_SECONDS": "30",
    }
    ic = icp.from_env(env, credential_source=secret)
    assert ic.reread_interval == 30.0
    remint(fake, secret)
    assert meta(ic.handle(event("request_tools_call_refund.json")))["status"] == "pending" and secret.reads == 1
    assert icp.from_env({k: v for k, v in env.items() if k != "REQUISITION_CRED_REREAD_SECONDS"}).reread_interval == 60.0


def test_lambda_handler_passes_the_source_to_the_interceptor(fake, tmp_path, secret, monkeypatch):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"schema": "requisition.lab.seed.v1", "act_types": [
        {"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384", "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    for k, v in {"REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential,
                 "REQUISITION_PRINCIPAL": fake.principal, "REQUISITION_GATEWAY_ID": "gw-1",
                 "REQUISITION_TOOLS": json.dumps({GATEWAY_TOOL: ACT_TYPE}), "REQUISITION_SEED": str(seed),
                 "REQUISITION_STORE": str(tmp_path / "store.json"), "REQUISITION_KEYS_FILE": str(keys),
                 "REQUISITION_REQUIRE_PQ": "0"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(icp, "_INTERCEPTOR", None)
    remint(fake, secret)
    out = icp.lambda_handler(copy.deepcopy(event("request_tools_call_refund.json")), None, credential_source=secret)
    assert meta(out)["status"] == "pending" and secret.reads == 1


# --- the bound is the code, not the limiter --------------


def test_exactly_one_reread_even_when_the_interval_has_passed(ric, fake, secret, mono):
    # a mutant (the retry calls _tools_call again) survived an earlier form of this test: the test clock never advanced,
    # so the 60 s limiter hid a second re-read. Here every read advances the clock past the interval.
    real = secret.__call__

    def advancing():
        mono.t += 3600  # the limiter alone would allow another re-read
        return real()

    ic = ric()
    ic.credential_source = advancing
    fake.credential_states[fake.credential] = EXPIRED
    secret.credential = FRESH
    fake.credential_states[FRESH] = EXPIRED
    body = body_of(ic.handle(event("request_tools_call_refund.json")))
    assert body["error"]["code"] == icp.FAIL_CLOSED and secret.reads == 1

