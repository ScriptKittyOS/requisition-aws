# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The gate's single-use, signature, post-quantum and transport rules, one section each."""

import base64
import copy
import hashlib
import http.client
import json
import pathlib
import threading
import types

import pytest

from requisition_aws import canonical
from requisition_aws import interceptor as icp
from requisition_aws.client import Client, RequisitionRefused
from requisition_aws.gate import Gate, RecordInvalid, arguments_object
from requisition_aws.interceptor import Interceptor
from requisition_aws.keys import KeyRegistry
from requisition_aws.registry import ToolRegistry
from requisition_aws.store import Store, idempotency_key
from requisition_aws.strands_hook import RequisitionHook

from .conftest import ACT_TYPE, TOOL, refund_args
from .fake_requisition import KEY_ID, MLDSA_KEY_ID, FakeRequisition
from .test_canonical import SEED_SCHEMA
from .test_interceptor import GATEWAY_TOOL, body_of, event, posts, with_id

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def ic(gate):
    reg = ToolRegistry()
    reg.register(GATEWAY_TOOL, ACT_TYPE, SEED_SCHEMA)
    return Interceptor(gate, reg, gateway_id="gw-fixture-0001", agent_name="agentcore-gateway")


def passed(out):
    return "transformedGatewayRequest" in out["mcp"] and "transformedGatewayResponse" not in out["mcp"]


def approved_allow_event(ic, fake):
    ev = event("request_tools_call_refund.json")
    request_id = body_of(ic.handle(ev))["result"]["_meta"]["requisition"]["request_id"]
    fake.approve(request_id)
    return with_id(ev, 8)


# --- at most one pass-through per statement, always ----------------------------------


def test_1_same_rpc_id_resent_five_times_passes_through_once(ic, fake):
    ev = approved_allow_event(ic, fake)
    outs = [ic.handle(ev) for _ in range(5)]
    assert [passed(o) for o in outs] == [True, False, False, False, False]
    for out in outs[1:]:
        text = body_of(out)["result"]["content"][0]["text"]
        assert body_of(out)["result"]["isError"] is True and "already used" in text and "new approval" in text
    assert len(fake.spent) == 1


def test_1_a_replayed_allow_after_exec_not_after_is_refused(ic, fake, clock):
    """The stored execute for this invocation got an allow, but the pass-through never happened (a
    crash between the answer and the claim). A resend after exec_not_after must not pass."""
    ev = approved_allow_event(ic, fake)
    body = ev["mcp"]["gatewayRequest"]["body"]
    session = next(v for k, v in ev["mcp"]["gatewayRequest"]["headers"].items() if k.lower() == "mcp-session-id")
    args = arguments_object("agentcore-gateway", session, ACT_TYPE, body["params"]["arguments"])
    act_hash = canonical.act_hash(ACT_TYPE, args)
    key = idempotency_key("agentcore-gateway", "gw-fixture-0001", session, body["id"], act_hash)
    s = ic.gate.file_or_find(ACT_TYPE, args)
    assert ic.gate.execute(s, args, key).allowed  # stored under the interceptor's own key
    clock.advance(61)  # past the allow's exec_not_after (decision + 60 s), inside the body's not_after
    out = ic.handle(ev)
    assert not passed(out) and "exec_not_after" in body_of(out)["result"]["content"][0]["text"]


def test_1_the_strands_hook_admits_one_tool_use_per_statement(gate, registry, fake):
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    d = gate.execute(s, args, "k-1")
    hook = RequisitionHook(gate, registry, agent_name="refund-agent", session_id="s-1")
    first = types.SimpleNamespace(tool_use={"toolUseId": "tu-1", "name": TOOL, "input": refund_args()}, cancel_tool=False)
    second = types.SimpleNamespace(tool_use={"toolUseId": "tu-2", "name": TOOL, "input": refund_args()}, cancel_tool=False)
    hook._admit(first, s.statement_id, d)
    hook._admit(second, s.statement_id, d)  # before the first tool's AfterToolCallEvent
    assert first.cancel_tool is False and "already used" in second.cancel_tool


def test_1_the_target_runs_once_for_a_reused_id(fake, tmp_path, clock):
    from .test_mcp_target import call, make_target

    t, ledger, _ = make_target(fake, tmp_path, clock)
    call(t, 1)
    fake.approve(next(iter(fake.requests)))
    results = [call(t, 2)[1]["result"] for _ in range(5)]
    assert len(ledger.entries()) == 1 and all(r["content"] == results[0]["content"] for r in results)


# --- signatures checked by default; no cleartext to a public host ----------------------


def env_for(fake, tmp_path, **over):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"act_types": [{"registration": {"name": ACT_TYPE, "act_hash_derivation": "args_sha384",
                                                                "display_schema": SEED_SCHEMA}}]}))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(fake.registry))
    env = {"REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential, "REQUISITION_PRINCIPAL": fake.principal,
           "REQUISITION_GATEWAY_ID": "gw-1", "REQUISITION_TOOLS": json.dumps({GATEWAY_TOOL: ACT_TYPE}),
           "REQUISITION_SEED": str(seed), "REQUISITION_STORE": str(tmp_path / "store.json"),
           "REQUISITION_KEYS_FILE": str(keys)}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


def test_2_the_interceptor_will_not_start_without_a_key_file(fake, tmp_path):
    with pytest.raises(KeyError):
        icp.from_env(env_for(fake, tmp_path, REQUISITION_KEYS_FILE=None))
    client = Client(fake.base_url, fake.credential, fake.principal)
    with pytest.raises(ValueError, match="key file"):
        Interceptor(Gate(client, Store(str(tmp_path / "s.json")), approval_base_url="x"), ToolRegistry(),
                    gateway_id="gw", agent_name="a")


def test_2_lambda_without_a_key_file_refuses_every_call(fake, tmp_path, monkeypatch):
    for k, v in env_for(fake, tmp_path, REQUISITION_KEYS_FILE=None, REQUISITION_REQUIRE_PQ="0").items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("REQUISITION_KEYS_FILE", raising=False)
    monkeypatch.setattr(icp, "_INTERCEPTOR", None)
    body = body_of(icp.lambda_handler(event("request_tools_call_refund.json"), None))
    assert body["error"]["code"] == icp.FAIL_CLOSED and "misconfigured" in body["error"]["message"]


def test_2_require_pq_is_on_by_default(fake, tmp_path):
    assert icp.from_env(env_for(fake, tmp_path)).gate.require_pq is True
    assert icp.from_env(env_for(fake, tmp_path, REQUISITION_REQUIRE_PQ="0")).gate.require_pq is False
    from requisition_aws import mcp_target

    target, _ = mcp_target.from_env(env_for(fake, tmp_path, REQUISITION_TOOLS=None,
                                            REQUISITION_LEDGER=str(tmp_path / "l.jsonl")))
    assert target.gate.require_pq is True


def test_2_a_corrupted_signature_is_never_passed_through(fake, tmp_path, clock):
    it = icp.from_env(env_for(fake, tmp_path, REQUISITION_REQUIRE_PQ="0"))
    it.gate.clock = clock
    ev = approved_allow_event(it, fake)
    fake.corrupt_signatures = True
    out = it.handle(ev)
    assert not passed(out) and body_of(out)["error"]["code"] == icp.FAIL_CLOSED


@pytest.mark.parametrize("url, private_ok, allowed", [
    ("http://127.0.0.1:4103", False, True),
    ("http://localhost:4103", False, True),
    ("http://[::1]:4103", False, True),
    ("https://requisition.example.com", False, True),
    ("http://8.8.8.8:4103", False, False),
    ("http://requisition.example.com", False, False),
    ("http://10.0.4.7:4103", False, False),
    ("http://10.0.4.7:4103", True, True),
    ("http://169.254.10.1", True, True),
    ("http://requisition.internal", True, False),  # a name could resolve anywhere: an IP literal only
    ("http://8.8.8.8", True, False),
])
def test_2_plaintext_only_to_loopback_or_an_allowed_private_address(url, private_ok, allowed):
    if allowed:
        Client(url, "c", "p", allow_plaintext_private=private_ok)
    else:
        with pytest.raises(ValueError, match="https"):
            Client(url, "c", "p", allow_plaintext_private=private_ok)


def test_2_the_interceptor_refuses_to_start_on_http_to_a_public_host(fake, tmp_path):
    with pytest.raises(ValueError, match="https"):
        icp.from_env(env_for(fake, tmp_path, REQUISITION_URL="http://203.0.113.9:4103"))
    it = icp.from_env(env_for(fake, tmp_path, REQUISITION_URL="http://10.1.2.3:4103", REQUISITION_ALLOW_PLAINTEXT_PRIVATE="1"))
    assert it.gate.client.base_url == "http://10.1.2.3:4103"


# --- after the tool ran, never "did not run" --------------------------------------------


def test_3_a_failure_after_the_tool_ran_says_it_ran(fake, tmp_path, clock, monkeypatch):
    from .test_mcp_target import call, make_target, text

    t, ledger, _ = make_target(fake, tmp_path, clock)
    call(t, 1)
    fake.approve(next(iter(fake.requests)))

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(t.gate.store, "compare_and_set", broken)
    result = call(t, 2)[1]["result"]
    assert len(ledger.entries()) == 1
    assert result["isError"] is True and "did not run" not in text(result)
    assert "RAN" in text(result) and "OSError" in text(result)
    assert result["_meta"]["requisition"]["statement_id"]


# --- post-quantum required at run time in the demos and the image ------------------------


def test_4_demos_and_image_require_pq_at_run_time():
    for name in ("run_demo.py", "run_target_local.py"):
        text = (ROOT / "demo" / name).read_text()
        assert "require_pq=opts.require_pq" in text or "require_pq=a.require_pq" in text, name
    assert "ENV REQUISITION_REQUIRE_PQ=1" in (ROOT / "deploy" / "target" / "Dockerfile").read_text().replace("\\\n", "")
    assert "export REQUISITION_REQUIRE_PQ" in (ROOT / "demo" / "rehearse.sh").read_text()


def test_4_the_gate_runs_nothing_on_an_ed25519_only_record_when_pq_is_required(gate, fake, client, store, clock):
    g = Gate(client, store, approval_base_url="x", keys=gate.keys, clock=clock, require_pq=True)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = g.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    with pytest.raises(RecordInvalid, match="post-quantum"):
        g.read(s, args)


# --- three checks only one test each can catch ---------------------------------------------------------


def cosigned(clock, tmp_path, **fake_kw):
    server = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, cosign="signed", **fake_kw)
    server.base_url = server.start()
    return server


def gate_with(server, tmp_path, clock, registry=None, **kw):
    client = Client(server.base_url, server.credential, server.principal, timeout=5)
    keys = KeyRegistry.from_bytes(json.dumps(registry or server.registry).encode())
    return Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="x", keys=keys, clock=clock, **kw)


def statement_of(server, gate):
    args = arguments_object("refund-agent", "s-m", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    server.approve(s.request_id)
    return gate.read(s, args)


def test_5_m1_a_cosignature_key_id_other_than_the_signed_one_is_refused(tmp_path, clock):
    """(gate.py co-signature key_id rule): the co-signature names another key id whose entry is the
    SAME ML-DSA-87 key, so only the key_id rule can catch it."""
    server = cosigned(clock, tmp_path)
    try:
        registry = copy.deepcopy(server.registry)
        twin = dict(next(e for e in registry["entries"] if e["key_id"] == MLDSA_KEY_ID), key_id="requisition_lab_dev_mldsa87_twin")
        registry["entries"].append(twin)
        server.cosign_tamper = lambda cos: {**cos, "key_id": "requisition_lab_dev_mldsa87_twin"}
        with pytest.raises(RecordInvalid, match="cosign.key_id"):
            statement_of(server, gate_with(server, tmp_path, clock, registry))
    finally:
        server.stop()


def test_5_m2_an_ed25519_cosignature_does_not_count_as_post_quantum(tmp_path, clock):
    """(gate.py mldsa87-key check): the signed cosign names the Ed25519 key and the co-signature is
    a valid Ed25519 signature; only the algorithm check stops it from satisfying require_pq."""
    server = cosigned(clock, tmp_path)
    server.cosign_with = "ed25519"
    try:
        with pytest.raises(RecordInvalid, match="ML-DSA-87"):
            statement_of(server, gate_with(server, tmp_path, clock, require_pq=True))
    finally:
        server.stop()


@pytest.mark.parametrize("tamper", ["drop", "differ"])
def test_5_m3_an_allow_whose_signed_exec_not_after_is_not_the_answers_is_refused(gate, fake, tamper):
    """(gate.py signed exec_not_after check)."""
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    fake.response_tamper = (lambda r: {**r, "exec_not_after": None}) if tamper == "drop" else \
        (lambda r: {**r, "exec_not_after": "2099-01-01T00:00:00Z"})
    with pytest.raises(RecordInvalid, match="exec_not_after"):
        gate.execute(s, args, "k-m3")


# --- smaller rules -------------------------------------------------------------------------------------


def test_6_an_exact_retry_after_revocation_is_superseded(gate, fake):
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    assert gate.execute(s, args, "k-6").allowed
    fake.revoke(s.request_id)
    with pytest.raises(RequisitionRefused) as err:
        gate.replay_stored("k-6", args)
    assert err.value.code == "decision_superseded" and err.value.status == 409


def test_7_the_demos_require_and_compare_the_key_file(fake, tmp_path, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("rtl", ROOT / "demo" / "run_target_local.py")
    rtl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rtl)
    for k, v in {"REQUISITION_URL": fake.base_url, "REQUISITION_CRED": fake.credential,
                 "REQUISITION_PRINCIPAL": fake.principal,
                 "REQUISITION_DEMO_DIR": str(tmp_path)}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("REQUISITION_LAB_KEY_FILE", raising=False)
    with pytest.raises(SystemExit):
        rtl.main(["--transcript", str(tmp_path / "t.txt"), "--timeout", "0", "--poll", "0", "--no-require-pq"])
    other = tmp_path / "other.json"
    other.write_text(json.dumps(FakeRequisition().registry))
    monkeypatch.setenv("REQUISITION_LAB_KEY_FILE", str(other))
    assert rtl.main(["--transcript", str(tmp_path / "t.txt"), "--timeout", "0", "--poll", "0", "--no-require-pq"]) == 1
    assert "not byte-equal" in (tmp_path / "t.txt").read_text()
    run_demo = (ROOT / "demo" / "run_demo.py").read_text()
    assert "REQUISITION_LAB_KEY_FILE" in run_demo and "not byte-equal" in run_demo


def test_8_botocore_is_a_demo_extra_and_cryptography_is_declared():
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert not any(d.startswith("botocore") for d in project["dependencies"])
    assert any(d.startswith("cryptography") for d in project["dependencies"])
    assert any(d.startswith("botocore") for d in project["optional-dependencies"]["strands"])
    assert "--require-hashes" in (ROOT / "deploy" / "target" / "Dockerfile").read_text()


@pytest.mark.parametrize("length", ["-1", "abc"])
def test_10_a_bad_content_length_is_400(fake, tmp_path, clock, length):
    from requisition_aws.mcp_target import serve

    from .test_mcp_target import make_target

    t, _, _ = make_target(fake, tmp_path, clock)
    server = serve(t, "127.0.0.1", 0)
    server.block_on_close = False  # a handler blocked on read(-1) must not hang the test's close
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("content-type", "application/json")
        conn.putheader("content-length", length)
        conn.endheaders()
        try:
            status = conn.getresponse().status
        except (TimeoutError, OSError):
            status = "no answer (the handler blocked)"
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()


def test_11_the_raw_body_must_match_with_types(ic, fake):
    ev = event("request_tools_call_refund.json")
    ev["mcp"]["rawGatewayRequest"]["body"] = ev["mcp"]["rawGatewayRequest"]["body"].replace("1250", "1250.0")
    assert body_of(ic.handle(ev))["error"]["code"] == -32600
