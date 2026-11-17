# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
import contextlib
import json
import multiprocessing
import os
import tempfile

import pytest

from requisition_aws import canonical
from requisition_aws.client import (
    Client,
    RequisitionRefused,
    RequisitionUnavailable,
    loads_strict,
)
from requisition_aws.gate import Gate, RecordInvalid, StaleExecute, arguments_object
from requisition_aws.store import Store, idempotency_key

from .conftest import ACT_TYPE, refund_args


def args_obj(**over):
    return arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args(**over))


# --- client: exact body shapes -------------------------------------------------------------------


def test_propose_body_shape(client):
    args = args_obj()
    body = loads_strict(client.propose_body(ACT_TYPE, args))
    # sanction_requests.ex:75-76: exactly these members, no nonce
    assert set(body) == {"principal", "act_type", "act_hash", "act_hash_alg", "display"}
    assert body["act_hash_alg"] == "sha384+canonical_payload.v3"
    assert body["display"] == args
    assert body["act_hash"] == canonical.act_hash(ACT_TYPE, args)
    assert len(body["act_hash"]) == 96  # sanction_requests.ex:82


def test_execute_body_shape(client):
    args = args_obj()
    raw = client.execute_body(ACT_TYPE, args, "ab" * 32, "n" * 10, "2026-11-09T12:02:00Z")
    body = loads_strict(raw)
    # execute.ex:99-100
    assert set(body) == {
        "principal", "act_type", "act_hash", "act_hash_alg", "display_projection", "statement_id", "nonce", "not_after",
    }
    assert body["display_projection"] == args
    assert raw == canonical.encode(body)  # deterministic bytes: what is stored is what is replayed


@pytest.mark.parametrize("nonce", ["", "has space", "x" * 129, "slash/"])
def test_execute_body_refuses_a_bad_nonce(client, nonce):
    with pytest.raises(ValueError):
        client.execute_body(ACT_TYPE, args_obj(), "s", nonce, "2026-11-09T12:02:00Z")


def test_credential_is_never_in_repr(client):
    assert client.credential not in repr(client)


def test_unreachable_is_unavailable():
    c = Client("http://127.0.0.1:9", "rqc_x", "rqp_x", timeout=1)
    with pytest.raises(RequisitionUnavailable):
        c.propose(ACT_TYPE, args_obj())


def test_5xx_is_unavailable_and_4xx_is_refused(client, fake):
    fake.status_override = 503
    with pytest.raises(RequisitionUnavailable):
        client.propose(ACT_TYPE, args_obj())
    fake.status_override = None
    bad = Client(fake.base_url, "rqc_wrong", fake.principal)
    with pytest.raises(RequisitionRefused) as err:
        bad.propose(ACT_TYPE, args_obj())
    assert err.value.code == "caller_unauthenticated"


def test_dropped_connection_is_unavailable(client, fake):
    fake.down = True
    with pytest.raises(RequisitionUnavailable):
        client.get_request("00000000-0000-0000-0000-000000000000")


def test_get_request_refuses_a_non_uuid_before_sending(client, fake):
    with pytest.raises(ValueError):
        client.get_request("../keys")
    assert fake.calls == []


def test_duplicate_members_in_an_answer_are_refused():
    with pytest.raises(ValueError):
        loads_strict(b'{"verdict":"allow","verdict":"deny"}')


# --- store ---------------------------------------------------------------------------------------


def test_create_if_absent_is_conditional(store):
    assert store.create_if_absent("executes", "k", {"v": 1}) == (True, {"v": 1})
    assert store.create_if_absent("executes", "k", {"v": 2}) == (False, {"v": 1})
    assert store.get("executes", "k") == {"v": 1}


def test_store_file_is_private_and_json(store):
    store.create_if_absent("executes", "k", {"v": 1})
    assert oct(os.stat(store.path).st_mode & 0o777) == "0o600"
    assert json.loads(open(store.path).read())["executes"]["k"] == {"v": 1}


def _race(path, key, value, queue):
    queue.put(Store(path).create_if_absent("executes", key, {"v": value})[0])


def test_create_if_absent_across_processes_has_one_winner(tmp_path):
    path = str(tmp_path / "s.json")
    queue = multiprocessing.Queue()
    procs = [multiprocessing.Process(target=_race, args=(path, "k", i, queue)) for i in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    wins = [queue.get() for _ in procs]
    assert wins.count(True) == 1


def test_idempotency_key_distinguishes_int_and_string_ids():
    assert idempotency_key("gw", "sess", 1, "h") != idempotency_key("gw", "sess", "1", "h")
    assert len(idempotency_key("a")) == 64


# --- gate: the whole flow against the fake -------------------------------------------------------


def test_propose_is_deduplicated_on_act_hash(gate, fake):
    args = args_obj()
    first = gate.file_or_find(ACT_TYPE, args)
    second = gate.file_or_find(ACT_TYPE, args)
    assert first.request_id == second.request_id
    assert first.filed_now and not second.filed_now
    assert sum(1 for m, p in fake.calls if m == "POST" and p == "/v1/sanction-requests") == 1
    assert first.status == "pending" and first.approval_url == "http://127.0.0.1:4103/approvals"


def test_sanctioned_execute_allow_then_spent_closes_dedupe(gate, fake, clock):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    assert s.status == "sanctioned" and s.statement_id
    assert s.approval_url.endswith("/approvals/" + fake.requests[s.request_id]["approval_id"])
    d = gate.execute(s, args, "key-1")
    assert d.allowed and d.signature_checked and not d.replayed and gate.runnable(d)
    # exact retry: the stored bytes again, the stored allow back
    again = gate.execute(s, args, "key-1")
    assert again.allowed and again.replayed and again.decision == d.decision
    # a fresh nonce on the same statement: signed deny statement_spent
    spent = gate.execute_fresh(s, args, "key-2")
    assert not spent.allowed and spent.code == "statement_spent" and spent.signature_checked
    # the spent request is never matched again: a new identical call files a new request
    s2 = gate.file_or_find(ACT_TYPE, args)
    assert s2.request_id != s.request_id and s2.filed_now


def test_allow_is_not_runnable_after_exec_not_after(gate, fake, clock):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    d = gate.execute(gate.read(s, args), args, "k")
    clock.advance(61)
    assert not gate.runnable(d)


def test_a_stored_not_after_in_the_past_fails_closed(gate, fake, clock):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    body = gate.client.execute_body(ACT_TYPE, args, s.statement_id, "k", "2026-11-09T12:00:30Z")
    gate.store.claim_execute("k", s.request_id, body, "2026-11-09T12:00:30Z")
    clock.advance(31)
    before = len(fake.calls)
    with pytest.raises(StaleExecute):
        gate.execute(s, args, "k")
    assert len(fake.calls) == before  # nothing was sent


def test_refused_request_is_closed(gate, fake):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.refuse(s.request_id)
    s = gate.read(s, args)
    assert s.status == "refused" and s.refused_code
    assert gate.file_or_find(ACT_TYPE, args).request_id != s.request_id


def test_unknown_stored_request_is_refiled(gate, fake):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    del fake.requests[s.request_id]
    s2 = gate.file_or_find(ACT_TYPE, args)
    assert s2.request_id != s.request_id


def test_intake_refusal_sends_nothing(gate, fake):
    with pytest.raises(canonical.IntakeRefusal):
        gate.file_or_find(ACT_TYPE, args_obj(reason="task-123 refund"))
    with pytest.raises(canonical.IntakeRefusal):
        gate.file_or_find(ACT_TYPE, args_obj(amount_minor=12.5))
    assert fake.calls == [("GET", "/v1/keys")]


def test_a_tampered_decision_is_refused(gate, fake, monkeypatch):
    """Only the signature can catch this one: an allow whose signed bytes are changed in a field no
    other rule reads (decided_at), with receipt_hash recomputed in the envelope and the answer."""
    import hashlib

    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    s = gate.read(s, args)
    real = gate.client.execute

    def tamper(body):
        answer = real(body)
        env = answer["decision"]
        signed = json.loads(env["signed_payload"])
        signed["metadata"]["decided_at"] = "2026-11-09T11:59:59Z"
        env["signed_payload"] = canonical.encode(signed).decode()
        env["receipt_hash"] = answer["receipt_hash"] = hashlib.sha256(env["signed_payload"].encode()).hexdigest()
        return answer

    monkeypatch.setattr(gate.client, "execute", tamper)
    with pytest.raises(RecordInvalid, match="signature"):
        gate.execute(s, args, "k1")


def test_a_statement_for_other_arguments_is_refused(gate, fake):
    args = args_obj()
    s = gate.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    with pytest.raises(RecordInvalid):
        gate.read(s, args_obj(amount_minor=999999))


def test_wrong_pinned_key_refuses(client, store, clock, fake):
    other = type(fake)(act_types={}, now=clock.now)
    keys = __import__("requisition_aws.keys", fromlist=["KeyRegistry"]).KeyRegistry.from_bytes(
        json.dumps(other.registry).encode()
    )
    g = Gate(client, store, approval_base_url="http://x", keys=keys, clock=clock)
    args = args_obj()
    s = g.file_or_find(ACT_TYPE, args)
    fake.approve(s.request_id)
    with pytest.raises(RecordInvalid):
        g.read(s, args)


@contextlib.contextmanager
def _short_socket_path(name="v1.sock"):
    """A socket path in a short private folder. The system temporary folder is used on purpose, here only: a Unix
    socket path holds at most 107 bytes on Linux, and a long pytest tmp_path would fail the bind."""
    folder = tempfile.mkdtemp(prefix="rq-")  # mode 0700
    path = os.path.join(folder, name)
    try:
        assert len(path.encode()) < 100, f"socket path is {len(path.encode())} bytes; keep it under 100: {path}"
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        os.rmdir(folder)


def test_client_over_a_unix_socket(clock):
    from .fake_requisition import FakeRequisition
    from .test_canonical import SEED_SCHEMA

    fake = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now)
    with _short_socket_path() as sock:
        base = fake.start(unix_path=sock)
        try:
            c = Client(base, fake.credential, fake.principal, unix_socket=sock)
            assert json.loads(c.keys())["entries"]
            assert c.propose(ACT_TYPE, args_obj())["status"] == "pending"
        finally:
            fake.stop()
