# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A retirement must reach a running gate; post-quantum is decided by the pinned key file, not by the record's own
``cosign`` claim; the entry points accept the KMS signer by default. The rule's text and
its vectors are tests/test_key_rule.py's."""

import copy
import json
import os

import pytest

from requisition_aws import canonical
from requisition_aws.client import Client
from requisition_aws.gate import Gate, RecordInvalid, arguments_object
from requisition_aws.keys import KeyRegistry
from requisition_aws.store import Store

from .conftest import ACT_TYPE, refund_args
from .fake_requisition import KEY_ID, FakeRequisition
from .test_canonical import SEED_SCHEMA


def write(path, registry, mtime=None):
    path.write_text(json.dumps(registry))
    if mtime is not None:
        os.utime(path, ns=(mtime, mtime))


class Wall:
    def __init__(self):
        self.t = 1_000.0

    def __call__(self):
        return self.t


# --- a retirement reaches a running gate -----------------------------------------------------------


def test_a_retirement_in_the_key_file_reaches_a_running_registry(tmp_path, fake, client, clock):
    path = tmp_path / "keys.json"
    write(path, fake.registry)
    keys = KeyRegistry.from_file(str(path), max_age_seconds=300, clock=Wall())
    gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://x", keys=keys, clock=clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    sanction = gate.file_or_find(ACT_TYPE, args)
    fake.approve(sanction.request_id)
    sanction = gate.read(sanction, args)  # control: the active key verifies the statement
    assert sanction.statement is not None
    retired = copy.deepcopy(fake.registry)
    retired["entries"][0].update(status="retired", valid_to="2026-11-09T11:00:00Z", status_changed_at="2026-11-09T11:00:00Z")
    write(path, retired)  # the file the gate was started with, changed in place; no restart, no new registry
    with pytest.raises(RecordInvalid, match="key_not_valid_at_signing"):
        gate.read(sanction, args)


def test_a_rewrite_that_keeps_the_stat_is_picked_up_at_the_bounded_age(tmp_path, fake):
    """"retired" and "revoked" are both seven bytes: the size and, by os.utime, the mtime stay the same, so only the
    bounded age can bring the change in."""
    retired = copy.deepcopy(fake.registry)
    retired["entries"][0].update(status="retired", valid_to="2027-01-01T00:00:00Z")
    path = tmp_path / "keys.json"
    write(path, retired, mtime=1_700_000_000_000_000_000)
    wall = Wall()
    keys = KeyRegistry.from_file(str(path), max_age_seconds=300, clock=wall)
    assert keys.status_of(KEY_ID) == "retired"
    path.write_text(path.read_text().replace('"retired"', '"revoked"'))
    os.utime(path, ns=(1_700_000_000_000_000_000,) * 2)
    wall.t += 299
    assert keys.status_of(KEY_ID) == "retired"  # inside the bound and the stat unchanged: not re-read
    wall.t += 2
    assert keys.status_of(KEY_ID) == "revoked"  # past the bound: re-read whatever the stat says


def test_an_unreadable_key_file_fails_closed_and_recovers(tmp_path, fake):
    path = tmp_path / "keys.json"
    write(path, fake.registry)
    wall = Wall()
    keys = KeyRegistry.from_file(str(path), max_age_seconds=300, clock=wall)
    path.write_text("{not json")
    assert keys.check({"key_id": KEY_ID, "signed_payload": "{}", "signature": ""}) == "key_file_unreadable"
    assert keys.algorithm(KEY_ID) is None  # nothing from the last good read is served while the file is unreadable
    write(path, fake.registry)
    assert keys.algorithm(KEY_ID) == "ed25519"


# --- post-quantum by policy, not by the record's own claim -------------------------------------------


def server(clock, cosign):
    s = FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=clock.now, newer_routes=True, cosign=cosign)
    s.base_url = s.start()
    return s


def test_a_record_that_omits_its_cosign_claim_is_refused_when_the_key_file_holds_a_pq_key(tmp_path, clock):
    s = server(clock, "signed")  # the registry holds the lab's ML-DSA-87 key
    try:
        keys = KeyRegistry.from_bytes(json.dumps(s.registry).encode())
        gate = Gate(Client(s.base_url, s.credential, s.principal, timeout=5), Store(str(tmp_path / "s.json"), clock=clock),
                    approval_base_url="http://x", keys=keys, clock=clock)  # no require_pq: the library default
        payload = json.dumps({"occurred_at": "2026-11-09T12:00:00Z", "metadata": {}})
        envelope = {"key_id": KEY_ID, "signed_payload": payload}
        with pytest.raises(RecordInvalid, match="post-quantum"):
            gate._cosigned({}, envelope, {})  # a classical forger writes a record with no cosign member at all
    finally:
        s.stop()


def test_seat_absent_is_refused_by_default_when_the_key_file_holds_a_pq_key(tmp_path, clock):
    s = server(clock, "seat_absent")
    try:
        keys = KeyRegistry.from_bytes(json.dumps(s.registry).encode())
        gate = Gate(Client(s.base_url, s.credential, s.principal, timeout=5), Store(str(tmp_path / "s.json"), clock=clock),
                    approval_base_url="http://x", keys=keys, clock=clock)
        args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
        sanction = gate.file_or_find(ACT_TYPE, args)
        s.approve(sanction.request_id)
        with pytest.raises(RecordInvalid, match="post-quantum"):
            gate.read(sanction, args)
    finally:
        s.stop()


def test_allow_classical_only_is_the_explicit_opt_out(tmp_path, clock):
    s = server(clock, "seat_absent")
    try:
        keys = KeyRegistry.from_bytes(json.dumps(s.registry).encode())
        gate = Gate(Client(s.base_url, s.credential, s.principal, timeout=5), Store(str(tmp_path / "s.json"), clock=clock),
                    approval_base_url="http://x", keys=keys, clock=clock, allow_classical_only=True)
        args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
        sanction = gate.file_or_find(ACT_TYPE, args)
        s.approve(sanction.request_id)
        assert gate.read(sanction, args).statement is not None
    finally:
        s.stop()


def test_without_a_pq_key_in_the_file_nothing_is_expected(tmp_path, fake, client, clock):
    keys = KeyRegistry.from_bytes(json.dumps(fake.registry).encode())
    gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://x", keys=keys, clock=clock)
    assert gate._cosigned({}, {"key_id": KEY_ID, "signed_payload": "{}"}, {}) is False


# --- the entry points ---------------------------------------------------------------------------------


def test_the_entry_points_accept_the_kms_signer_by_default(tmp_path, fake):
    path = tmp_path / "keys.json"
    write(path, fake.registry)
    keys = KeyRegistry.from_env({"REQUISITION_KEYS_FILE": str(path)})
    assert keys.accept_signers == frozenset({"kms"})
    keys = KeyRegistry.from_env({"REQUISITION_KEYS_FILE": str(path), "REQUISITION_ACCEPT_SIGNERS": "dev,kms"})
    assert keys.accept_signers == frozenset({"dev", "kms"})
    keys = KeyRegistry.from_env({"REQUISITION_KEYS_FILE": str(path), "REQUISITION_ACCEPT_SIGNERS": "any"})
    assert keys.accept_signers is None
    with pytest.raises(Exception):
        KeyRegistry.from_env({"REQUISITION_KEYS_FILE": str(path), "REQUISITION_ACCEPT_SIGNERS": ""})


def test_pq_is_not_expected_from_an_ml_dsa_key_that_was_not_usable_at_the_signed_instant(tmp_path, clock):
    s = server(clock, "signed")
    try:
        registry = copy.deepcopy(s.registry)
        ml = next(e for e in registry["entries"] if e["algorithm"] == "mldsa87")
        ml.update(status="retired", valid_to="2026-11-01T00:00:00Z")  # retired before the records below were signed
        keys = KeyRegistry.from_bytes(json.dumps(registry).encode())
        envelope = {"key_id": KEY_ID, "signed_payload": json.dumps({"occurred_at": "2026-11-09T12:00:00Z"})}
        assert keys.pq_expected(envelope) is False
        early = {"key_id": KEY_ID, "signed_payload": json.dumps({"occurred_at": "2026-10-01T00:00:00Z"})}
        assert keys.pq_expected(early) is True  # while that key was usable it was expected
    finally:
        s.stop()


def test_pq_is_expected_only_of_an_ml_dsa_87_key_of_the_same_signer(tmp_path, clock):
    s = server(clock, "signed")
    try:
        registry = copy.deepcopy(s.registry)
        next(e for e in registry["entries"] if e["algorithm"] == "mldsa87")["signer"] = "kms"  # the ed25519 key is "dev"
        keys = KeyRegistry.from_bytes(json.dumps(registry).encode())
        envelope = {"key_id": KEY_ID, "signed_payload": json.dumps({"occurred_at": "2026-11-09T12:00:00Z"})}
        assert keys.pq_expected(envelope) is False
    finally:
        s.stop()


def test_a_decision_signed_by_a_key_retired_after_the_statement_is_refused_with_the_reason(tmp_path, fake, client, clock):
    path = tmp_path / "keys.json"
    write(path, fake.registry)
    keys = KeyRegistry.from_file(str(path), max_age_seconds=300, clock=Wall())
    gate = Gate(client, Store(str(tmp_path / "s.json"), clock=clock), approval_base_url="http://x", keys=keys, clock=clock)
    args = arguments_object("refund-agent", "s-1", ACT_TYPE, refund_args())
    sanction = gate.file_or_find(ACT_TYPE, args)
    fake.approve(sanction.request_id)
    sanction = gate.read(sanction, args)
    retired = copy.deepcopy(fake.registry)
    retired["entries"][0].update(status="retired", valid_to="2026-11-09T11:00:00Z", status_changed_at="2026-11-09T11:00:00Z")
    write(path, retired)
    with pytest.raises(RecordInvalid, match=r"decision signature does not verify.*key_not_valid_at_signing"):
        gate.execute(sanction, args, "nonce-late")


# --- an empty accepted-signers set is a configuration error, never "any" --------------------------------


def test_an_empty_accepted_signers_set_is_refused_everywhere(tmp_path, fake):
    from requisition_aws.keys import KeyError_, key_standing
    entry = {"status": "active", "valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "signer": "kms"}
    with pytest.raises(ValueError, match="empty"):
        key_standing(entry, "2026-11-09T12:00:00Z", frozenset())
    with pytest.raises(KeyError_, match="empty"):
        KeyRegistry.from_bytes(json.dumps(fake.registry).encode(), accept_signers=[])
    with pytest.raises(KeyError_):
        KeyRegistry({}, accept_signers=())
