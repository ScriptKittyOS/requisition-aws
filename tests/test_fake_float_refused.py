# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The fake answers a float argument as Requisition's execute API is specified to: 400 ``float_refused``, at propose
(in ``display``) and at execute (in ``display_projection``), from the JSON text it receives (``1.0`` is a float
there). Its check is its own: it does not call the code under test."""

import datetime as dt
import json

from requisition_aws import canonical

from .fake_requisition import FakeRequisition
from .test_canonical import GOOD, SEED_SCHEMA

ACT_TYPE = "payments.refund_send"
NOW = dt.datetime(2026, 11, 9, 12, 0, 0, tzinfo=dt.timezone.utc)


def _fake():
    return FakeRequisition(act_types={ACT_TYPE: canonical.ArgsSchema(SEED_SCHEMA)}, now=lambda: NOW)


def _post(fake, path, text):
    return fake.dispatch("POST", path, {"authorization": "Bearer " + fake.credential}, text.encode())


def _propose_text(fake, display_text):
    head = json.dumps({"principal": fake.principal, "act_type": ACT_TYPE, "act_hash": "0" * 96,
                       "act_hash_alg": canonical.ACT_HASH_ALG})
    return head[:-1] + ',"display":' + display_text + "}"


def _execute_text(fake, projection_text):
    head = json.dumps({"principal": fake.principal, "act_type": ACT_TYPE, "act_hash": "0" * 96,
                       "act_hash_alg": canonical.ACT_HASH_ALG, "statement_id": "5" * 64, "nonce": "n" * 32,
                       "not_after": "2026-11-09T12:02:00Z"})
    return head[:-1] + ',"display_projection":' + projection_text + "}"


def _display(amount_lexeme):
    return json.dumps(GOOD).replace('"amount_minor": 1250', '"amount_minor": ' + amount_lexeme)


def test_propose_with_a_float_argument_is_float_refused():
    fake = _fake()
    for lexeme in ("1250.0", "12.5", "1.25e3", "-0.0"):
        status, body, _ = _post(fake, "/v1/sanction-requests", _propose_text(fake, _display(lexeme)))
        assert (status, body) == (400, {"error": "float_refused"}), lexeme
    assert fake.requests == {}


def test_execute_with_a_float_argument_is_float_refused_and_claims_nothing():
    fake = _fake()
    for lexeme in ("1250.0", "1.25e3"):
        status, body, _ = _post(fake, "/v1/execute", _execute_text(fake, _display(lexeme)))
        assert (status, body) == (400, {"error": "float_refused"}), lexeme
    assert fake.claims == {} and fake.spent == set()


def test_the_fake_still_answers_every_other_malformed_member_as_before():
    fake = _fake()
    status, body, _ = _post(fake, "/v1/sanction-requests", _propose_text(fake, _display('"1250"')))
    assert (status, body) == (400, {"error": "malformed_member"})
    status, body, _ = _post(fake, "/v1/sanction-requests", _propose_text(fake, _display("1250")))
    assert (status, body) == (400, {"error": "act_hash_derived_mismatch"})  # an integer passes intake


class _AcceptsAnything:
    """An act type whose schema takes any arguments, so the answer below is the fake's own float check alone."""

    def validate(self, display):
        return None


def test_the_fake_refuses_a_float_itself_at_any_depth_whatever_the_act_types_schema():
    fake = FakeRequisition(act_types={ACT_TYPE: _AcceptsAnything()}, now=lambda: NOW)
    for display in ('{"a":1.0}', '{"a":{"b":[0,{"c":-0.0}]}}', '{"a":[1,2.5e3]}'):
        status, body, _ = _post(fake, "/v1/sanction-requests", _propose_text(fake, display))
        assert (status, body) == (400, {"error": "float_refused"}), display
        status, body, _ = _post(fake, "/v1/execute", _execute_text(fake, display))
        assert (status, body) == (400, {"error": "float_refused"}), display
    status, body, _ = _post(fake, "/v1/sanction-requests", _propose_text(fake, '{"a":[1,{"b":2}]}'))
    assert (status, body) == (400, {"error": "act_hash_derived_mismatch"})  # no float: past the check
    assert fake.requests == {} and fake.claims == {}
