# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Known-answer and refusal tests for requisition_aws.canonical (CanonicalPayload v3 port).

Sources of the known answers (all read from the Requisition version of 2026-10-26, never computed by
this port):
  * canonical_payload_test.exs:67,79      the golden map's bytes (no float in our domain: the
                                          golden carries 2.5, so only its float-free half is used)
  * canonical_payload_test.exs:163,203    literals
  * canonical_payload_test.exs:207-212    the RFC 8785 Appendix B string, Jason's upper-case escape
  * canonical_payload_test.exs:175-189    the UTF-16 key order
  * test/support/fixtures/execute_api_lab/act_hash_v3/  vectors V1 and V2: never copied here (they are
                                          effector material); Requisition's own suite runs this package's
                                          act_hash over them (test/bin_scripts/requisition_aws_drift_test.exs).
"""

import hashlib
import json
import pathlib

import pytest

from requisition_aws import canonical
from requisition_aws.canonical import CanonicalRefusal, IntakeRefusal

# Requisition's bin/lab-verify and the verify_receipt.py it runs, committed byte for byte at the paths lab-verify
# expects (tests/fixtures/requisition/PROVENANCE.md); Requisition's suite checks they are still its own files.
REQ_TREE = pathlib.Path(__file__).resolve().parent / "fixtures" / "requisition"
SEED = pathlib.Path(__file__).resolve().parent / "fixtures" / "seed" / "aws_demo.v1.json"


# --- encoding ---------------------------------------------------------------------------------


def test_literals_known_answer():
    # canonical_payload_test.exs:163 and :203
    assert canonical.encode({"c": False, "a": None, "b": True}) == b'{"a":null,"b":true,"c":false}'
    assert canonical.encode({"literals": [None, True, False]}) == b'{"literals":[null,true,false]}'


def test_rfc8785_appendix_b_string_with_jasons_upper_case_escape():
    # canonical_payload_test.exs:207-212: Jason escapes U+000F as \u000F (upper-case), "/" is not
    # escaped, non-ASCII is raw UTF-8
    value = {"string": "€$\u000f\nA'B\"\\/"}
    expected = '{"string":"€$\\u000F\\nA\'B\\"\\\\/"}'.encode("utf-8")
    assert canonical.encode(value) == expected


def test_short_escapes_are_jasons():
    # deps/jason/lib/encode.ex:284-293: \b \t \n \f \r \" \\ short; other C0 as \u00XX upper hex
    assert canonical.encode("\b\t\n\f\r\"\\\x01\x1f\x7f") == b'"\\b\\t\\n\\f\\r\\"\\\\\\u0001\\u001F\x7f"'


def test_keys_sort_by_utf16_code_units():
    # canonical_payload_test.exs:175-189: the RFC 8785 3.2.3 sort
    euro, ctrl, smiley, o_d, dalet = "€", "\u0080", "\U0001f602", "ö", "דּ"
    value = {
        euro: 1, "\r": 1, "\n": 1, "1": 1, ctrl: 1, smiley: 1, o_d: 1, dalet: 1, "</script>": 1,
    }
    decoded = json.loads(canonical.encode(value), object_pairs_hook=lambda pairs: [k for k, _ in pairs])
    assert decoded == ["\n", "\r", "1", "</script>", ctrl, o_d, euro, smiley, dalet]


def test_integers_and_nesting():
    assert canonical.encode({"b": [1, -2, {"z": 0, "a": "x"}], "a": 9007199254740991}) == (
        b'{"a":9007199254740991,"b":[1,-2,{"a":"x","z":0}]}'
    )


@pytest.mark.parametrize("bad", [1.0, 0.5, {"a": 2.5}, [1e30]])
def test_floats_are_refused(bad):
    with pytest.raises(CanonicalRefusal):
        canonical.encode(bad)


@pytest.mark.parametrize("bad", [{1: "x"}, (1, 2), {"a": object()}, b"bytes", {"a": "\ud800"}])
def test_outside_the_domain_is_refused(bad):
    with pytest.raises(CanonicalRefusal):
        canonical.encode(bad)


# --- act_hash: the repo's own vectors, read in place --------------------------------------------


def _vectors():
    index = VECTORS / "vectors.json"
    if not index.exists():
        return []
    return json.loads(index.read_text())["vectors"]


def test_act_hash_puts_act_type_inside_and_refuses_a_member_named_act_type():
    args = {"agent": "a", "args": {"amount_minor": 1}}
    pre = canonical.preimage("payments.refund_send", args)
    assert pre == b'{"act_type":"payments.refund_send","agent":"a","args":{"amount_minor":1}}'
    assert canonical.act_hash("payments.refund_send", args) == hashlib.sha384(pre).hexdigest()
    # args_schema.ex:23-25 refuses a top-level act_type at registration; the port refuses it too
    with pytest.raises(CanonicalRefusal):
        canonical.act_hash("x", {"act_type": "y"})


def test_display_digest_is_sha256_of_the_arguments_without_act_type():
    # Effector.encode/2 (an argument row's stored bytes and display_digest)
    args = {"b": 1, "a": "x"}
    assert canonical.display_digest(args) == hashlib.sha256(b'{"a":"x","b":1}').hexdigest()


# --- intake ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, code",
    [
        ("line\nbreak", "forbidden_character"),  # Cc
        ("rtl‮override", "forbidden_character"),  # Cf
        ("zero​width", "forbidden_character"),  # Cf
        ("ls ", "forbidden_character"),  # Zl
        ("ps ", "forbidden_character"),  # Zp
        ("é", "string_not_nfc"),  # NFD
        ("disk-2 failed", "display_value_redactable"),  # sk- inside a word
        ("task-123", "display_value_redactable"),
        ("a secret", "display_value_redactable"),
        ("SECRET", "display_value_redactable"),
        ("Bearer abc.def", "display_value_redactable"),
        ("token=abc", "display_value_redactable"),
        ("password=hunter2", "display_value_redactable"),
        ("api_key: zzz", "display_value_redactable"),
        ("postgres://u:pw@host/db", "display_value_redactable"),
        ("ghp_abcdef", "display_value_redactable"),
        ("whsec_abc", "display_value_redactable"),
        ("AIzaABCDEFGHIJKLMNOPQRSTUV", "display_value_redactable"),
        ("cookie=abc", "display_value_redactable"),
    ],
)
def test_check_string_refusals(value, code):
    with pytest.raises(IntakeRefusal) as err:
        canonical.check_string(value)
    assert err.value.code == code


@pytest.mark.parametrize(
    "value",
    [
        "duplicate charge on order 4411",
        "acct-7781",
        "customer requested refund",
        "Résumé café",  # NFC non-ASCII
        "SecretStores.LocalFile",  # bare token glued to a dot: redaction.ex:220-223 keeps it
        "integrations/secret_stores/",
        "token refresh failed",  # redaction.ex:160-162 keeps prose
        "credential_isolation=server_side_only",  # redaction.ex:139-141
    ],
)
def test_check_string_accepts(value):
    canonical.check_string(value)


def test_redaction_replays_the_pipeline_not_a_simple_match():
    # "token=[REDACTED]" is already in redacted form: the redactor leaves it unchanged, so
    # Requisition would accept it; the port answers the same (would_redact compares, it does not
    # merely match)
    assert canonical.would_redact("token=[REDACTED]") is False
    assert canonical.would_redact("token=abc") is True


def test_configured_secret_values_are_refused_when_known():
    # redaction.ex:618-623: a configured env secret of at least 8 characters anywhere in a value
    assert canonical.would_redact("pay acct ZZZZZZZZ1", configured_secrets=["ZZZZZZZZ1"]) is True
    assert canonical.would_redact("pay acct ZZZZ", configured_secrets=["ZZZZ"]) is False


@pytest.mark.parametrize(
    "args, code",
    [
        ({"a": 1.5}, "float_refused"),
        ({"a": None}, "missing_member"),
        ({"a": 2**53}, "malformed_member"),
        ({"a": -(2**53)}, "malformed_member"),
        ({"members": []}, "member_out_of_schema"),
        ({"membership_digest": "x"}, "member_out_of_schema"),
        ({"cue_ready_digest": "x"}, "member_out_of_schema"),
        ({"emitter_mode": "live"}, "member_out_of_schema"),
        ({"act_type": "x"}, "member_out_of_schema"),
        ({"a": {"b": ["ok", "line\n"]}}, "forbidden_character"),
        ({"a": b"x"}, "malformed_member"),
    ],
)
def test_check_arguments_refusals(args, code):
    with pytest.raises(IntakeRefusal) as err:
        canonical.check_arguments(args)
    assert err.value.code == code


def test_check_arguments_refuses_a_non_object():
    with pytest.raises(IntakeRefusal):
        canonical.check_arguments(["a"])


# A float member, at any depth, is refused float_refused with its path, before any other check: the server's name for
# it, and the encoder's. The walk takes members in sorted order and list items in order, so the first float of that
# walk is the one named. The arguments value itself, when it is not an object, stays malformed_member.
@pytest.mark.parametrize(
    "args, path",
    [
        ({"a": 1.5}, "a"),
        ({"a": -0.0}, "a"),
        ({"a": 0.0}, "a"),
        ({"a": json.loads("1e5")}, "a"),  # an exponent decodes as a float in Python
        ({"a": float("nan")}, "a"),
        ({"a": float("inf")}, "a"),
        ({"a": float("-inf")}, "a"),
        ({"a": [1, 2.5]}, "a.1"),
        ({"a": {"b": [0, {"c": -1.25}]}}, "a.b.1.c"),
        ({"a": "x\u0000", "b": 1.5}, "b"),  # before forbidden_character at an earlier member
        ({"a": 2**53, "b": 1.5}, "b"),  # before the integer bound (malformed_member) at an earlier member
        ({"a": None, "b": 0.5}, "b"),  # before missing_member
        ({"a": b"x", "b": 0.5}, "b"),  # before malformed_member for another type
        ({"act_type": 1.5}, "act_type"),  # before member_out_of_schema for a reserved name
        ({"b": 1.5, "a": 2.5}, "a"),  # the first in sorted order
    ],
)
def test_check_arguments_refuses_a_float_member_float_refused_with_its_path(args, path):
    with pytest.raises(IntakeRefusal) as err:
        canonical.check_arguments(args)
    assert (err.value.code, err.value.path) == ("float_refused", path)


def test_check_arguments_names_a_float_read_from_json_text_float_refused():
    from requisition_aws.client import loads_strict

    for text in ('{"a":1.0}', '{"a":1e5}', '{"a":1E5}', '{"a":1e-7}', '{"a":-0.0}', '{"a":{"b":[0,0.5]}}'):
        with pytest.raises(IntakeRefusal) as err:
            canonical.check_arguments(loads_strict(text))
        assert err.value.code == "float_refused", text


def test_check_arguments_a_float_as_the_whole_arguments_value_stays_malformed_member():
    for value in (1.5, -0.0, float("nan")):
        with pytest.raises(IntakeRefusal) as err:
            canonical.check_arguments(value)
        assert (err.value.code, err.value.path) == ("malformed_member", ""), value


# --- the args schema (args_schema.ex), the subset the demo seed uses ---------------------------

SEED_SCHEMA = [
    {"path": "agent", "type": "s", "required": True, "min_length": 1, "max_length": 64},
    {"path": "session", "type": "s", "required": True, "min_length": 1, "max_length": 64},
    {"path": "tool", "type": "enum", "required": True, "values": ["payments.refund_send"]},
    {"path": "args", "type": "obj", "required": True},
    {"path": "args.amount_minor", "type": "i", "required": True, "min": 1, "max": 100000000},
    {"path": "args.currency", "type": "enum", "required": True, "values": ["USD", "EUR", "GBP"]},
    {"path": "args.account", "type": "s", "required": True, "min_length": 1, "max_length": 64},
    {"path": "args.reason", "type": "s", "required": True, "min_length": 1, "max_length": 200},
]

GOOD = {
    "agent": "refund-agent",
    "session": "s-1",
    "tool": "payments.refund_send",
    "args": {"amount_minor": 1250, "currency": "USD", "account": "acct-7781", "reason": "duplicate charge"},
}


def test_schema_accepts_the_demo_arguments():
    schema = canonical.ArgsSchema(SEED_SCHEMA)
    schema.validate(GOOD)


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda a: a["args"].update(amount_minor=0), "display_member_out_of_range"),
        (lambda a: a["args"].update(amount_minor=100000001), "display_member_out_of_range"),
        (lambda a: a["args"].update(amount_minor="10"), "malformed_member"),
        (lambda a: a["args"].update(currency="JPY"), "malformed_member"),
        (lambda a: a["args"].update(cc="someone"), "member_out_of_schema"),
        (lambda a: a["args"].pop("reason"), "missing_member"),
        (lambda a: a["args"].update(reason="x" * 201), "display_member_out_of_range"),
        (lambda a: a.update(tool="other.tool"), "malformed_member"),
        (lambda a: a.update(extra=1), "member_out_of_schema"),
        (lambda a: a["args"].update(account="sk-live"), "display_value_redactable"),
    ],
)
def test_schema_refusals_never_truncate(mutate, code):
    args = json.loads(json.dumps(GOOD))
    mutate(args)
    with pytest.raises(IntakeRefusal) as err:
        canonical.ArgsSchema(SEED_SCHEMA).validate(args)
    assert err.value.code == code


@pytest.mark.parametrize(
    "mutate, path",
    [
        (lambda a: a["args"].update(amount_minor=12.5), "args.amount_minor"),
        (lambda a: a["args"].update(amount_minor=-0.0), "args.amount_minor"),
        (lambda a: a["args"].update(amount_minor=1250.0), "args.amount_minor"),
        (lambda a: a["args"].update(account=1.5), "args.account"),  # a float where a string is declared
        (lambda a: a.update(tool=1.0), "tool"),  # where an enum is declared
        (lambda a: a["args"].update(cc=0.5), "args.cc"),  # before member_out_of_schema
        (lambda a: (a["args"].update(currency="JPY"), a["args"].update(reason=2.5)), "args.reason"),  # before the enum
    ],
)
def test_schema_refuses_a_float_member_float_refused_with_its_path(mutate, path):
    args = json.loads(json.dumps(GOOD))
    mutate(args)
    with pytest.raises(IntakeRefusal) as err:
        canonical.ArgsSchema(SEED_SCHEMA).validate(args)
    assert (err.value.code, err.value.path) == ("float_refused", path)


def test_schema_a_float_as_the_whole_arguments_value_stays_malformed_member():
    with pytest.raises(IntakeRefusal) as err:
        canonical.ArgsSchema(SEED_SCHEMA).validate(1.5)
    assert (err.value.code, err.value.path) == ("malformed_member", "")


def test_schema_with_an_unported_facet_is_refused_at_construction():
    with pytest.raises(ValueError):
        canonical.ArgsSchema([{"path": "n", "type": "i", "required": True, "length_of": "xs"}])


def test_seed_file_schema_matches_the_test_copy():
    rows = json.loads(SEED.read_text())["act_types"]
    assert rows[0]["registration"]["display_schema"] == SEED_SCHEMA
