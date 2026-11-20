# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Every environment setting that switches or loosens a control accepts a closed set of spellings. Any other value
refuses to start, naming the variable; it never falls back to the weaker setting. Unset keeps the safe default.

The bad spellings are GENERATED (case variants of the usual words, every kind of padding, numbers, digits of other
scripts, non-finite numbers, random text), not picked by hand, and each one goes through the real entry points:
``interceptor.from_env``, ``mcp_target.from_env``, the Lambda handler, the deployed Lambda entry and
``demo/rehearse.sh``."""

import hashlib
import importlib.util
import json
import os
import pathlib
import random
import string
import subprocess

import pytest

from requisition_aws import interceptor as icp
from requisition_aws import mcp_target

from .test_gate_rules import env_for

ROOT = pathlib.Path(__file__).resolve().parent.parent
RNG_SEED = 20261120

# --- the generators -------------------------------------------------------------------------------------------

WORDS = ("true", "false", "yes", "no", "on", "off", "y", "n", "t", "f", "enable", "enabled", "disable", "disabled",
         "required", "require", "none", "null", "nil", "ok", "set", "unset", "default", "strict", "pq", "any")
SPACES = (" ", "  ", "\t", "\n", "\r", "\r\n", "\v", "\f", "\u00a0", "\u2003", "\u3000", "\u200b", "\ufeff")
OTHER_DIGITS_ALL = ("\uff15", "\u0665", "\u096b", "\uff10", "\u0660", "\u0966")  # fullwidth, Arabic-Indic, Devanagari
OTHER_DIGITS = {"0": ("\uff10", "\u0660", "\u0966", "\u2070", "\u2080", "\U0001d7ce"),  # fullwidth, Arabic-Indic, ...
                "1": ("\uff11", "\u0661", "\u0967", "\u00b9", "\u2081", "\U0001d7cf")}


def case_variants(word):
    alternating = "".join(c.upper() if i % 2 else c for i, c in enumerate(word))
    return {word, word.upper(), word.capitalize(), alternating, alternating.swapcase()}


def padded(value):
    for space in SPACES:
        yield space + value
        yield value + space
        yield space + value + space


def random_text(rng, alphabet, count, low=1, high=12):
    return {"".join(rng.choice(alphabet) for _ in range(rng.randint(low, high))) for _ in range(count)}


def bad_flags():
    """Spellings a 1/0 switch must refuse: everything here but exactly "1" and "0"."""
    rng = random.Random(RNG_SEED)
    out = {""}
    for word in WORDS:
        out |= case_variants(word)
    for value in ("1", "0"):
        out |= set(padded(value))
        out |= set(OTHER_DIGITS[value])
        out |= {"+" + value, "-" + value, "0" + value, value + "0", value + value, value + ".0", value + "e0",
                "0x" + value, "0b" + value, value + "_0", '"' + value + '"', "'" + value + "'", value + ";", value + "#"}
    out |= {"2", "3", "9", "-0", "00", "10", "11", "01", "1.5", "0.1", "1e1", "100", "-100", "NaN", "inf", "1,0"}
    out |= {str(rng.randint(2, 10**9)) for _ in range(32)}
    out |= random_text(rng, string.ascii_letters + string.punctuation + " ", 96)
    assert not out & {"1", "0"}
    return sorted(out)


def bad_seconds():
    """Spellings a positive number of seconds must refuse (accepted: decimal digits, optionally a dot and more digits,
    whose value is above zero and at most one day, 86400)."""
    rng = random.Random(RNG_SEED + 1)
    out = {"", "0", "00", "0.0", "000.000", "-0", "-1", "-5", "-0.5", "+5", "+0.5", ".5", "5.", "5..0", "5.0.0",
           "nan", "NaN", "NAN", "-nan", "inf", "Inf", "INF", "-inf", "+inf", "infinity", "Infinity", "-Infinity",
           "1e400", "1E3", "5e0", "5e-1", "0x10", "0o10", "0b10", "3_00", "1,5", "5s", "300ms", "1m", "5 0",
           "9" * 400, "9" * 400 + ".0",  # digits only, but their value is not finite
           "86400.5", "86401", "100000", "1" + "0" * 300, "604800", "31536000"}  # above one day
    for value in ("5", "60", "300", "0.5"):
        out |= set(padded(value))
        out |= {value.replace(ascii_digit, other) for ascii_digit in "0356" for other in OTHER_DIGITS_ALL
                if ascii_digit in value}
    for word in WORDS + ("forever", "never", "max", "unlimited"):
        out |= case_variants(word)
    out |= {"-" + str(rng.randint(1, 10**6)) for _ in range(16)}
    out |= {str(rng.randint(86401, 10**12)) for _ in range(16)}
    out |= random_text(rng, string.ascii_letters + string.punctuation + " ", 64)
    assert not [v for v in out if seconds_oracle(v)], "the generator made an accepted value"
    return sorted(out)


def seconds_oracle(value):
    """The test's own statement of an accepted number of seconds (written apart from settings.py)."""
    if not value or not set(value) <= set("0123456789.") or value.count(".") > 1 or value[0] == "." or value[-1] == ".":
        return False
    return 0 < float(value) <= 86400


TCHAR = set(string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~")


def bad_header_names():
    """Header names a header setting must refuse when it is set: empty, or any character outside an RFC 9110
    token."""
    rng = random.Random(RNG_SEED + 2)
    out = {"", "X Caller", "X:Caller", "X-Caller,Y", "X-Caller;", "(x)", "x/y", "x@y", "x=y", "x[y]", "x{y}", "x\\y",
           "x?y", 'x"y', "\u00dcber", "x\u00e9", "x\u200by"}
    out |= set(padded("X-Requisition-Caller"))
    bad = string.punctuation.translate({ord(c): None for c in TCHAR}) + " \t"
    out |= {head + rng.choice(bad) + tail for head, tail in
            zip(random_text(rng, sorted(TCHAR), 48, 0, 6), random_text(rng, sorted(TCHAR), 48, 0, 6))}
    assert all(not v or set(v) - TCHAR for v in out)
    return sorted(out)


def duplicate_tool_maps(tools):
    """A tool map with a member named twice (JSON that Python's json module reads, keeping the last value)."""
    (name, act), = tools.items()
    return [f'{{"{name}": "{act}", "{name}": "{act}"}}', f'{{"{name}": "other.type", "{name}": "{act}"}}',
            f'{{"{name}": "{act}", "{name}": "other.type"}}', f'{{"{name}": {{"act_type": "{act}"}}, "{name}": "{act}"}}']


# --- the entry points -----------------------------------------------------------------------------------------


def interceptor_env(fake, tmp_path, **over):
    return env_for(fake, tmp_path, **over)


def target_env(fake, tmp_path, **over):
    return env_for(fake, tmp_path, **{"REQUISITION_TOOLS": None, "REQUISITION_LEDGER": str(tmp_path / "ledger.jsonl"), **over})


BUILDERS = {"interceptor": (interceptor_env, lambda env: icp.from_env(env)),
            "mcp_target": (target_env, lambda env: mcp_target.from_env(env))}


def accepted(build, env):
    """The error the entry point refused to start with, or "STARTED"."""
    try:
        build(env)
    except Exception as error:  # noqa: BLE001 - any refusal; the caller checks that it names the variable
        return error
    return "STARTED"


def assert_every_value_refused(fake, tmp_path, entry, name, values, extra=None):
    make, build = BUILDERS[entry]
    started, wrong = [], []
    for value in values:
        result = accepted(build, make(fake, tmp_path, **{name: value}, **(extra or {})))
        if result == "STARTED":
            started.append(value)
        elif not str(result).startswith(name + " "):
            wrong.append((value, str(result)[:120]))
    assert started == [], f"{entry} STARTED with {name} set to {len(started)} unaccepted values: {started[:12]!r}"
    assert wrong == [], f"{entry} refused for another reason than {name}: {wrong[:6]!r}"


FLAGS = ("REQUISITION_REQUIRE_PQ", "REQUISITION_ALLOW_CLASSICAL_ONLY", "REQUISITION_ALLOW_PLAINTEXT_PRIVATE")
SECONDS = {"interceptor": ("REQUISITION_TIMEOUT", "REQUISITION_KEYS_MAX_AGE_SECONDS", "REQUISITION_CRED_REREAD_SECONDS"),
           "mcp_target": ("REQUISITION_TIMEOUT", "REQUISITION_KEYS_MAX_AGE_SECONDS")}
HEADERS = ("REQUISITION_CALLER_HEADER", "REQUISITION_SESSION_HEADER")


@pytest.mark.parametrize("entry", sorted(BUILDERS))
@pytest.mark.parametrize("name", FLAGS)
def test_a_switch_refuses_to_start_on_any_value_but_1_or_0(fake, tmp_path, entry, name):
    assert_every_value_refused(fake, tmp_path, entry, name, bad_flags())


@pytest.mark.parametrize("entry", sorted(BUILDERS))
def test_require_pq_true_or_empty_never_turns_the_requirement_off(fake, tmp_path, entry):
    # the finding: "true", "yes", "on", "TRUE", " 1" and "" read as "not 1", so post-quantum was silently off
    make, build = BUILDERS[entry]
    for value in ("true", "yes", "on", "TRUE", " 1", ""):
        result = accepted(build, make(fake, tmp_path, REQUISITION_REQUIRE_PQ=value))
        assert isinstance(result, Exception) and str(result).startswith("REQUISITION_REQUIRE_PQ "), (value, result)


@pytest.mark.parametrize("entry", sorted(BUILDERS))
def test_the_switches_accept_1_and_0_and_default_to_the_safe_setting(fake, tmp_path, entry):
    make, build = BUILDERS[entry]
    def gate(**over):
        built = build(make(fake, tmp_path, **over))
        return (built if entry == "interceptor" else built[0]).gate

    assert gate().require_pq is True and gate().allow_classical_only is False
    assert gate(REQUISITION_REQUIRE_PQ="1").require_pq is True
    assert gate(REQUISITION_REQUIRE_PQ="0").require_pq is False
    assert gate(REQUISITION_ALLOW_CLASSICAL_ONLY="1").allow_classical_only is True
    assert gate(REQUISITION_ALLOW_CLASSICAL_ONLY="0").allow_classical_only is False
    url = "http://10.1.2.3:4000"
    assert gate(REQUISITION_URL=url, REQUISITION_ALLOW_PLAINTEXT_PRIVATE="1").client.allow_plaintext_private is True
    for over in ({}, {"REQUISITION_ALLOW_PLAINTEXT_PRIVATE": "0"}):
        with pytest.raises(ValueError, match="https"):
            build(make(fake, tmp_path, REQUISITION_URL=url, **over))


@pytest.mark.parametrize("entry, name", [(e, n) for e, names in sorted(SECONDS.items()) for n in names])
def test_a_number_of_seconds_refuses_to_start_unless_it_is_a_finite_positive_decimal(fake, tmp_path, entry, name):
    assert_every_value_refused(fake, tmp_path, entry, name, bad_seconds())


def test_the_numbers_of_seconds_accept_plain_decimals_and_keep_their_defaults(fake, tmp_path):
    it = icp.from_env(interceptor_env(fake, tmp_path))
    assert (it.gate.client.timeout, it.gate.keys._source.max_age, it.reread_interval) == (5.0, 300.0, 60.0)
    it = icp.from_env(interceptor_env(fake, tmp_path, REQUISITION_TIMEOUT="0.5", REQUISITION_KEYS_MAX_AGE_SECONDS="30",
                                      REQUISITION_CRED_REREAD_SECONDS="05"))
    assert (it.gate.client.timeout, it.gate.keys._source.max_age, it.reread_interval) == (0.5, 30.0, 5.0)
    target, _ = mcp_target.from_env(target_env(fake, tmp_path, REQUISITION_TIMEOUT="7", REQUISITION_KEYS_MAX_AGE_SECONDS="9"))
    assert (target.gate.client.timeout, target.gate.keys._source.max_age) == (7.0, 9.0)
    it = icp.from_env(interceptor_env(fake, tmp_path, REQUISITION_KEYS_MAX_AGE_SECONDS="86400"))
    assert it.gate.keys._source.max_age == 86400.0  # one day: the largest accepted


@pytest.mark.parametrize("name", HEADERS)
def test_a_header_setting_that_is_set_must_be_a_header_name(fake, tmp_path, name):
    assert_every_value_refused(fake, tmp_path, "mcp_target", name, bad_header_names())


def test_the_header_settings_accept_a_header_name_and_stay_off_when_unset(fake, tmp_path):
    target, _ = mcp_target.from_env(target_env(fake, tmp_path))
    assert (target.caller_header, target.session_header) == (None, None)
    target, _ = mcp_target.from_env(target_env(fake, tmp_path, REQUISITION_CALLER_HEADER="X-Requisition-Caller",
                                               REQUISITION_SESSION_HEADER="x-amzn-session_1"))
    assert (target.caller_header, target.session_header) == ("x-requisition-caller", "x-amzn-session_1")


@pytest.mark.parametrize("entry", sorted(BUILDERS))
def test_a_tool_map_naming_a_tool_twice_refuses_to_start(fake, tmp_path, entry):
    tools = {"refunds___payments_refund_send": "payments.refund_send"} if entry == "interceptor" \
        else {"payments_refund_send": "payments.refund_send"}
    values = duplicate_tool_maps(tools) + ['{"a": NaN}', '{"a": Infinity}', "\ufeff" + json.dumps(tools)]
    values += ["[]", "[" + json.dumps(tools) + "]", '"x"', "1", "0", "true", "false", "null", '""', "", "{"]  # not an object
    assert_every_value_refused(fake, tmp_path, entry, "REQUISITION_TOOLS", values)


def bad_caller_sources():
    rng = random.Random(RNG_SEED + 3)
    out = {""}
    for word in ("legacy_session", "sigv4", "jwt"):
        out |= case_variants(word)
        out |= set(padded(word))
        out |= {word.replace("_", "-"), word + ",", word + "s"}
    out |= {"iam", "aws_iam", "clientInfo", "none", "any", "session", "bearer"}
    out |= random_text(rng, string.ascii_letters + "_-", 32)
    return sorted(out - {"legacy_session", "sigv4", "jwt"})


def test_the_caller_source_refuses_to_start_on_any_value_but_its_three_words(fake, tmp_path):
    assert_every_value_refused(fake, tmp_path, "interceptor", "REQUISITION_CALLER_SOURCE", bad_caller_sources())


def test_the_lambda_handler_refuses_every_call_on_an_unaccepted_switch(fake, tmp_path, monkeypatch):
    from .test_interceptor import body_of, event

    for value in ("true", " 1", ""):
        for k, v in interceptor_env(fake, tmp_path, REQUISITION_REQUIRE_PQ=value).items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(icp, "_INTERCEPTOR", None)
        body = body_of(icp.lambda_handler(event("request_tools_call_refund.json"), None))
        assert "error" in body, (value, "the call was handled, not refused", body)
        assert body["error"]["code"] == icp.FAIL_CLOSED and "misconfigured" in body["error"]["message"], value
        assert fake.requests == {}


def bad_hosts():
    """MCP_HOST values the target must refuse: empty, padded, a URL, a port, a wildcard, characters outside a host name
    or an IP literal."""
    rng = random.Random(RNG_SEED + 5)
    out = {"", "*", "localhost:8000", "127.0.0.1:8000", "http://127.0.0.1", "[::1]", "a b", "-host", "host-", "a..b",
           ".host", "host.", "h\u00f6st", "host_name", "0.0.0.0/0", "localhost,0.0.0.0", "a" * 64, "::1::"}
    for host in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
        out |= set(padded(host))
    out |= {"x" + rng.choice("!\"#$%&'()*+,/;<=>?@[\\]^`{|}~ ") + "y" for _ in range(24)}
    return sorted(out)


def test_the_target_host_refuses_to_start_unless_it_is_a_host_name_or_an_ip_literal(fake, tmp_path):
    started, wrong = [], []
    for value in bad_hosts():
        try:
            _, opts = mcp_target.from_env(target_env(fake, tmp_path, MCP_HOST=value))
            started.append((value, opts["host"]))
        except Exception as error:  # noqa: BLE001 - any refusal; it must name the variable
            if not str(error).startswith("MCP_HOST "):
                wrong.append((value, str(error)[:100]))
    assert started == [], f"the target took MCP_HOST values it should refuse: {started[:12]!r}"
    assert wrong == []


def test_the_target_host_takes_names_and_ip_literals_and_stays_on_loopback_when_unset(fake, tmp_path):
    _, opts = mcp_target.from_env(target_env(fake, tmp_path))
    assert opts["host"] == "127.0.0.1"
    for host in ("0.0.0.0", "127.0.0.1", "::1", "::", "localhost", "target.example", "10.1.2.3"):
        _, opts = mcp_target.from_env(target_env(fake, tmp_path, MCP_HOST=host))
        assert opts["host"] == host


def test_the_lambda_handler_log_names_the_refused_variable_and_never_its_value(fake, tmp_path, monkeypatch, caplog):
    for name, value in (("REQUISITION_REQUIRE_PQ", "TRUE-sekret-1"), ("REQUISITION_TIMEOUT", "sekret-2"),
                        ("REQUISITION_TOOLS", '{"sekret-3": 1, "sekret-3": 2}')):
        for k, v in interceptor_env(fake, tmp_path, **{name: value}).items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(icp, "_INTERCEPTOR", None)
        caplog.clear()
        with caplog.at_level("ERROR"):
            icp.lambda_handler({}, None)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert name + " must be" in text, (name, text)
        assert "sekret" not in text, text
        monkeypatch.delenv(name)


# --- the deployed Lambda entry: the pinned principal is required -------------------------------------------------

ENTRY = ROOT / "deploy" / "lambda" / "interceptor_entry.py"
PRINCIPAL = "rqp_" + "0" * 32


def load_entry(tmp_path, monkeypatch, principal_expected):
    spec = importlib.util.spec_from_file_location("interceptor_entry_settings_under_test", ENTRY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    keys = tmp_path / "lab-keys.json"
    keys.write_bytes(b'{"entries": []}')
    monkeypatch.setenv("REQUISITION_KEYS_FILE", str(keys))
    monkeypatch.setenv("REQUISITION_KEYS_SHA256", hashlib.sha256(keys.read_bytes()).hexdigest())
    monkeypatch.setenv("REQUISITION_SECRET_ARN", "arn:aws:secretsmanager:us-east-2:000000000000:secret:fixture")
    if principal_expected is None:
        monkeypatch.delenv("REQUISITION_PRINCIPAL_EXPECTED", raising=False)
    else:
        monkeypatch.setenv("REQUISITION_PRINCIPAL_EXPECTED", principal_expected)
    monkeypatch.delenv("REQUISITION_CRED", raising=False)

    reads = []

    class Secrets:
        def get_secret_value(self, SecretId):  # noqa: N803 - boto3's name
            reads.append(SecretId)
            return {"SecretString": json.dumps({"credential": "rqc_x", "principal": "rqp_" + "1" * 32})}

    monkeypatch.setattr(mod, "_secrets_client", lambda: Secrets())
    reached = []
    monkeypatch.setattr(mod._interceptor, "lambda_handler", lambda *a, **k: reached.append(1) or {"ok": True})
    mod._reads = reads
    return mod, reached


def bad_principals():
    """Pinned principals the entry must refuse: anything but rqp_ and 32 lower-case hex digits."""
    rng = random.Random(RNG_SEED + 4)
    good = "rqp_" + "1" * 32
    out = {None, "", "rqp_", "rqp", good.upper(), "RQP_" + "1" * 32, "rqp_" + "A" * 32, "rqp_" + "1" * 31,
           "rqp_" + "1" * 33, "rqp-" + "1" * 32, "rqcl_" + "1" * 32, "rqc_" + "1" * 32, "1" * 32, good + ",", good + ";"}
    out |= set(padded("")) | set(padded(good))
    out |= {"rqp_" + "".join(rng.choice("0123456789abcdefg") for _ in range(32)) for _ in range(8)} - {None}
    out |= random_text(rng, string.ascii_letters + string.digits + "_-", 16)
    oracle = lambda v: isinstance(v, str) and len(v) == 36 and v.startswith("rqp_") and set(v[4:]) <= set("0123456789abcdef")  # noqa: E731
    return sorted((v for v in out if not oracle(v)), key=repr)


@pytest.mark.parametrize("value", bad_principals())
def test_the_lambda_entry_refuses_without_a_pinned_principal(tmp_path, monkeypatch, value):
    # unset or blank, the pin used to be skipped and any principal the secret named was taken; now anything but a
    # principal id (rqp_ and 32 lower-case hex digits) refuses before the secret is read
    mod, reached = load_entry(tmp_path, monkeypatch, value)
    out = mod.handler({"mcp": {"gatewayRequest": {"body": {"id": 5}}}}, None)
    assert reached == [], "the request reached the interceptor with no pinned principal"
    assert out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == icp.FAIL_CLOSED
    assert "REQUISITION_CRED" not in os.environ
    assert mod._reads == [], "the secret was read before the missing pin refused"


def test_the_lambda_entry_log_names_the_pin_and_never_its_value(tmp_path, monkeypatch, caplog):
    mod, _ = load_entry(tmp_path, monkeypatch, "rqp_SEKRET")
    with caplog.at_level("ERROR"):
        mod.handler({"mcp": {"gatewayRequest": {"body": {"id": 6}}}}, None)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "REQUISITION_PRINCIPAL_EXPECTED must be" in text and "SEKRET" not in text, text


# --- demo/rehearse.sh: its switches take 1 or 0 ----------------------------------------------------------------


def rehearse(tmp_path, **over):
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "REQUISITION_DEMO_DIR": str(tmp_path),
           "REQUISITION_SEED": str(tmp_path / "seed.json"), "REQUISITION_URL": "http://127.0.0.1:9",
           "REQUISITION_CRED": "rqc_x", "REQUISITION_PRINCIPAL": PRINCIPAL,
           "REQUISITION_LAB_KEY_FILE": str(tmp_path / "keys.json"), "OUT": str(tmp_path / "out"),
           "STEPS": "9"}  # an unknown step: nothing runs, the summary says FAIL (exit 1) once the knobs are read
    env.update(over)
    return subprocess.run(["bash", str(ROOT / "demo" / "rehearse.sh")], env=env, capture_output=True, text=True,
                          timeout=30)


@pytest.mark.parametrize("name", ("REQUIRE_PQ", "REHEARSE_DRY"))
def test_rehearse_refuses_a_switch_that_is_not_1_or_0(tmp_path, name):
    started = []
    for value in bad_flags():
        if "\x00" in value:
            continue
        run = rehearse(tmp_path, **{name: value})
        if run.returncode != 2 or name not in run.stderr:
            started.append((value, run.returncode))
    assert started == [], f"rehearse.sh ran with {name} set to {len(started)} unaccepted values: {started[:12]!r}"


def test_rehearse_takes_1_and_0_and_reads_require_pq_as_on_when_unset(tmp_path):
    for over in ({}, {"REQUIRE_PQ": "1"}, {"REQUIRE_PQ": "0"}, {"REHEARSE_DRY": "0"}):
        run = rehearse(tmp_path, **over)
        assert run.returncode == 1 and "unknown step 9" in run.stdout, (over, run.stdout, run.stderr)
