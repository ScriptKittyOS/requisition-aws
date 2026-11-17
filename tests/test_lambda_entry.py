# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The deployed Lambda entry, now in this repo (deploy/lambda/interceptor_entry.py; the entry first
deployed was its source and read the caller secret ONCE per environment). On
``caller_credential_expired`` the interceptor re-reads the credential, so
the entry hands it a source that reads Secrets Manager AGAIN (the cache bypassed), checks the secret
still names the pinned principal, and replaces the cached credential. No AWS: a fake Secrets Manager.
"""

import hashlib
import importlib.util
import json
import pathlib

import pytest

from requisition_aws import interceptor as icp

ENTRY = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "lambda" / "interceptor_entry.py"
PRINCIPAL = "rqp_" + "0" * 32


class FakeSecrets:
    def __init__(self, credential, principal=PRINCIPAL):
        self.value = {"credential": credential, "principal": principal}
        self.calls = []

    def get_secret_value(self, SecretId):  # noqa: N803 - boto3's name
        self.calls.append(SecretId)
        return {"SecretString": json.dumps(self.value)}


@pytest.fixture
def entry(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("interceptor_entry_under_test", ENTRY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    keys = tmp_path / "lab-keys.json"
    keys.write_bytes(b'{"entries": []}')
    monkeypatch.setenv("REQUISITION_KEYS_FILE", str(keys))
    monkeypatch.setenv("REQUISITION_KEYS_SHA256", hashlib.sha256(keys.read_bytes()).hexdigest())
    monkeypatch.setenv("REQUISITION_SECRET_ARN", "arn:aws:secretsmanager:us-east-2:000000000000:secret:fixture")
    monkeypatch.setenv("REQUISITION_PRINCIPAL_EXPECTED", PRINCIPAL)
    monkeypatch.delenv("REQUISITION_CRED", raising=False)
    secrets = FakeSecrets("rqc_cached")
    monkeypatch.setattr(mod, "_secrets_client", lambda: secrets)
    seen = {}

    def fake_handler(event, context, credential_source=None):
        seen["source"] = credential_source
        return {"ok": True}

    monkeypatch.setattr(mod._interceptor, "lambda_handler", fake_handler)
    mod._test = {"secrets": secrets, "seen": seen}
    return mod


def test_the_secret_is_read_once_and_a_source_is_handed_to_the_interceptor(entry):
    import os

    assert entry.handler({}, None) == {"ok": True} and entry.handler({}, None) == {"ok": True}
    assert len(entry._test["secrets"].calls) == 1 and os.environ["REQUISITION_CRED"] == "rqc_cached"
    assert callable(entry._test["seen"]["source"])


def test_the_source_rereads_the_secret_and_replaces_the_cache(entry):
    import os

    entry.handler({}, None)
    entry._test["secrets"].value["credential"] = "rqc_reminted"
    assert entry._test["seen"]["source"]() == "rqc_reminted"
    assert len(entry._test["secrets"].calls) == 2 and os.environ["REQUISITION_CRED"] == "rqc_reminted"


@pytest.mark.parametrize("value", [{"credential": "rqc_x", "principal": "rqp_" + "1" * 32}, {"credential": "", "principal": PRINCIPAL},
                                   {"credential": "not-a-credential", "principal": PRINCIPAL}])
def test_a_reread_secret_that_is_not_this_callers_credential_refuses(entry, value):
    import os

    entry.handler({}, None)
    entry._test["secrets"].value = value
    with pytest.raises(Exception):
        entry._test["seen"]["source"]()
    assert os.environ["REQUISITION_CRED"] == "rqc_cached"


def test_the_entry_names_the_fail_closed_code(entry, monkeypatch):
    monkeypatch.setenv("REQUISITION_KEYS_SHA256", "0" * 64)  # the packed key file is not the pinned one
    out = entry.handler({"mcp": {"gatewayRequest": {"body": {"id": 3}}}}, None)
    body = out["mcp"]["transformedGatewayResponse"]["body"]
    assert body["id"] == 3 and body["error"]["code"] == icp.FAIL_CLOSED


def test_a_first_read_naming_another_principal_refuses(entry):
    # the pinned principal (REQUISITION_PRINCIPAL_EXPECTED) is checked on every read, the first included
    entry._test["secrets"].value = {"credential": "rqc_x", "principal": "rqp_" + "1" * 32}
    out = entry.handler({"mcp": {"gatewayRequest": {"body": {"id": 4}}}}, None)
    assert out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"] == icp.FAIL_CLOSED
    assert "source" not in entry._test["seen"]
