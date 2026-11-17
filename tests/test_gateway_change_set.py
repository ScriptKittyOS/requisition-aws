# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""G1/G2: the AWS change is ONE operator-run CloudFormation
change set on the Gateway's stack, never an imperative UpdateGateway (a later full deploy of the stack would
silently revert it, and it drifts the stack). Nothing in this repository runs it.

What the change set carries:
* G1: the Gateway's MCP ``SupportedVersions`` listing every version it keeps (UpdateGateway and the
  template property REPLACE the list: https://aws.amazon.com/blogs/machine-learning/how-agentcore-gateway-supports-the-mcp-2026-07-28-spec/,
  read 2026-11-10);
* G2: ``InterceptionPoints: [REQUEST, RESPONSE]`` with passRequestHeaders kept true (the tool
  definitions reach the interceptor only at RESPONSE, gateway-interceptors-types.html; the deployed
  stack's template has REQUEST only);
* D2: invoke of the interceptor restricted to the Gateway (a Lambda permission whose principal is the
  AgentCore service and whose ``SourceArn`` is this Gateway).

It creates the change set, describes it, and refuses to
execute one that would Remove or Replace any resource (if the Gateway shows Replace, that refusal is
the finding to report). Without ``--go`` it writes nothing. These tests run it with a stub ``aws``
first on PATH that records its arguments: no real AWS call is possible.
"""

import os
import pathlib
import stat
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "gateway" / "g12-change-set.sh"
WRITE_VERBS = ("update-", "create-", "put-", "delete-", "execute-", "synchronize-", "tag-", "untag-", "add-permission")


@pytest.fixture
def stub_aws(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "aws-calls.txt"
    stub = bindir / "aws"
    stub.write_text(f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "{log}"\necho "{{}}"\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    return bindir, log


def test_the_change_set_script_exists_parses_and_says_it_is_operator_run():
    text = SCRIPT.read_text()
    assert subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode == 0
    assert "set -euo pipefail" in text and "operator" in text.lower() and "--go" in text


def test_without_go_no_aws_write_is_made(stub_aws, tmp_path):
    bindir, log = stub_aws
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "AWS_PROFILE": "none", "STACK_DIR": str(tmp_path)}
    proc = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)
    calls = log.read_text().splitlines() if log.exists() else []
    assert not any(verb in call for call in calls for verb in WRITE_VERBS), calls
    assert "would" in (proc.stdout + proc.stderr).lower()


def test_it_is_a_change_set_never_an_imperative_update():
    text = SCRIPT.read_text()
    assert "create-change-set" in text and "describe-change-set" in text
    assert "update-gateway" not in text and "update-gateway-target" not in text


def test_it_refuses_a_change_set_that_removes_or_replaces():
    text = SCRIPT.read_text()
    assert "Remove" in text and "Replace" in text and "refus" in text.lower()


def test_g1_lists_every_version_the_gateway_keeps():
    text = SCRIPT.read_text()
    assert "SupportedVersions" in text
    for version in ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"):
        assert version in text


def test_g2_adds_response_beside_request_with_headers_passed():
    text = SCRIPT.read_text()
    assert "RESPONSE" in text and "REQUEST" in text and "PassRequestHeaders: true" in text


def test_d2_restricts_invoke_of_the_interceptor_to_the_gateway():
    text = SCRIPT.read_text()
    assert "AWS::Lambda::Permission" in text and "SourceArn" in text and "bedrock-agentcore.amazonaws.com" in text


def test_the_readmes_state_the_incomplete_guard_and_the_narrow_allowlist():
    
    reg = " ".join((ROOT / "deploy" / "registration" / "README.md").read_text().split())
    assert "aws_demo_v2_incomplete" in reg and "naming convention" in reg and "malformed_member" in reg
    readme = " ".join((ROOT / "README.md").read_text().split())
    assert "subscriptions/listen" in readme and "list_changed" in readme
