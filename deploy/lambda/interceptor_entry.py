# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Lambda entry point for the Requisition AgentCore Gateway REQUEST interceptor.

It is tested and versioned with the interceptor.

**What it does.**
- On the first invocation of an execution environment, it loads the /v1 caller (credential and principal) from
  Secrets Manager and puts them into this process's environment.
- It hands every event to ``requisition_aws.interceptor.lambda_handler``. That handler reads the rest of its
  configuration from the function's environment (the stack template's ``InterceptorFunction``).
- It also passes a credential source (:func:`_reread_credential`). When Requisition refuses the cached credential with
  ``caller_credential_expired``, the interceptor calls the source once.
  - The source reads Secrets Manager AGAIN, bypassing the cache.
  - It checks that the secret still names the pinned principal.
  - It replaces the cached credential.
  - The interceptor then retries that invocation exactly once, and allows at most one re-read per
    ``REQUISITION_CRED_REREAD_SECONDS`` per environment (default 60).

**Fail closed.**
- While the secret is unreadable, unminted (the stack's empty placeholder) or malformed, every request gets a JSON-RPC
  error naming no secret (``FAIL_CLOSED``), and the next invocation tries again.
- A re-read that fails, or that returns a credential which is not this caller's, refuses the call.
- The credential is never logged.

**Environment** (set by the stack template): ``REQUISITION_SECRET_ARN``, plus the interceptor's own variables:
``REQUISITION_URL``, ``REQUISITION_GATEWAY_ID``, ``REQUISITION_TOOLS``, ``REQUISITION_SEED``, ``REQUISITION_STORE``,
``REQUISITION_AGENT``, ``REQUISITION_APPROVAL_BASE``, ``REQUISITION_TIMEOUT``, ``REQUISITION_KEYS_FILE``,
``REQUISITION_KEYS_SHA256``, ``REQUISITION_PRINCIPAL_EXPECTED``, ``REQUISITION_REQUIRE_PQ``,
``REQUISITION_ALLOW_PLAINTEXT_PRIVATE``, and optionally ``REQUISITION_CRED_REREAD_SECONDS``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

from requisition_aws import interceptor as _interceptor

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

_CALLER_LOADED = False


def _secrets_client():  # separated so the local test can replace it
    import boto3  # provided by the Lambda Python runtime
    from botocore.config import Config

    return boto3.client("secretsmanager", config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2}))


def _check_keys_pin() -> None:
    """The packed key file must be the one the stack names (REQUISITION_KEYS_SHA256): zip and config agree."""
    want = os.environ.get("REQUISITION_KEYS_SHA256", "")
    with open(os.environ["REQUISITION_KEYS_FILE"], "rb") as handle:
        have = hashlib.sha256(handle.read()).hexdigest()
    if have != want:
        raise ValueError("the packed key file is not the one the stack pins")


def _read_caller() -> tuple[str, str]:
    """The caller secret, read from Secrets Manager now (never from a cache): (credential, principal)."""
    raw = _secrets_client().get_secret_value(SecretId=os.environ["REQUISITION_SECRET_ARN"])["SecretString"]
    value = json.loads(raw)
    credential = value.get("credential") if isinstance(value, dict) else None
    principal = value.get("principal") if isinstance(value, dict) else None
    if not (isinstance(credential, str) and credential.startswith("rqc_") and isinstance(principal, str) and principal):
        raise ValueError("the caller secret is not minted yet")
    expected = os.environ.get("REQUISITION_PRINCIPAL_EXPECTED", "")
    if expected and principal != expected:
        raise ValueError("the caller secret names another principal than the stack pins")
    return credential, principal


def _load_caller() -> None:
    _check_keys_pin()
    credential, principal = _read_caller()
    os.environ["REQUISITION_CRED"] = credential
    os.environ["REQUISITION_PRINCIPAL"] = principal


def _reread_credential() -> str:
    """The interceptor's credential source: a fresh read that must name the same principal as the cached one."""
    credential, principal = _read_caller()
    if os.environ.get("REQUISITION_PRINCIPAL") and principal != os.environ["REQUISITION_PRINCIPAL"]:
        raise ValueError("the re-read caller secret names another principal")
    os.environ["REQUISITION_CRED"] = credential
    return credential


def _rpc_id(event: Any) -> Any:
    try:
        return event["mcp"]["gatewayRequest"]["body"].get("id")
    except Exception:  # noqa: BLE001 - malformed input still gets a refusal
        return None


def handler(event: Any, context: Any) -> dict:
    global _CALLER_LOADED
    if not _CALLER_LOADED:
        try:
            _load_caller()
            _CALLER_LOADED = True
        except Exception as error:  # noqa: BLE001 - any failure refuses the call
            log.error("requisition interceptor: caller credential unavailable (%s)", type(error).__name__)
            return _interceptor.rpc_error(
                _rpc_id(event), _interceptor.FAIL_CLOSED,
                "Requisition interceptor: caller credential unavailable; the call is refused (fail closed)")
    return _interceptor.lambda_handler(event, context, credential_source=_reread_credential)
