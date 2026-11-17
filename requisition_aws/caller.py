# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Who is calling: the caller-key sources of the Gateway REQUEST interceptor (G1).

An MCP-target interceptor's input has no identity field. Its only caller-bound material is the
``Authorization`` header, and only with ``passRequestHeaders`` true
(gateway-interceptors-types.html, read 2026-11-10). The Gateway authenticates the inbound request
BEFORE it invokes the interceptor (AWS ML blog, "Apply fine-grained access control with Bedrock
AgentCore Gateway interceptors": "AgentCore Gateway authenticates the inbound request. AgentCore
Gateway invokes the custom interceptor."). Three sources, chosen by configuration
(``REQUISITION_CALLER_SOURCE``):

* ``legacy_session`` (:class:`LegacySessionCaller`, the DEFAULT until a live call measures what the
  Gateway forwards under AWS_IAM): the pre-G1 behaviour, the ``Mcp-Session-Id`` header. It is not a
  caller identity; MCP 2026-07-28 removes it.
* ``sigv4`` (:class:`SigV4Caller`): the access-key id of the SigV4 ``Authorization`` header, for an
  ``AWS_IAM`` gateway. The Gateway checked the signature; this function cannot (it holds no secret).
  An access-key id names a credential, not a principal: one principal with two keys is two callers
  (that direction fails closed), and temporary (ASIA) keys rotate.
* ``jwt`` (:class:`JwtCaller`): a bearer JWT verified HERE against a pinned issuer and JWKS
  (RS256 only), for a ``CUSTOM_JWT`` gateway: defence in depth, and the only sound source on a
  gateway whose authorizer is NONE.

``clientInfo`` is never the caller (MCP 2026-07-28 basic: "self-reported … SHOULD NOT rely on them
for security decisions").
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import canonical
from .client import loads_strict

SESSION_NAMESPACE = "requisition-aws/caller-session"
_SIGV4 = re.compile(
    r"\AAWS4-HMAC-SHA256 Credential=(A[KS]IA[A-Z0-9]{12,124})/[0-9]{8}/[a-z0-9-]+/[a-z0-9-]+/aws4_request(?:,|\Z)")
_B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")


def header_values(headers: Any, name: str) -> list:
    """Every value of a request header by case-insensitive name (RFC 9110)."""
    if not isinstance(headers, dict):
        return []
    return [value for key, value in headers.items() if isinstance(key, str) and key.lower() == name]


def header(headers: Any, name: str) -> str | None:
    """A request header by case-insensitive name, or None: absent, not a string, or AMBIGUOUS (more
    than one case variant; the first one is never chosen)."""
    values = header_values(headers, name)
    return values[0] if len(values) == 1 and isinstance(values[0], str) else None


def caller_session(caller_key: str, client_id: str | None) -> str:
    """The signed ``session`` member: the client's own id (or none) namespaced by the caller key.
    Deterministic, at most 64 characters, never the raw key; stable across the pending call and
    the re-call, so the act hash matches; a new caller key (a rotated credential) is a new act."""
    digest = hashlib.sha256(canonical.encode([SESSION_NAMESPACE, caller_key, client_id])).hexdigest()
    return "caller-" + digest[:48]


class LegacySessionCaller:
    """The pre-G1 source: the raw ``Mcp-Session-Id`` is the signed session and part of the call key."""

    source = "legacy_session"


class SigV4Caller:
    source = "sigv4"

    def key(self, headers: Any) -> str | None:
        value = header(headers, "authorization")
        # two credentials, in any spelling (``credential=`` too): ambiguous, fail closed
        if not value or value.lower().count("credential=") != 1:
            return None
        match = _SIGV4.match(value)
        return f"sigv4:{match.group(1)}" if match else None


def _b64url(part: str) -> bytes:
    if not _B64URL.match(part):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _b64url_int(value: Any) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError("not a base64url integer")
    return int.from_bytes(_b64url(value), "big")


class JwtCaller:
    """A bearer JWT verified against a pinned issuer and JWKS: ``jwt:<iss>|<sub>`` (``client_id``
    when the token has no ``sub``, the M2M case), or None for anything else."""

    source = "jwt"

    def __init__(self, issuer: str, jwks: dict, *, audiences=(), clients=(),
                 clock: Callable[[], float] = time.time, leeway: int = 60):
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("a JWT caller needs its issuer")
        audiences, clients = tuple(audiences or ()), tuple(clients or ())
        if not audiences and not clients:
            raise ValueError("a JWT caller pins its audiences or its client ids (neither given)")
        self.issuer, self.audiences, self.clients = issuer, audiences, clients
        self.clock, self.leeway = clock, leeway
        self.keys: dict[str, rsa.RSAPublicKey] = {}
        for jwk in (jwks or {}).get("keys", []):
            if isinstance(jwk, dict) and jwk.get("kty") == "RSA" and isinstance(jwk.get("kid"), str) \
                    and jwk.get("alg", "RS256") == "RS256" and jwk.get("use", "sig") == "sig":
                numbers = rsa.RSAPublicNumbers(_b64url_int(jwk["e"]), _b64url_int(jwk["n"]))
                self.keys[jwk["kid"]] = numbers.public_key()
        if not self.keys:
            raise ValueError("the pinned JWKS holds no RS256 signing key")

    def key(self, headers: Any) -> str | None:
        try:
            return self._key(headers)
        except (ValueError, TypeError, KeyError, binascii.Error, InvalidSignature, UnicodeDecodeError):
            return None

    def _key(self, headers: Any) -> str | None:
        value = header(headers, "authorization")
        if not value or not value.startswith("Bearer "):
            return None
        parts = value[len("Bearer "):].split(".")
        if len(parts) != 3:
            return None
        head = loads_strict(_b64url(parts[0]))
        if not isinstance(head, dict) or head.get("alg") != "RS256" or head.get("kid") not in self.keys:
            return None
        self.keys[head["kid"]].verify(_b64url(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"),
                                      padding.PKCS1v15(), hashes.SHA256())
        claims = loads_strict(_b64url(parts[1]))  # a duplicate claim is refused, never "the last one"
        if not isinstance(claims, dict) or claims.get("iss") != self.issuer:
            return None
        now = self.clock()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp <= now - self.leeway:
            return None
        if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, (int, float)) or nbf > now + self.leeway):
            return None
        aud = claims.get("aud")
        auds = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        client_id = claims.get("client_id")
        if not (any(a in self.audiences for a in auds if isinstance(a, str))
                or (isinstance(client_id, str) and client_id in self.clients)):
            return None
        if "sub" in claims:
            subject = claims["sub"]
        else:
            subject = client_id
        if not isinstance(subject, str) or not subject:
            return None
        return f"jwt:{self.issuer}|{subject}"
