# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The one reader of the entry points' environment settings that switch or loosen a control.

Each setting accepts a closed set of spellings. Any other value refuses to start with a :class:`SettingError` that
names the variable and the accepted values; it never falls back to a weaker setting. An unset variable keeps its
default, which is the safe one. The value itself is never repeated in the message.

- :func:`switch`: exactly ``1`` or ``0``.
- :func:`seconds`: decimal digits, optionally a dot and more digits (``5``, ``0.5``), whose value is above zero and at
  most one day (86400).
- :func:`header_name`: unset, or an HTTP field name (an RFC 9110 token); set and empty is refused.
- :func:`choice`: one of the listed words, exactly.
- :func:`principal_id`: a Requisition principal id, ``rqp_`` and 32 lower-case hex digits.
- :func:`json_map`: a JSON object read by the strict reader (a member named twice, NaN or Infinity is refused).
- :func:`host`: a host name (RFC 1123) or an IP literal; set and empty is refused.

:func:`log_reason` is what a log line may say about a refusal: a SettingError's message (it names the variable and the
accepted values, never the value), any other error's type only.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Mapping

from .client import loads_strict

SWITCH = {"1": True, "0": False}
SECONDS_FORM = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z", re.ASCII)
TOKEN_FORM = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z", re.ASCII)
PRINCIPAL_FORM = re.compile(r"rqp_[0-9a-f]{32}\Z", re.ASCII)
HOST_NAME = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z", re.ASCII)
MAX_SECONDS = 86400.0  # one day


class SettingError(ValueError):
    """A setting holds a value outside its accepted spellings: the entry point refuses to start."""


def _refuse(name: str, accepted: str) -> SettingError:
    return SettingError(f"{name} must be {accepted}; refusing to start")


def switch(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = env.get(name)
    if value is None:
        return default
    if value not in SWITCH:
        raise _refuse(name, 'exactly "1" or "0" (unset: "%d")' % default)
    return SWITCH[value]


def seconds(env: Mapping[str, str], name: str, default: float) -> float:
    value = env.get(name)
    if value is None:
        return float(default)
    number = float(value) if SECONDS_FORM.match(value) else math.nan
    if not (math.isfinite(number) and 0 < number <= MAX_SECONDS):
        raise _refuse(name, "a number of seconds above zero and at most 86400 (one day), in decimal digits (such as 5 or 0.5)")
    return number


def header_name(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None:
        return None
    if not TOKEN_FORM.match(value):
        raise _refuse(name, "an HTTP header name (letters, digits and !#$%&'*+.^_`|~-), or unset")
    return value


def choice(env: Mapping[str, str], name: str, words: tuple[str, ...], default: str) -> str:
    value = env.get(name, default)
    if value not in words:
        raise _refuse(name, "one of " + ", ".join(words))
    return value


def principal_id(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if value is None or not PRINCIPAL_FORM.match(value):
        raise _refuse(name, "a principal id: rqp_ and 32 lower-case hex digits (required)")
    return value


def json_map(env: Mapping[str, str], name: str, default: str | None = None) -> dict[str, Any]:
    value = env.get(name, default)
    if value is None:
        raise _refuse(name, "set to a JSON object")
    try:
        parsed = loads_strict(value)
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        raise _refuse(name, "a JSON object (strict: no member named twice, no NaN or Infinity)")
    return parsed


def host(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name)
    if value is None:
        return default
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not HOST_NAME.match(value):
        raise _refuse(name, f"a host name or an IP literal (unset: {default})")
    return value


def log_reason(error: BaseException) -> str:
    return str(error) if isinstance(error, SettingError) else type(error).__name__
