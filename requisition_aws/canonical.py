# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A port of Requisition's CanonicalPayload v3 encoder, its act hash, and its intake rules.

Everything here is read from the Requisition version of 2026-10-26, file:line cited:

* ENCODING. ``lib/autonomous_agency/authority_assurance/canonical_payload.ex``:
  - null/true/false, integers as ``Integer.to_string`` (:180-183);
  - strings through ``Jason.encode!`` (:186-190): Jason's ``:json`` escape mode
    (``deps/jason/lib/encode.ex:284-302``): ``\\b \\t \\n \\f \\r \\" \\\\`` short, every other byte
    0x00-0x1F as ``\\u00XX`` with UPPER-case hex, everything else (``/``, DEL, non-ASCII) raw UTF-8;
  - object keys sorted by UTF-16 code units (:220, :258-265), ``,`` and ``:`` with no spaces;
  - floats are encoded by Requisition with Jason's float form (a declared RFC 8785 divergence,
    :19-22). This port REFUSES every float instead: the act-hash domain has none (``ActHash`` moduledoc,
    ``act_hash.ex:10-12``; ``args_schema.ex:87`` refuses a float at intake), so a float can only be
    an adapter bug, and refusing it fails closed.
* ACT HASH. ``act_hash.ex:36-41``: lower-case hex SHA-384 of the v3 bytes of the arguments object
  with the key ``"act_type"`` put inside it. Label ``sha384+canonical_payload.v3`` (:21).
* DISPLAY DIGEST of an argument row: ``Effector.encode/2`` (``effector.ex:113-118``): SHA-256 hex of the v3 bytes of the
  arguments object WITHOUT ``act_type``; the statement signs it as ``display_digest``
  (``sanction_requests.ex:378``) and the decision as ``display_projection_digest``
  (``execute.ex:573``), compared at execute 6b (``execute.ex:498-502``).
* INTAKE. ``display.ex:84-100`` (via ``args_schema.ex:172-173``): a string is refused
  ``forbidden_character`` (Unicode Cc, Cf, Zl, Zp), ``string_not_nfc``, ``display_value_redactable``
  (``Security.Redaction.redact_text/1`` would change it); an integer outside +-(2^53-1) or another
  type is ``malformed_member``; ``null`` anywhere is ``missing_member`` (``args_schema.ex:164``).
  A float member at any depth is ``float_refused`` with its path, before any other check (``refuse_float``),
  the name the encoders below give it; an arguments value that is not an object stays ``malformed_member``.
  The redactor (``lib/autonomous_agency/security/redaction.ex``) is ported below, pattern by pattern.
* The member names the adapter keeps out of the top level (``RESERVED_TOP_LEVEL``; ``effector.ex:145``,
  ``:159-170``): ``members``, ``membership_digest``, ``cue_ready_digest``, ``emitter_mode``; and
  ``act_type`` (``args_schema.ex:23-25``).

Every refusal here happens BEFORE anything is sent to Requisition: fail closed.

CANONICAL_PAYLOAD.V4 is a second encoder beside the v3 one, a port of Requisition's
``CanonicalPayload.V4``: a STRICT SUBSET of RFC 8785. For every input ``encode_v4`` accepts, its bytes are
exactly the bytes RFC 8785 prescribes; everything else is refused by the encoder itself. It differs from
``encode`` in four places, each a narrowing: control characters escape in LOWER-case hex; an integer outside
+-(2^53-1) is ``integer_out_of_range`` (``encode`` writes it exactly); a lone surrogate is ``lone_surrogate``;
nesting stops at 64 containers (``too_deep``). Floats stay refused: decimals are not admitted. Its reader,
``canonicalize_v4``, also refuses the integer lexeme ``-0`` (``negative_zero``): RFC 8785 erratum 7920 (Verified) says a
parser SHOULD error on ``-0``, which the standard writes ``0``.
It also takes exact ``int``, ``str``, ``dict`` and ``list`` only (a subclass could render itself otherwise).
``encode``, ``ACT_HASH_ALG`` and every v3 function are unchanged, and v3 is still what this package sends;
``act_hash(act_type, args, alg)`` derives under the label a record carries. The shared vectors are
``tests/vectors/canonical_v4`` (a byte copy of Requisition's, pinned by digest).

REASON PRECEDENCE, when a text has more than one fault. The reason is a function of the text alone, the same in all four
implementations (Requisition's CanonicalPayload.V4, this module, the offline verifier's copy and requisition-ts's
canonicalizeV4); the rows of group "two-faults" in tests/vectors/canonical_v4/vectors.jsonl pin it, and requisition's
bin/canonical-v4-compare compares the reason code of every row. The text is refused with the FIRST reason of this list that
applies, whatever the positions of the faults:
  1. invalid_utf8      the bytes are not UTF-8;
  2. too_deep          more than 64 nested containers, counted by a scan of the brackets outside strings alone (a double
                       quote that is not escaped opens or closes a string, a backslash skips the next character, "[" and "{"
                       count up, "]" and "}" down, with no floor), before and independently of syntax;
  3. malformed_json    not RFC 8259 JSON;
then, only for text that is valid JSON, judged over the whole document:
  4. duplicate_key     two member names equal after unescaping, in any object;
  5. lone_surrogate    an escaped surrogate without its other half, in a name or a value;
  6. float_refused     a number with a fraction or an exponent;
  7. negative_zero     the integer lexeme -0 (RFC 8785 erratum 7920), judged from the lexeme: no value has a sign of zero;
  8. integer_out_of_range  an integer outside +-(2^53-1).
A TERM handed to the encoder is walked in order and the first fault is its reason; for a term with more than one fault only
"refused" is common to the implementations.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, Iterable

ACT_HASH_ALG = "sha384+canonical_payload.v3"
ACT_HASH_ALGS = (ACT_HASH_ALG,)  # the labels this package derives under; it SENDS the first; sha384+canonical_payload.v4 is not a label (withdrawn): encode_v4 is an encoder only
MAX_DEPTH_V4 = 64  # containers; the 65th is refused (CanonicalPayload.V4.max_depth/0)
MAX_INTEGER = 9_007_199_254_740_991  # display.ex:74, args_schema.ex:38
RESERVED_TOP_LEVEL = ("act_type", "members", "membership_digest", "cue_ready_digest", "emitter_mode")


class CanonicalRefusal(ValueError):
    """A value outside the encoder's accepted domain (this port's domain: no floats)."""

    def __init__(self, code: str, path: list):
        super().__init__(f"canonical payload refused: {code} at {path!r}")
        self.code = code
        self.path = path


class IntakeRefusal(ValueError):
    """A value Requisition's intake would refuse, with the step-0 code it would answer."""

    def __init__(self, code: str, path: str = ""):
        super().__init__(f"{code} at {path or '(top)'}")
        self.code = code
        self.path = path


# --- the encoder -------------------------------------------------------------------------------

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


def _string(value: str, path: list) -> str:
    try:
        value.encode("utf-8")  # a lone surrogate is not valid UTF-8 (canonical_payload.ex:186-189)
    except UnicodeEncodeError:
        raise CanonicalRefusal("invalid_string", path) from None
    out = []
    for ch in value:
        cp = ord(ch)
        if cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20:
            out.append("\\u%04X" % cp)  # upper-case hex: Jason's :io_lib.format("\\u~4.16.0B")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _utf16_key(name: str) -> bytes:
    return name.encode("utf-16-be")  # big-endian code units compare as the RFC 8785 sort


def _encode(value: Any, path: list) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise CanonicalRefusal("float_refused", path)
    if isinstance(value, str):
        return _string(value, path)
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalRefusal("non_string_key", path + [key])
            _string(key, path + [key])
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_string(k, path) + ":" + _encode(v, path + [k]) for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_encode(v, path + [i]) for i, v in enumerate(value)) + "]"
    raise CanonicalRefusal("unencodable", path)


def encode(value: Any) -> bytes:
    """The CanonicalPayload v3 bytes of ``value`` (dict/list/str/int/bool/None only)."""
    return _encode(value, []).encode("utf-8")


# --- canonical_payload.v4: a strict subset of RFC 8785 --------------------------------------------


def _string_v4(value: str, path: list) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalRefusal("lone_surrogate", path) from None
    out = []
    for ch in value:
        cp = ord(ch)
        if cp in _SHORT:
            out.append(_SHORT[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)  # RFC 8785 3.2.2.2: lower-case hex
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _encode_v4(value: Any, path: list, depth: int) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    kind = type(value)  # exact types only: a subclass may render itself differently
    if kind is int:
        if not -MAX_INTEGER <= value <= MAX_INTEGER:  # THE BOUND, in the encoder
            raise CanonicalRefusal("integer_out_of_range", path)
        return "%d" % value
    if kind is float:
        raise CanonicalRefusal("float_refused", path)
    if kind is str:
        return _string_v4(value, path)
    if kind is dict:
        if depth >= MAX_DEPTH_V4:
            raise CanonicalRefusal("too_deep", path)
        for key in value:
            if type(key) is not str:
                raise CanonicalRefusal("non_string_key", path + [key])
            _string_v4(key, path + [key])
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))  # RFC 8785 3.2.3: UTF-16 code units
        return "{" + ",".join(_string_v4(k, path) + ":" + _encode_v4(v, path + [k], depth + 1) for k, v in items) + "}"
    if kind is list:
        if depth >= MAX_DEPTH_V4:
            raise CanonicalRefusal("too_deep", path)
        return "[" + ",".join(_encode_v4(v, path + [i], depth + 1) for i, v in enumerate(value)) + "]"
    raise CanonicalRefusal("unencodable", path)


def encode_v4(value: Any) -> bytes:
    """The ``canonical_payload.v4`` bytes of ``value``, or a ``CanonicalRefusal``."""
    return _encode_v4(value, [], 0).encode("utf-8")


def _reader_v4() -> tuple:
    """The reader's hooks and the content faults they note: a duplicate name, a float, the integer lexeme -0, an integer
    outside the bound are NOTED, not raised, so the whole text is read before the precedence order (see the module docs)
    picks the reason."""
    faults: dict = {}

    def pairs(items: list) -> dict:
        out: dict = {}
        for key, value in items:
            if key in out:
                faults.setdefault("duplicate_key", [key])
            out[key] = value
        return out

    def float_(lexeme: str) -> Any:
        faults.setdefault("float_refused", [])  # from the lexeme: no float is ever parsed
        return 0

    def int_(lexeme: str) -> int:
        if lexeme == "-0":  # erratum 7920, from the lexeme: int("-0") is 0. RFC 8259 admits no other spelling of it.
            faults.setdefault("negative_zero", [])
            return 0
        # 2^53-1 has 16 digits. A longer lexeme is out of range whatever it is, and is never handed to int(), whose own
        # digit limit would answer a different error. The bound itself is the encoder's.
        if len(lexeme.lstrip("-")) > 16:
            faults.setdefault("integer_out_of_range", [])
            return 0
        return int(lexeme)

    return faults, pairs, float_, int_


def _constant_v4(name: str) -> Any:
    raise CanonicalRefusal("malformed_json", [])  # NaN, Infinity, -Infinity are not JSON


def _lone_surrogate_v4(value: Any) -> bool:
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return True
        return False
    if type(value) is dict:
        return any(_lone_surrogate_v4(k) or _lone_surrogate_v4(v) for k, v in value.items())
    if type(value) is list:
        return any(_lone_surrogate_v4(v) for v in value)
    return False


def _depth_v4(text: str) -> None:
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH_V4:
                raise CanonicalRefusal("too_deep", [])
        elif ch in "]}":
            depth -= 1


def canonicalize_v4(data: bytes | str) -> bytes:
    """The ``canonical_payload.v4`` bytes of JSON TEXT: a strict RFC 8259 read, then ``encode_v4``.

    Refused by the read, before the encoder sees anything: bytes that are not UTF-8 (``invalid_utf8``),
    a duplicate member name anywhere (``duplicate_key``), anything that is not RFC 8259 JSON, NaN and
    Infinity and a byte order mark included (``malformed_json``), nesting beyond 64 (``too_deep``), and a
    number with a fraction or an exponent (``float_refused``, from its lexeme). Refused after it: an
    escaped surrogate without its other half (``lone_surrogate``), the integer lexeme ``-0``
    (``negative_zero``, RFC 8785 erratum 7920, from its lexeme) and an integer outside +-(2^53-1)
    (``integer_out_of_range``). Every refusal is a ``CanonicalRefusal``, and its reason, when the text has more
    than one fault, is the first of the PRECEDENCE order in the module docs.
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")  # strict: no surrogatepass, no UTF-16/32 detection
        except UnicodeDecodeError:
            raise CanonicalRefusal("invalid_utf8", []) from None
    else:
        text = data
    _depth_v4(text)
    faults, pairs, float_, int_ = _reader_v4()
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=_constant_v4, parse_float=float_, parse_int=int_)
    except CanonicalRefusal:
        raise
    except (ValueError, RecursionError):
        raise CanonicalRefusal("malformed_json", []) from None
    if "duplicate_key" in faults:
        raise CanonicalRefusal("duplicate_key", faults["duplicate_key"])
    if _lone_surrogate_v4(value):
        raise CanonicalRefusal("lone_surrogate", [])
    for code in ("float_refused", "negative_zero", "integer_out_of_range"):
        if code in faults:
            raise CanonicalRefusal(code, [])
    return encode_v4(value)


_ENCODERS = {ACT_HASH_ALG: encode}


def preimage(act_type: str, args: dict, alg: str = ACT_HASH_ALG) -> bytes:
    """The bytes ``ActHash.derive/3`` hashes: the arguments object with ``act_type`` put inside, under
    ``alg``'s encoder. An unknown label is refused ``act_hash_alg_unknown``, never derived under another."""
    encoder = _ENCODERS.get(alg) if isinstance(alg, str) else None
    if encoder is None:
        raise CanonicalRefusal("act_hash_alg_unknown", [])
    if not isinstance(args, dict):
        raise CanonicalRefusal("not_an_object", [])
    if "act_type" in args:
        # Map.put would overwrite it (act_hash.ex:37); an argument row can never carry one
        # (args_schema.ex:23-25), so the port refuses rather than silently overwrite
        raise CanonicalRefusal("act_type_member_reserved", ["act_type"])
    if not isinstance(act_type, str) or not act_type:
        raise CanonicalRefusal("act_type_not_a_string", [])
    return encoder({**args, "act_type": act_type})


def act_hash(act_type: str, args: dict, alg: str = ACT_HASH_ALG) -> str:
    """Lower-case hex SHA-384 of ``preimage(act_type, args, alg)``; ``alg`` is the record's ``act_hash_alg``
    (default ``sha384+canonical_payload.v3``, the label this package sends)."""
    return hashlib.sha384(preimage(act_type, args, alg)).hexdigest()


def display_digest(args: dict) -> str:
    """An argument row's ``display_digest`` / ``display_projection_digest`` (Requisition's ``Effector.encode/2``)."""
    return hashlib.sha256(encode(args)).hexdigest()


# --- the redactor (redaction.ex), byte mode ------------------------------------------------------
#
# Elixir's ~r without the `u` flag is PCRE in byte (non-UTF) mode: \w, \s, \b and /i are ASCII
# only and `.` is a byte. Python's `re` over `bytes` patterns has exactly those semantics, so the
# patterns run over the UTF-8 bytes, as Requisition runs them.

_I = re.IGNORECASE

_SECRET_KEY_WORDS = (  # redaction.ex:146-149
    rb"[A-Za-z0-9_\-]*(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    rb"private[_-]?key|client[_-]?secret|secret|password|passwd|pwd|token|"
    rb"authorization|bearer|passphrase|userinfo|cookie)[A-Za-z0-9_\-]*"
    rb"|[A-Za-z0-9_\-]*credentials?(?:[_-](?:value|values|data|payload|blob|material))?"
)
_AUTH_SCHEMES = rb"Bearer|Basic|Digest|Negotiate|NTLM|Token|ApiKey|AWS4-HMAC-SHA256"  # :165

_BEARER = re.compile(rb"\bBearer\s+[A-Za-z0-9+/=._\-]+", _I)  # :169
_SECRET_ASSIGNMENT = re.compile(  # :188-200
    rb"(?<![\w:/])(?P<key>" + _SECRET_KEY_WORDS + rb")"
    rb"(?P<sep>(?:\">>|\")?\s*(?:=>|:=|[:=])\s*|\"\s*,\s*)"
    rb"(?P<val>(?:(?:" + _AUTH_SCHEMES + rb")\s+)?\[REDACTED\]|"
    rb"<<\"(?:[^\"\\]|\\.)*\">>|\"(?:[^\"\\]|\\.)*\"|"
    rb"'(?:[^'\\]|\\.)*'|(?:" + _AUTH_SCHEMES + rb")\s+[^\s,;&\"')\]}]+|[^\s,;&\"')\]}]+)",
    _I,
)
_LEGACY_ASSIGNMENT = re.compile(rb"(api[_-]?key|token|secret|password)=([^\s&]+)", _I)  # :209
_URL_USERINFO = re.compile(rb"\b([a-z][a-z0-9+.\-]*://[^/\s:@]+):([^@\s/]+)@", _I)  # :214
_COOKIE = re.compile(  # :218
    rb"\b((?:set[_-]?)?cookie)(\"?\s*(?:=>|:=|[:=])\s*)(\"(?:[^\"\\]|\\.)*\"|[^\r\n\"}\],]+)", _I
)
_BARE_SECRET = re.compile(  # :224 (no /i)
    rb"(?<![\w./])(?:[a-z0-9_\-]*secret[a-z0-9_\-]*|[A-Z0-9_\-]*SECRET[A-Z0-9_\-]*)"
    rb"(?![\w./])(?!\"?\s*(?:=>|:=|[:=])\s*\"?\[REDACTED\])"
)
_SHAPES = [  # :230-244
    re.compile(rb"sk_(live|test)_[A-Za-z0-9._\-]+", _I),
    re.compile(rb"sk[_-](live|test)[_\-][A-Za-z0-9._\-]+", _I),
    re.compile(rb"sk-[A-Za-z0-9._\-]+", _I),
    re.compile(rb"sk-or-v1-[A-Za-z0-9._\-]+", _I),
    re.compile(rb"whsec[_\-]?[A-Za-z0-9._\-]+", _I),
    re.compile(rb"nvapi[_\-]?[A-Za-z0-9._\-]+", _I),
    re.compile(rb"ya29\.[A-Za-z0-9._\-]+", _I),
    re.compile(rb"1//[A-Za-z0-9._\-]+", _I),
    re.compile(rb"pat-[A-Za-z0-9._\-]+", _I),
    re.compile(rb"xox[baprs]-[A-Za-z0-9._\-]+", _I),
    re.compile(rb"gh[pousr]_[A-Za-z0-9_]+", _I),
    re.compile(rb"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(
        rb"-----BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY-----.*?-----END (RSA|OPENSSH|EC|PRIVATE) KEY-----",
        _I | re.DOTALL,
    ),
]
_REDACTED = b"[REDACTED]"


def redact_text(value: str, configured_secrets: Iterable[str] = ()) -> str:
    """``Redaction.redact_text(value, :untrusted)`` (redaction.ex:319-330), step for step.

    ``configured_secrets`` stands in for the server's env secrets (redaction.ex:118-131, :618-623),
    which an adapter cannot read: pass any you know; the server refuses the rest itself.
    """
    data = value.encode("utf-8")
    for secret in configured_secrets:  # redact_configured_secrets
        if isinstance(secret, str) and len(secret.strip()) >= 8:
            data = data.replace(secret.encode("utf-8"), _REDACTED)
    data = _URL_USERINFO.sub(lambda m: m.group(1) + b":[REDACTED]@", data)
    data = _BEARER.sub(b"Bearer [REDACTED]", data)
    data = _COOKIE.sub(lambda m: m.group(1) + m.group(2) + _REDACTED, data)
    data = _SECRET_ASSIGNMENT.sub(lambda m: m.group("key") + m.group("sep") + _REDACTED, data)
    data = _LEGACY_ASSIGNMENT.sub(lambda m: m.group(1) + b"=[REDACTED]", data)
    for pattern in _SHAPES + [_BARE_SECRET]:
        data = pattern.sub(_REDACTED, data)
    return data.decode("utf-8", errors="surrogateescape")


def would_redact(value: str, configured_secrets: Iterable[str] = ()) -> bool:
    """Would ``Redaction.redact_text/1`` change ``value``? (display.ex:95)"""
    return redact_text(value, configured_secrets) != value


# --- intake ------------------------------------------------------------------------------------

_FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}  # display.ex:75


def check_string(value: str, path: str = "", configured_secrets: Iterable[str] = ()) -> None:
    """``Display.check_value/1`` for a string, in its order (display.ex:90-98)."""
    if not isinstance(value, str):
        raise IntakeRefusal("malformed_member", path)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise IntakeRefusal("malformed_member", path) from None
    if any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value):
        raise IntakeRefusal("forbidden_character", path)
    if unicodedata.normalize("NFC", value) != value:
        raise IntakeRefusal("string_not_nfc", path)
    if would_redact(value, configured_secrets):
        raise IntakeRefusal("display_value_redactable", path)


def _join(prefix: str, key: Any) -> str:
    return f"{prefix}.{key}" if prefix else str(key)


def refuse_float(value: Any, path: str = "") -> None:
    """Raise ``IntakeRefusal("float_refused", path)`` at the first float in ``value`` (a ``float`` of any value:
    ``-0.0``, ``1e5`` as decoded, ``nan``, ``inf``), walking members in sorted order and list items in order; the
    path is the one intake names (``a.b.0``). Intake runs it before every other check, so a float has one name
    whatever else is wrong with the arguments. A member under a name that is not a string is left to those checks."""
    if isinstance(value, float):
        raise IntakeRefusal("float_refused", path)
    if isinstance(value, dict):
        for key in sorted(k for k in value if isinstance(k, str)):
            refuse_float(value[key], _join(path, key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            refuse_float(item, _join(path, i))


def _check_value(value: Any, path: str, secrets: tuple) -> None:
    if value is None:
        raise IntakeRefusal("missing_member", path)
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_INTEGER <= value <= MAX_INTEGER:
            raise IntakeRefusal("malformed_member", path)
        return
    if isinstance(value, str):
        check_string(value, path, secrets)
        return
    if isinstance(value, dict):
        for key in sorted(value):
            if not isinstance(key, str):
                raise IntakeRefusal("malformed_member", path)
            check_string(key, _join(path, key), secrets)
            _check_value(value[key], _join(path, key), secrets)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_value(item, _join(path, i), secrets)
        return
    raise IntakeRefusal("malformed_member", path)  # every other type (a float never reaches here: refuse_float)


def check_arguments(args: Any, configured_secrets: Iterable[str] = ()) -> None:
    """The schema-free half of intake, over every value at any depth. Raises IntakeRefusal."""
    if not isinstance(args, dict):
        raise IntakeRefusal("malformed_member", "")
    refuse_float(args)
    for name in RESERVED_TOP_LEVEL:
        if name in args:
            raise IntakeRefusal("member_out_of_schema", name)
    _check_value(args, "", tuple(configured_secrets))


# --- the argument schema (args_schema.ex), the facets an adapter can check alone ----------------

_TYPES = {"i", "s", "enum", "b", "list", "obj"}
_FACETS = {  # args_schema.ex:29-36, minus the cross-member facets this port does not carry
    "i": {"min", "max"},
    "s": {"min_length", "max_length"},
    "enum": {"values"},
    "b": set(),
    "list": {"min_items", "max_items"},
    "obj": set(),
}
_UNPORTED = {"length_of", "greater_than", "sorted"}


class ArgsSchema:
    """A path-form ``display_schema`` (args_schema.ex:1-26), validated locally before propose.

    Requisition re-validates at propose (``effector.ex:134``) and its answer is the one that counts;
    this copy only lets the adapter refuse early. A schema using a facet this port does not carry
    (``length_of``, ``greater_than``, ``sorted``) is refused at construction: fail closed.
    String lengths are counted in code points; Requisition counts graphemes (``String.length``,
    ``args_schema.ex:219``), so for ``max_length`` this copy is never looser.
    """

    def __init__(self, entries: list[dict]):
        if not isinstance(entries, list) or not entries:
            raise ValueError("malformed_display_schema")
        self.by_path: dict[str, dict] = {}
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") not in _TYPES:
                raise ValueError("malformed_display_schema")
            extra = set(entry) - {"path", "type", "required"} - _FACETS[entry["type"]]
            if extra & _UNPORTED:
                raise ValueError(f"facet not ported: {sorted(extra & _UNPORTED)}")
            if extra:
                raise ValueError("malformed_display_schema")
            path = entry.get("path")
            if not isinstance(path, str) or path in self.by_path:
                raise ValueError("malformed_display_schema")
            if path == "act_type":
                raise ValueError("act_type_member_reserved")
            self.by_path[path] = entry

    def _members(self, obj_path: str | None) -> dict[str, dict]:
        out = {}
        for path, entry in self.by_path.items():
            if obj_path is None:
                if "." not in path and "[]" not in path:
                    out[path] = entry
            elif path.startswith(obj_path + ".") and "." not in path[len(obj_path) + 1 :] and not path.endswith("[]"):
                out[path[len(obj_path) + 1 :]] = entry
        return out

    def validate(self, args: Any, configured_secrets: Iterable[str] = ()) -> None:
        """Shape first, then facets, as ``ArgsSchema.validate/2`` (args_schema.ex:93-101)."""
        if not isinstance(args, dict):
            raise IntakeRefusal("malformed_member", "")
        refuse_float(args)
        secrets = tuple(configured_secrets)
        self._shape_object(args, None, secrets)
        self._facets_object(args, None)

    def _shape_object(self, value: dict, obj_path: str | None, secrets: tuple) -> None:
        members = self._members(obj_path)
        for key in value:
            if key not in members:
                raise IntakeRefusal("member_out_of_schema", _join(obj_path or "", key))
        for name in sorted(members):
            entry = members[name]
            if name not in value:
                if entry["required"]:
                    raise IntakeRefusal("missing_member", _join(obj_path or "", name))
                continue
            self._shape_value(value[name], entry, secrets)

    def _shape_value(self, value: Any, entry: dict, secrets: tuple) -> None:
        path, kind = entry["path"], entry["type"]
        if value is None:
            raise IntakeRefusal("missing_member", path)
        if kind == "i":
            if isinstance(value, bool) or not isinstance(value, int) or not -MAX_INTEGER <= value <= MAX_INTEGER:
                raise IntakeRefusal("malformed_member", path)
        elif kind == "s":
            if not isinstance(value, str):
                raise IntakeRefusal("malformed_member", path)
            check_string(value, path, secrets)
        elif kind == "enum":
            if not isinstance(value, str) or value not in entry["values"]:
                raise IntakeRefusal("malformed_member", path)
        elif kind == "b":
            if not isinstance(value, bool):
                raise IntakeRefusal("malformed_member", path)
        elif kind == "obj":
            if not isinstance(value, dict):
                raise IntakeRefusal("malformed_member", path)
            self._shape_object(value, path, secrets)
        elif kind == "list":
            if not isinstance(value, list):
                raise IntakeRefusal("malformed_member", path)
            element = self.by_path.get(path + "[]")
            if element is None:
                raise IntakeRefusal("malformed_member", path)
            if isinstance(entry.get("max_items"), int) and len(value) > entry["max_items"]:
                raise IntakeRefusal("member_out_of_schema", path)
            for item in value:
                self._shape_value(item, element, secrets)

    def _facets_object(self, value: dict, obj_path: str | None) -> None:
        for name in sorted(value):
            path = _join(obj_path or "", name)
            self._facet(value[name], self.by_path[path])

    def _facet(self, value: Any, entry: dict) -> None:
        kind, path = entry["type"], entry["path"]
        out = IntakeRefusal("display_member_out_of_range", path)
        if kind == "i":
            if isinstance(entry.get("min"), int) and value < entry["min"]:
                raise out
            if isinstance(entry.get("max"), int) and value > entry["max"]:
                raise out
        elif kind == "s":
            if isinstance(entry.get("min_length"), int) and len(value) < entry["min_length"]:
                raise out
            if isinstance(entry.get("max_length"), int) and len(value) > entry["max_length"]:
                raise out
        elif kind == "obj":
            self._facets_object(value, path)
        elif kind == "list":
            if isinstance(entry.get("min_items"), int) and len(value) < entry["min_items"]:
                raise out
            for item in value:
                self._facet(item, self.by_path[path + "[]"])
