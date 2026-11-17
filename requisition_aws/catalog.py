# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The tool-definition digest (G2): the rug-pull refusal.

``tool_digest`` is the lower-case hex SHA-384 of ``CanonicalPayload`` v3 (``canonical.encode``, the
act hash's own encoder) over the definition's present members among ``name``, ``title``,
``description``, ``inputSchema``, ``outputSchema`` and ``annotations`` (MCP ``Tool``). A definition
the encoder cannot encode (a float, anywhere) has NO digest: :class:`CatalogRefusal`
``catalog_unencodable``, and the tool is refused (fail closed).

A v2 act type declares ``tool_digest`` as an ``enum`` of the approved digests (one per form that
calls the tool: the Strands view and the Gateway's listing), registered through a registration that two separate
approver accounts approve. Requisition refuses any other digest at propose; this module lets each adapter form
refuse first, and the Gateway form refuse a call to a tool whose listing drifted.

The approval page shows the digest, not the description; the registration pins the description that digest names.

MARKS: the interceptor marks a
drifted listed tool under ``mark_key(gateway id, tool, pin)``, so a re-pin (a new registration of the corrected
digest, approved by two separate approver accounts) is not blocked by the old pin's mark. A mark written before the pin was in the key
(``legacy_mark_key``) still refuses, under any pin. The operator clears marks:

    python -m requisition_aws.catalog --clear-mark <gateway-id> <tool> [--store PATH]   (else REQUISITION_STORE)

It clears every mark of that gateway id and tool, under any pin. Each cleared mark is APPENDED to
``catalog_marks_cleared`` as ``<mark key>:<n>`` (n = 00000001, 00000002, ...; ``Store.clear_catalog_marks``,
one transaction), so no earlier clear is ever overwritten.

Clearing approves nothing. Each mark becomes ``catalog_recheck_pending``: a call is refused, and the next
``tools/list`` re-checks the definition. A tool still drifted is re-marked; the registered definition is
served. The TS proxy re-checks at call time by listing again. The interceptor cannot: a REQUEST carries no
definition. Exit codes: 0 done (the count is printed), 2 usage, 78 the store is unreadable.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from typing import Any

from . import canonical

MEMBERS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
DIGEST_PATH = "tool_digest"
MARK_NAMESPACE = "requisition-aws/catalog-mark"
RECHECK_PENDING = "catalog_recheck_pending"  # cleared by the operator; the next listing decides


class CatalogRefusal(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def definition_view(definition: Any) -> dict:
    if not isinstance(definition, dict) or not isinstance(definition.get("name"), str):
        raise CatalogRefusal("catalog_unreadable", "a tool definition is not an object with a name")
    return {k: definition[k] for k in MEMBERS if k in definition}


def tool_digest(definition: Any) -> str:
    view = definition_view(definition)
    try:
        encoded = canonical.encode(view)
    except (canonical.CanonicalRefusal, canonical.IntakeRefusal, ValueError, TypeError) as error:
        raise CatalogRefusal("catalog_unencodable", type(error).__name__) from None
    return hashlib.sha384(encoded).hexdigest()


def from_strands_spec(spec: Any) -> dict:
    """A Strands ``ToolSpec`` in the MCP ``Tool`` shape: ``inputSchema``/``outputSchema`` unwrapped
    from their ``{"json": ...}``; only the members present."""
    if not isinstance(spec, dict):
        raise CatalogRefusal("catalog_unreadable", "a tool spec is not an object")
    out: dict = {}
    for key in MEMBERS:
        if key not in spec:
            continue
        value = spec[key]
        if key in ("inputSchema", "outputSchema") and isinstance(value, dict) and set(value) == {"json"}:
            value = value["json"]
        out[key] = value
    return out


def pinned_digests(display_schema: Any) -> tuple[str, ...]:
    """The approved digests a display schema pins (its ``tool_digest`` enum), or ()."""
    for entry in display_schema or []:
        if isinstance(entry, dict) and entry.get("path") == DIGEST_PATH:
            values = entry.get("values")
            if entry.get("type") != "enum" or not isinstance(values, list) or not values \
                    or not all(isinstance(v, str) for v in values):
                raise ValueError("a tool_digest member must be an enum of digests")
            return tuple(values)
    return ()


def mark_key(gateway_id: str, tool: str, pin: str) -> str:
    """The store key of a catalog mark: gateway id, tool AND pin (a re-pin is not blocked)."""
    return hashlib.sha256(canonical.encode([MARK_NAMESPACE, gateway_id, tool, pin])).hexdigest()


def legacy_mark_key(gateway_id: str, tool: str) -> str:
    """The key of the first catalog marks (no pin): such a mark still refuses, under any pin, until the operator clears it."""
    return hashlib.sha256(canonical.encode([MARK_NAMESPACE, gateway_id, tool])).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m requisition_aws.catalog",
                                     description="Clear the interceptor's G2 catalog marks (the operator's command).")
    parser.add_argument("--clear-mark", nargs=2, metavar=("GATEWAY_ID", "TOOL"), required=True)
    parser.add_argument("--store", default=None, help="the interceptor's store file (default: REQUISITION_STORE)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return 2 if exit_.code else 0
    gateway_id, tool = args.clear_mark
    store_path = args.store or os.environ.get("REQUISITION_STORE")
    if not gateway_id or not tool or not store_path:
        print("usage: --clear-mark <gateway-id> <tool> needs both names and --store (or REQUISITION_STORE)",
              file=sys.stderr)
        return 2
    from .store import Store, StoreError  # here: the store module imports the gate's dependencies

    try:
        cleared = Store(store_path).clear_catalog_marks(gateway_id, tool)
    except (StoreError, OSError) as error:
        print(f"clear refused: {error}", file=sys.stderr)
        return 78
    print(f"cleared {cleared} catalog mark(s) for gateway {gateway_id!r}, tool {tool!r}; nothing is approved: "
          "a call waits until the next tools/list re-checks the definition")
    return 0


if __name__ == "__main__":
    sys.exit(main())
