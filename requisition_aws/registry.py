# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Tool -> act type registry. A tool not registered here is denied (deny by default)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .canonical import ArgsSchema
from .catalog import pinned_digests as _pinned


@dataclass(frozen=True)
class ToolBinding:
    tool_name: str  # the name the agent (or the Gateway, "<target>___<tool>") calls it by
    act_type: str  # the Requisition act type registered for it
    schema: ArgsSchema | None  # the act type's display_schema, for the local pre-check
    pinned_digests: tuple[str, ...] = ()  # G2: the act type's tool_digest enum (a v2 row), else ()
    pin: str | None = None  # G2: the digest THIS form sends (one of pinned_digests)


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolBinding] = {}

    def register(self, tool_name: str, act_type: str, display_schema: list | None = None,
                 pin: str | None = None) -> ToolBinding:
        """``pin``: the digest this form sends for a v2 row; one enum value is its own pin, several
        need one named; a pin outside the enum refuses (the registration is the catalog pin)."""
        if tool_name in self._tools:
            raise ValueError(f"tool {tool_name!r} registered twice")
        pinned = _pinned(display_schema)
        if pin is not None and pin not in pinned:
            raise ValueError(f"tool {tool_name!r}: pin is not one of its act type's registered tool digests")
        if pin is None and len(pinned) == 1:
            pin = pinned[0]
        binding = ToolBinding(tool_name, act_type, ArgsSchema(display_schema) if display_schema else None,
                              pinned, pin)
        self._tools[tool_name] = binding
        return binding

    def get(self, tool_name: str) -> ToolBinding | None:
        return self._tools.get(tool_name) if isinstance(tool_name, str) else None

    def names(self) -> list[str]:
        return sorted(self._tools)

    @classmethod
    def from_seed(cls, seed_path: str, tools: dict) -> "ToolRegistry":
        """Bind ``{tool_name: act_type}`` (or ``{tool_name: {"act_type", "tool_digest"}}``, a v2 row's
        pin) with each act type's display_schema read from a lab seed file
        (``lab/seed/aws_demo.v1.json``, schema ``requisition.lab.seed.v1``)."""
        with open(seed_path, "rb") as handle:
            seed = json.load(handle)
        rows = {row["registration"]["name"]: row["registration"] for row in seed.get("act_types", [])}
        registry = cls()
        for tool_name, spec in tools.items():
            if isinstance(spec, dict):
                if set(spec) - {"act_type", "tool_digest"} or not isinstance(spec.get("act_type"), str):
                    raise ValueError(f"tool {tool_name!r}: binding must be {{act_type, tool_digest}}")
                act_type, pin = spec["act_type"], spec.get("tool_digest")
            else:
                act_type, pin = spec, None
            row = rows.get(act_type)
            if row is None:
                raise ValueError(f"act type {act_type!r} is not in {seed_path}")
            if row.get("act_hash_derivation") != "args_sha384":
                raise ValueError(f"act type {act_type!r} is not an argument row (args_sha384)")
            registry.register(tool_name, act_type, row["display_schema"], pin=pin)
        return registry
