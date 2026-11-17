# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A Strands ``Model`` with no network: it plays a fixed script of turns.

Used by the tests and by ``demo/run_demo.py --scripted`` (the scripted agent
fallback). The tool call still goes through the agent's event loop, so the Requisition hook, the
interrupt and the resume are exactly the live path; only the model is replaced.

Stream events are Strands' Converse-shaped ``StreamEvent``s (``strands/types/streaming.py``).
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterable

from strands.models.model import Model


class ScriptedModel(Model):
    def __init__(self, turns: list[dict]):
        """``turns``: each ``{"tool": name, "input": {...}, "id": optional}`` or ``{"text": str}``,
        consumed one per model call."""
        self.turns = list(turns)
        self.config: dict[str, Any] = {"model_id": "scripted"}
        self.calls = 0

    def update_config(self, **model_config: Any) -> None:
        self.config.update(model_config)

    def get_config(self) -> Any:
        return self.config

    def structured_output(self, output_model, prompt, system_prompt=None, **kwargs):  # pragma: no cover
        raise NotImplementedError("the scripted model has no structured output")

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterable[dict]:
        self.calls += 1
        turn = self.turns.pop(0) if self.turns else {"text": "(script finished)"}
        yield {"messageStart": {"role": "assistant"}}
        if "tool" in turn:
            tool_use_id = turn.get("id") or f"tooluse_scripted_{self.calls}"
            yield {"contentBlockStart": {"start": {"toolUse": {"toolUseId": tool_use_id, "name": turn["tool"]}}}}
            yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(turn["input"])}}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "tool_use"}}
        else:
            yield {"contentBlockStart": {"start": {}}}
            yield {"contentBlockDelta": {"delta": {"text": turn["text"]}}}
            yield {"contentBlockStop": {}}
            yield {"messageStop": {"stopReason": "end_turn"}}
