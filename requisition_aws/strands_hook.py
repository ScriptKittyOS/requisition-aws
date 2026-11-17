# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""A Strands Agents hook that lets a tool run only on Requisition's signed allow for its exact arguments.

Strands (strands-agents 1.64.0, read from the installed source):
* ``BeforeToolCallEvent`` (``strands/hooks/events.py:221-258``): ``tool_use`` ({toolUseId, name, input}),
  ``cancel_tool`` (a message turns the call into an error tool result), ``interrupt(name, reason=...)``
  (``strands/types/interrupt.py``: raises ``InterruptException`` the first time, so the agent stops
  with ``stop_reason == "interrupt"``; the app resumes with
  ``[{"interruptResponse": {"interruptId": ..., "response": ...}}]`` and the callback runs again from
  the top, where the same ``interrupt(name)`` call now RETURNS the response). The interrupt id is
  ``v1:before_tool_call:<toolUseId>:<uuid5(name)>``, so one fixed name per callback is enough.
* ``AfterToolCallEvent`` (``events.py:261-311``): fired after the tool ran (or was cancelled:
  ``cancel_message`` set, ``duration`` None).

Flow:
  unregistered tool -> cancel (deny by default)
  local intake refusal -> cancel (refused, never truncated)
  propose (deduplicated on act_hash) -> pending -> interrupt {request_id, approval_url}
  resume -> re-read the request (the interrupt's response is never trusted: only the GET is)
  sanctioned -> execute (idempotent per tool use) -> verify the signed record
  allow, before exec_not_after, and the statement's single-use claim taken (a conditional write in
    the store BEFORE the tool may run) -> the tool runs; a second tool use on that statement is refused
  AfterToolCallEvent -> the tool_ran event,
    then, when the server has POST /v1/outcomes, the outcome (succeeded | failed, the
    SHA-256 of the ToolResult's content by gate.result_bytes); otherwise nothing more is sent
  anything else, or Requisition unreachable -> cancel_tool with the reason (fail closed)

LIMIT: this hook runs in the agent's own process; a compromised agent can
skip it. The Gateway interceptor and the target form are the out-of-process forms.

F1 (fence.py): every signed record read enters the store's position memory (a different
record at a held position: ``authority_equivocated``, both kept as evidence), and the admission claim
covers the statement and the approval it names (``approval_already_used`` for a re-minted statement).
It holds while this hook's store survives (the agent host's own file).

G2 (catalog.py): for a v2 act type (one whose schema pins ``tool_digest``) the
digest is RECOMPUTED at every callback, the resume included, from ``event.selected_tool.tool_spec``:
the definition the agent's model was given (the hook does not list an MCP server again). A digest the
registration does not pin is ``catalog_drift``; a definition the encoder cannot encode is
``catalog_unencodable``; either cancels before anything is proposed or executed. The digest is in the
arguments, so the signed act hash covers it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookProvider, HookRegistry
from strands.interrupt import InterruptException

from . import canonical, catalog
from .client import RequisitionError
from .gate import Decision, Gate, arguments_object
from .registry import ToolRegistry
from .store import idempotency_key

log = logging.getLogger(__name__)

INTERRUPT_NAME = "requisition_approval"


@dataclass
class Event:
    """One line of the hook's own log (for the demo transcript): never a credential."""

    kind: str
    tool_use_id: str
    detail: dict = field(default_factory=dict)


class RequisitionHook(HookProvider):
    def __init__(
        self,
        gate: Gate,
        registry: ToolRegistry,
        *,
        agent_name: str,
        session_id: str,
        on_event: Callable[[Event], None] | None = None,
    ):
        self.gate = gate
        self.registry = registry
        self.agent_name = agent_name
        self.session_id = session_id
        self.on_event = on_event or (lambda e: None)
        self.records: list[dict] = []  # every statement and decision seen, for the offline check
        self._allowed: dict[str, tuple[str, Decision]] = {}  # toolUseId -> (statement_id, the allow)
        self._args_of: dict[str, dict] = {}  # toolUseId -> the arguments object, for the outcome's offline check
        self._digest_of: dict[str, str] = {}  # toolUseId -> the tool digest recomputed at this call (G2)

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self.before_tool_call)
        registry.add_callback(AfterToolCallEvent, self.after_tool_call)

    # --- before ------------------------------------------------------------------------------------

    def _emit(self, kind: str, tool_use_id: str, **detail: Any) -> None:
        self.on_event(Event(kind, tool_use_id, detail))

    def _cancel(self, event: BeforeToolCallEvent, message: str) -> None:
        event.cancel_tool = "Requisition: " + message
        self._emit("cancelled", event.tool_use.get("toolUseId", ""), reason=message)

    def before_tool_call(self, event: BeforeToolCallEvent) -> None:
        try:
            self._before(event)
        except InterruptException:
            raise  # Strands' own control flow: the agent stops and returns the interrupt
        except canonical.IntakeRefusal as refusal:
            self._cancel(event, f"arguments refused before sending ({refusal.code} at {refusal.path or 'top'}); nothing was proposed")
        except canonical.CanonicalRefusal as refusal:
            self._cancel(event, f"arguments cannot be canonicalised ({refusal.code}); nothing was proposed")
        except RequisitionError as error:
            self._cancel(event, f"{error}; the tool did not run (fail closed)")
        except Exception as error:  # noqa: BLE001 - anything unexpected fails closed
            log.exception("requisition hook failed closed")
            self._cancel(event, f"internal error ({type(error).__name__}); the tool did not run (fail closed)")

    def _before(self, event: BeforeToolCallEvent) -> None:
        tool_use = event.tool_use
        tool_use_id = tool_use.get("toolUseId", "")
        binding = self.registry.get(tool_use.get("name"))
        if binding is None:
            self._cancel(event, f"tool {tool_use.get('name')!r} has no registered act type; denied by default")
            return
        tool_args = tool_use.get("input")
        if not isinstance(tool_args, dict):
            self._cancel(event, "tool input is not an object; denied")
            return
        digest = None
        if binding.pinned_digests:  # G2: recomputed from the tool as the model sees it NOW
            selected = getattr(event, "selected_tool", None)
            if selected is None:
                self._cancel(event, "catalog_unreadable: no selected tool to digest; the tool did not run (fail closed)")
                return
            try:
                digest = catalog.tool_digest(catalog.from_strands_spec(selected.tool_spec))
            except catalog.CatalogRefusal as refusal:
                self._cancel(event, f"{refusal.code}: the tool definition has no digest; the tool did not run (fail closed)")
                return
            if digest not in binding.pinned_digests:
                self._cancel(event, "catalog_drift: the tool definition is not the registered one; nothing was "
                                    "proposed and the tool did not run")
                return
        self._digest_of[tool_use_id] = digest
        args = arguments_object(self.agent_name, self.session_id, binding.act_type, tool_args, tool_digest=digest)
        canonical.check_arguments(args, self.gate.configured_secrets)
        act_hash = canonical.act_hash(binding.act_type, args)
        key = idempotency_key("strands", self.agent_name, self.session_id, tool_use_id, act_hash)

        # this tool use already executed (a re-entry): replay its stored body, never propose again
        replayed = self.gate.replay_stored(key, args)
        if replayed is not None:
            self._record_decision(args, binding.act_type, replayed)
            self._emit("decision", tool_use_id, verdict=replayed.verdict, code=replayed.code,
                       replayed=True, signature_checked=replayed.signature_checked)
            if replayed.allowed and self.gate.store.has_run(replayed.statement_id):
                self._cancel(event, f"statement {replayed.statement_id[:16]}... was already used; a new call needs a new approval")
                return
            self._admit(event, replayed.statement_id, replayed)
            return

        sanction = self.gate.file_or_find(binding.act_type, args, schema=binding.schema)
        self._emit("proposed" if sanction.filed_now else "found", tool_use_id,
                   request_id=sanction.request_id, act_hash=sanction.act_hash, status=sanction.status)

        if sanction.status == "pending":
            response = event.interrupt(
                INTERRUPT_NAME,
                reason={
                    "request_id": sanction.request_id,
                    "approval_url": sanction.approval_url,
                    "act_type": binding.act_type,
                    "act_hash": sanction.act_hash,
                    "arguments": args,
                },
            )
            # resumed: the response says only "look again"; the GET decides
            self._emit("resumed", tool_use_id, response=response if isinstance(response, (str, dict)) else str(response))
            sanction = self.gate.read(sanction, args)

        if sanction.status == "refused":
            self._cancel(event, f"sanction request {sanction.request_id} was refused ({sanction.refused_code})")
            return
        if sanction.status != "sanctioned":
            self._cancel(event, f"sanction request {sanction.request_id} is still {sanction.status}; awaiting approval at {sanction.approval_url}")
            return
        self.records.append({"kind": "statement", "arguments": args, "act_type": binding.act_type,
                             "record": sanction.statement, "request_id": sanction.request_id,
                             "cosignature": sanction.cosignature})
        self._emit("sanctioned", tool_use_id, request_id=sanction.request_id, statement_id=sanction.statement_id)

        if self.gate.store.has_run(sanction.statement_id):
            self._cancel(event, f"statement {sanction.statement_id[:16]}... was already used; a new call needs a new approval")
            return

        decision = self.gate.execute(sanction, args, key)
        self._record_decision(args, binding.act_type, decision)
        self._emit("decision", tool_use_id, verdict=decision.verdict, code=decision.code,
                   replayed=decision.replayed, signature_checked=decision.signature_checked)
        self._admit(event, sanction.statement_id, decision)

    def _record_decision(self, args: dict, act_type: str, decision: Decision) -> None:
        self.records.append({"kind": "decision", "arguments": args, "act_type": act_type,
                             "record": decision.decision, "verdict": decision.verdict, "code": decision.code,
                             "cosignature": decision.response.get("cosignature")})

    def _admit(self, event: BeforeToolCallEvent, statement_id: str, decision: Decision) -> None:
        if not decision.allowed:
            self._cancel(event, f"signed deny {decision.code} (statement {statement_id[:16]}...)")
            return
        if not self.gate.runnable(decision):
            self._cancel(event, f"the allow's exec_not_after ({decision.exec_not_after}) has passed")
            return
        # at most one tool use per statement, always: the claim is
        # a conditional write BEFORE the tool may run, not a mark after it ran, so two tool uses that
        # resolve to one statement before either finishes cannot both run. A tool another hook then
        # cancels has used its approval anyway (fail closed).
        # F1: the claim covers the statement AND the approval it names, in one transaction (fence.py)
        admission = self.gate.claim(decision, {"tool_use_id": event.tool_use.get("toolUseId", ""),
                                               "tool": event.tool_use.get("name"), "state": "admitted",
                                               "form": "strands"})
        if not admission.admitted:
            self._cancel(event, f"this approval was already used ({admission.code}); a new call needs a new approval")
            return
        self._allowed[event.tool_use.get("toolUseId", "")] = (statement_id, decision)
        self._args_of[event.tool_use.get("toolUseId", "")] = arguments_object(
            self.agent_name, self.session_id, decision.metadata.get("act_type"), event.tool_use.get("input"),
            tool_digest=self._digest_of.get(event.tool_use.get("toolUseId", "")))
        self._emit("allowed", event.tool_use.get("toolUseId", ""), statement_id=statement_id,
                   exec_not_after=decision.exec_not_after)

    # --- after -------------------------------------------------------------------------------------

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        tool_use_id = event.tool_use.get("toolUseId", "")
        allowed = self._allowed.pop(tool_use_id, None)
        if allowed is None or event.cancel_message is not None:
            return
        statement_id, decision = allowed  # the "ran" claim was written at admission
        self._emit("tool_ran", tool_use_id, statement_id=statement_id)
        result = event.result if isinstance(event.result, dict) else {}
        succeeded = event.exception is None and result.get("status") == "success"
        before = len(self.gate.outcome_records)
        status = self.gate.report_outcome(decision, succeeded, result.get("content"),
                                          None if succeeded else "tool_error")
        for rec in self.gate.outcome_records[before:]:
            self.records.append({"kind": "outcome", "arguments": self._args_of.get(tool_use_id),
                                 "act_type": decision.metadata.get("act_type"), "record": rec["record"],
                                 "cosignature": rec["cosignature"]})
        self._emit("outcome", tool_use_id, statement_id=statement_id,
                   outcome="succeeded" if succeeded else "failed", report=status)
