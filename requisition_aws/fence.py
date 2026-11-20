# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The relying party's own memory, kept outside Requisition's rollback domain (F1). The state lives in
the adapter's Store; ``Store.admit`` is the one atomic operation (store.py). This module holds the
vocabulary.

Two rules, nothing else:

* **Position memory (evidence).** Every signed record the relying party reads (the statement, the
  decision, the outcome record) is remembered by its SIGNED ``(chain_scope, sequence)`` (both inside
  the signed bytes) together with the record itself. A record
  presented at a remembered position with a different ``receipt_hash`` is refused
  ``authority_equivocated``, and both records are saved as one evidence entry: two records signed by
  the lab key at one chain position, which anyone can check offline (``bin/verify_chain.py`` reads the
  entry as a held input). There is NO ordering rule: the lab's chain is the whole account's (every
  caller, the console's mints, registry records), so gaps and older positions are normal and prove
  nothing.
* **Approval-keyed spend (prevention).** Before acting on an allow, the relying party claims the
  statement AND the signed ``approval_request_id`` its statement names. A rolled-back service that
  re-mints a new statement for an approval this relying party already acted on is refused
  ``approval_already_used``; the statement-keyed claim alone cannot see a re-mint (a new statement id).

Check order: signatures (the gate) -> position memory -> at the claim, the approval -> the
statement. Everything is persisted in one transaction before the effect.

WHAT IT CLAIMS, AND WHERE: the memory is the Store's file. It holds for an executor whose store
survives: the Strands hook in the agent's own process and the local Gateway target and interceptor
runs. A Lambda's or an AgentCore Runtime microVM's ``/tmp`` is per environment, so the deployed
interceptor and target make NO rollback claim until their store is durable (for example
DynamoDB). It covers the executor that already acted: a different executor with its own store never saw
the first use (open until decisions name their one audience).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .client import RequisitionError, loads_strict

AUTHORITY_EQUIVOCATED = "authority_equivocated"
APPROVAL_ALREADY_USED = "approval_already_used"
STATEMENT_ALREADY_USED = "statement_already_used"
APPROVAL_UNKNOWN = "approval_unknown"
STATEMENT_TYPE = "requisition.lab.statement.v0"


@dataclass
class Admission:
    code: str | None = None  # None: admitted
    known: bool = False  # this exact record was already held
    evidence: list = field(default_factory=list)  # the evidence entries this call wrote

    @property
    def admitted(self) -> bool:
        return self.code is None


class FenceRefused(RequisitionError):
    """The relying party's own memory refuses: never act on it."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


MESSAGES = {
    AUTHORITY_EQUIVOCATED: "Requisition signed a different record at a chain position this relying party already "
                           "holds (both kept as evidence); refused",
    APPROVAL_ALREADY_USED: "this approval was already acted on here; a re-minted statement for it is refused",
    STATEMENT_ALREADY_USED: "this statement was already acted on here",
    APPROVAL_UNKNOWN: "the approval this statement names is not known here; refused (fail closed)",
}


def refuse(code: str) -> FenceRefused:
    return FenceRefused(code, MESSAGES.get(code, "refused"))


def position_of(record: dict) -> tuple[str, int, dict]:
    """``(chain_scope, sequence, signed)`` from the SIGNED payload (never from any other member)."""
    signed = loads_strict(record["signed_payload"])  # duplicate members refused (ValueError)
    if not isinstance(signed, dict):
        raise ValueError("the signed payload is not a JSON object")
    scope, sequence = signed.get("chain_scope"), signed.get("sequence")
    if not isinstance(scope, str) or not scope or isinstance(sequence, bool) or not isinstance(sequence, int):
        raise ValueError("the signed record carries no chain position")
    return scope, sequence, signed


def position_key(chain_scope: str, sequence: int) -> str:
    import json

    return json.dumps([chain_scope, sequence], separators=(",", ":"))
