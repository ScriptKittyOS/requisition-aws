# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The adapter's idempotency store.

Why it exists: Requisition's propose has no idempotency key and no lookup by ``act_hash``
(``sanction_requests.ex:75``: no nonce member; ``v1/router.ex:114-124``: no such route), and an exact
execute retry must resend the same body, ``not_after`` included (``execute.ex:335-368``, ``:193-202``).
So the adapter remembers, before each call:

* ``proposals``: keyed on ``act_hash`` alone (the arguments object carries ``agent`` and
  ``session``). Holds the ``request_id`` filed. A record whose statement is spent (or otherwise
  closed) is moved to ``closed`` and never matched again, so a genuinely new call files anew.
* ``executes``: keyed on the call's idempotency key (``sha256(gateway | mcp_session_id |
  jsonrpc_id | act_hash)`` for the interceptor; the tool-use id for the Strands hook). Holds the
  request id and the EXACT execute body bytes; a retry replays them verbatim; a stored ``not_after``
  in the past fails closed.
* ``ran``: the "tool ran" claim per statement, written before the effect (all three forms).
* F1 (fence.py): ``positions`` (every signed record read, by its signed (chain_scope,
  sequence)), ``approvals`` (the approval-keyed spend), ``statement_approvals`` (statement id -> the
  approval it names, as read) and ``evidence`` (equivocation pairs). ``admit`` checks and writes them,
  and the claim, in ONE transaction.

The form: one local JSON file. Every mutation runs under an exclusive ``flock`` on a sidecar lock
file, re-reads the file, applies a conditional change (create-if-absent / compare-and-set), writes a
temp file, fsyncs it and ``os.replace``s it over the store (atomic on POSIX), then fsyncs the
directory. It is durable on one host only; a Lambda's /tmp is per execution environment, so the
interceptor needs a durable conditional-write store when deployed (not built here).
"""

from __future__ import annotations

import base64
import contextlib
import copy
import fcntl
import hashlib
import json
import os
import tempfile
import time
from typing import Any, Callable

from . import canonical, fence

FILING_STALE_SECONDS = 60


def idempotency_key(*parts: Any) -> str:
    """SHA-256 hex over the canonical bytes of ``parts`` (a list, so ``1`` and ``"1"`` differ).
    64 lower-case hex characters: also a valid execute nonce (``[A-Za-z0-9_-]{1,128}``)."""
    return hashlib.sha256(canonical.encode(list(parts))).hexdigest()


class StoreError(Exception):
    pass


class Store:
    NAMESPACES = ("proposals", "closed", "executes", "ran", "target_results",
                  "positions", "approvals", "statement_approvals", "evidence", "catalog_marks",
                  "catalog_marks_cleared")

    def __init__(self, path: str, clock: Callable[[], float] = time.time):
        self.path = os.path.abspath(path)
        self.clock = clock
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    # --- the primitive: read-modify-write under an exclusive lock ---------------------------------

    def _read(self) -> dict:
        try:
            with open(self.path, "rb") as handle:
                data = json.loads(handle.read() or b"{}")
        except FileNotFoundError:
            data = {}
        except ValueError as error:
            raise StoreError(f"store file is not JSON: {error}") from None
        for ns in self.NAMESPACES:
            data.setdefault(ns, {})
        return data

    def _write(self, data: dict) -> None:
        directory = os.path.dirname(self.path)
        fd, tmp = tempfile.mkstemp(prefix=".store-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(data, sort_keys=True, indent=1).encode())
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    @contextlib.contextmanager
    def _transaction(self):
        with open(self.path + ".lock", "a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                data = self._read()
                before = copy.deepcopy(data)
                yield data
                if data != before:
                    self._write(data)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def get(self, ns: str, key: str) -> Any:
        with self._transaction() as data:
            return copy.deepcopy(data[ns].get(key))

    def create_if_absent(self, ns: str, key: str, value: Any) -> tuple[bool, Any]:
        """Conditional write: store ``value`` only if ``key`` is absent. ``(created, current)``."""
        with self._transaction() as data:
            if key in data[ns]:
                return False, copy.deepcopy(data[ns][key])
            data[ns][key] = copy.deepcopy(value)
            return True, copy.deepcopy(value)

    def compare_and_set(self, ns: str, key: str, expected: Any, value: Any) -> bool:
        """Replace ``key``'s value only if it is still ``expected`` (None: absent)."""
        with self._transaction() as data:
            if data[ns].get(key) != expected:
                return False
            if value is None:
                data[ns].pop(key, None)
            else:
                data[ns][key] = copy.deepcopy(value)
            return True

    # --- catalog marks: the operator's clear ---------------------------------------------

    def clear_catalog_marks(self, gateway_id: str, tool: str) -> int:
        """In ONE transaction: every mark of ``gateway_id`` and ``tool`` (any pin; a pending re-check is not
        a mark) is APPENDED to ``catalog_marks_cleared`` as ``<mark key>:<n>`` with ``cleared_at`` (never
        overwriting an earlier clear; as requisition-ts Store.moveAppend does) and becomes
        ``catalog_recheck_pending``: nothing is approved, the next listing decides. Returns the count."""
        from .catalog import RECHECK_PENDING

        with self._transaction() as data:
            marks, cleared, now, count = data["catalog_marks"], data["catalog_marks_cleared"], self.clock(), 0
            for key in sorted(marks):
                mark = marks[key]
                if not isinstance(mark, dict) or mark.get("gateway_id") != gateway_id or mark.get("tool") != tool \
                        or mark.get("code") == RECHECK_PENDING:
                    continue
                prefix = key + ":"
                n = sum(1 for k in cleared if k.startswith(prefix)) + 1
                cleared[f"{prefix}{n:08d}"] = {**copy.deepcopy(mark), "cleared_at": now}
                marks[key] = {"gateway_id": gateway_id, "tool": tool, "pin": mark.get("pin"),
                              "code": RECHECK_PENDING, "marked_at": now}
                count += 1
            return count

    # --- proposals (dedupe on act_hash) ----------------------------------------------------

    def open_proposal(self, act_hash: str) -> dict | None:
        """The open proposal for ``act_hash``, or None. A closed (spent) one is never returned."""
        return self.get("proposals", act_hash)

    def reserve_proposal(self, act_hash: str, act_type: str) -> tuple[bool, dict]:
        """Reserve the right to file for ``act_hash`` (before the POST, so two callers never both
        file). ``(True, reservation)`` to the one that must file; ``(False, existing)`` otherwise.
        A reservation left ``filing`` for longer than FILING_STALE_SECONDS (a crash mid-file) may be
        taken over: at worst the approvers then see two requests, never a spend without approval."""
        now = self.clock()
        reservation = {"state": "filing", "act_type": act_type, "reserved_at": now, "token": os.urandom(8).hex()}
        with self._transaction() as data:
            existing = data["proposals"].get(act_hash)
            stale = (
                existing is not None
                and existing.get("state") == "filing"
                and now - existing.get("reserved_at", 0) > FILING_STALE_SECONDS
            )
            if existing is None or stale:
                if stale and existing.get("token"):
                    # the same token again: with the propose idempotency_key the server answers the
                    # request the crashed filer may already have made, instead of a second one
                    reservation["token"] = existing["token"]
                data["proposals"][act_hash] = reservation
                return True, copy.deepcopy(reservation)
            return False, copy.deepcopy(existing)

    def record_filed(self, act_hash: str, reservation: dict, request_id: str) -> dict:
        record = {
            "state": "filed",
            "act_type": reservation["act_type"],
            "request_id": request_id,
            "filed_at": self.clock(),
        }
        if not self.compare_and_set("proposals", act_hash, reservation, record):
            raise StoreError("the proposal reservation changed while filing")
        return record

    def release_reservation(self, act_hash: str, reservation: dict) -> None:
        self.compare_and_set("proposals", act_hash, reservation, None)

    def update_proposal(self, act_hash: str, request_id: str, **fields: Any) -> None:
        with self._transaction() as data:
            record = data["proposals"].get(act_hash)
            if record and record.get("request_id") == request_id:
                record.update(fields)

    def close_proposal(self, act_hash: str, request_id: str, reason: str) -> None:
        """Move the proposal out of dedupe for good (its statement is spent, refused or expired)."""
        with self._transaction() as data:
            record = data["proposals"].get(act_hash)
            if record and record.get("request_id") == request_id:
                del data["proposals"][act_hash]
                record.update(state="closed", closed_reason=reason, closed_at=self.clock())
                data["closed"][request_id] = record

    # --- executes (the exact body, replayed verbatim) ---------------------------------------------

    def claim_execute(self, key: str, request_id: str, body: bytes, not_after: str) -> tuple[bool, dict]:
        """Store the execute body under ``key`` BEFORE sending it. ``(created, record)``: if another
        invocation stored one first, its record (and bytes) win."""
        record = {
            "request_id": request_id,
            "body_b64": base64.b64encode(body).decode(),
            "not_after": not_after,
            "stored_at": self.clock(),
            "response": None,
        }
        return self.create_if_absent("executes", key, record)

    @staticmethod
    def body_of(record: dict) -> bytes:
        return base64.b64decode(record["body_b64"])

    def record_response(self, key: str, response: dict) -> None:
        with self._transaction() as data:
            record = data["executes"].get(key)
            if record is not None:
                record["response"] = response

    # --- the Strands hook's "tool ran" mark -------------------------------------------------------

    def mark_ran(self, statement_id: str, info: dict) -> bool:
        created, _ = self.create_if_absent("ran", statement_id, {**info, "ran_at": self.clock()})
        return created

    def has_run(self, statement_id: str) -> bool:
        return self.get("ran", statement_id) is not None

    # --- F1: position memory, approval-keyed spend, evidence (fence.py) -----------------------------

    def admit(self, record: dict, *, spend: dict | None = None) -> "fence.Admission":
        """ONE transaction (fence.py's two rules). ``record``: a four-field envelope whose signature the
        caller has checked. The position memory first: an unknown position is remembered; the same hash
        is known; a different hash is ``authority_equivocated``, both records saved as evidence and
        nothing else written. Then, only with ``spend`` (``{"statement_id", "approval_request_id"
        (None: the approval the statement named when it was read), **info}``, the claim before acting on
        an allow): the approval spent -> ``approval_already_used``; the statement run ->
        ``statement_already_used``; otherwise both are written with ``info``. Persisted (fsync,
        replace) before it returns."""
        scope, sequence, signed = fence.position_of(record)
        key = fence.position_key(scope, sequence)
        now = self.clock()
        with self._transaction() as data:
            held = data["positions"].get(key)
            if held is not None and held["receipt_hash"] != record["receipt_hash"]:
                entry = {"code": fence.AUTHORITY_EQUIVOCATED, "chain_scope": scope, "sequence": sequence,
                         "held": copy.deepcopy(held["record"]), "presented": copy.deepcopy(record), "at": now}
                data["evidence"].setdefault(key, [])
                if not any(e["presented"]["receipt_hash"] == record["receipt_hash"] for e in data["evidence"][key]):
                    data["evidence"][key].append(entry)
                return fence.Admission(fence.AUTHORITY_EQUIVOCATED, False, [copy.deepcopy(entry)])
            known = held is not None
            if not known:
                data["positions"][key] = {"receipt_hash": record["receipt_hash"], "record": copy.deepcopy(record),
                                          "read_at": now}
            md = signed.get("metadata") if isinstance(signed.get("metadata"), dict) else {}
            if signed.get("receipt_type") == fence.STATEMENT_TYPE and isinstance(md.get("approval_request_id"), str):
                data["statement_approvals"].setdefault(record["receipt_hash"], md["approval_request_id"])
            if spend is None:
                return fence.Admission(None, known)
            info = {k: v for k, v in spend.items() if k not in ("statement_id", "approval_request_id")}
            statement_id = spend["statement_id"]
            approval = spend.get("approval_request_id") or data["statement_approvals"].get(statement_id)
            if not approval:
                return fence.Admission(fence.APPROVAL_UNKNOWN, known)
            if approval in data["approvals"]:
                return fence.Admission(fence.APPROVAL_ALREADY_USED, known)
            if statement_id in data["ran"]:
                return fence.Admission(fence.STATEMENT_ALREADY_USED, known)
            data["approvals"][approval] = {"statement_id": statement_id, "receipt_hash": record["receipt_hash"],
                                           **info, "spent_at": now}
            data["ran"][statement_id] = {**info, "approval_request_id": approval, "ran_at": now}
            return fence.Admission(None, known)

    def position(self, chain_scope: str, sequence: int) -> str | None:
        held = self.get("positions", fence.position_key(chain_scope, sequence))
        return held["receipt_hash"] if held else None

    def evidence(self) -> list[dict]:
        with self._transaction() as data:
            return [copy.deepcopy(e) for entries in data["evidence"].values() for e in entries]

    def held_records(self) -> list[dict]:
        """Every signed record in the position memory (what a stranger's check takes as held records)."""
        with self._transaction() as data:
            return [copy.deepcopy(h["record"]) for h in data["positions"].values()]

    def approval_spent(self, approval_request_id: str) -> bool:
        return self.get("approvals", approval_request_id) is not None

    def approval_of(self, statement_id: str) -> str | None:
        return self.get("statement_approvals", statement_id)
