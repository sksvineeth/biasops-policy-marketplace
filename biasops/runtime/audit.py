# runtime/audit.py — Immutable append-only audit log.
# Every BiasOps runtime check writes here — the record regulators ask for.
#
# Design principles:
#   - Append-only: entries are never modified or deleted
#   - Structured: every entry is JSON, every field is explicit
#   - Complete: enough context to reconstruct the decision without BiasOps
#   - Fast: writes must not block the enforcement path

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_AUDIT_PATH = Path(__file__).resolve().parent.parent.parent / "audit.jsonl"


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------


class AuditEntry:
    """A single immutable audit log entry.

    Every runtime check produces exactly one AuditEntry regardless of
    outcome (ALLOW, DENY, REQUIRE_HUMAN). The entry captures enough
    information to fully reconstruct the decision without BiasOps running.

    Attributes:
        audit_id:            Unique ID for this check (UUID4).
        timestamp:           UTC ISO timestamp when the check ran.
        agent_id:            Agent that requested the action.
        action:              The action the agent wanted to perform.
        context:             Runtime context passed by the agent.
        decision:            ALLOW | DENY | REQUIRE_HUMAN
        reasons:             Human-readable explanation of the decision.
        policies_evaluated:  Policy IDs that were evaluated.
        attestation_status:  SAGA verification result (VALID, EXPIRED, etc.)
        required_action:     What the agent must do instead (on DENY).
        regulatory_refs:     Regulatory articles that triggered the decision.
        policy_version:      Version of the highest-priority policy applied.
        latency_ms:          How long the check took in milliseconds.
        metadata:            Optional extra fields for extensibility.
    """

    __slots__ = (
        "audit_id",
        "timestamp",
        "agent_id",
        "action",
        "context",
        "decision",
        "reasons",
        "policies_evaluated",
        "attestation_status",
        "required_action",
        "regulatory_refs",
        "policy_version",
        "latency_ms",
        "metadata",
    )

    def __init__(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any],
        decision: str,
        reasons: list[str],
        policies_evaluated: list[str],
        attestation_status: str,
        required_action: str = "",
        regulatory_refs: list[str] | None = None,
        policy_version: str = "",
        latency_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.audit_id = f"chk_{uuid.uuid4().hex[:16]}"
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.agent_id = agent_id
        self.action = action
        self.context = context
        self.decision = decision
        self.reasons = reasons
        self.policies_evaluated = policies_evaluated
        self.attestation_status = attestation_status
        self.required_action = required_action
        self.regulatory_refs = regulatory_refs or []
        self.policy_version = policy_version
        self.latency_ms = latency_ms
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict — safe for JSON and API responses."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action": self.action,
            "context": self.context,
            "decision": self.decision,
            "reasons": self.reasons,
            "policies_evaluated": self.policies_evaluated,
            "attestation_status": self.attestation_status,
            "required_action": self.required_action,
            "regulatory_refs": self.regulatory_refs,
            "policy_version": self.policy_version,
            "latency_ms": round(self.latency_ms, 2),
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialise to a single-line JSON string for JSONL writing."""
        return json.dumps(self.to_dict(), default=str)


# ---------------------------------------------------------------------------
# Audit store
# ---------------------------------------------------------------------------


class AuditStore:
    """Append-only audit log backed by a JSONL file.

    Each line in the file is a complete, self-contained JSON object.
    The file is never truncated or rewritten — only appended to.

    In production this would be replaced with an immutable store
    (S3 + object lock, Postgres append-only table, etc.) with no
    interface changes at the call site.

    Args:
        path: Path to the ``.jsonl`` audit log file. Created if absent.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else _DEFAULT_AUDIT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Touch the file to ensure it exists
        self._path.touch(exist_ok=True)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> str:
        """Append one audit entry to the log.

        Args:
            entry: The :class:`AuditEntry` to persist.

        Returns:
            The ``audit_id`` of the written entry.
        """
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(entry.to_json() + "\n")
        except OSError as exc:
            # Log but never raise — a failing audit store must not block
            # the enforcement decision from being returned to the agent.
            logger.error("Failed to write audit entry %s: %s", entry.audit_id, exc)
        return entry.audit_id

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def read_all(self) -> list[dict[str, Any]]:
        """Return all audit entries as a list of dicts (newest last).

        Returns:
            List of entry dicts in chronological order.
        """
        entries = []
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError as exc:
                            logger.warning("Corrupt audit line skipped: %s", exc)
        except FileNotFoundError:
            pass
        return entries

    def query(
        self,
        agent_id: str | None = None,
        action: str | None = None,
        decision: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query the audit log with optional filters.

        All filters are optional and combine with AND logic.
        Results are returned newest-first, capped at ``limit``.

        Args:
            agent_id:  Filter by agent identifier.
            action:    Filter by action name.
            decision:  Filter by decision (ALLOW / DENY / REQUIRE_HUMAN).
            since:     Only entries at or after this UTC datetime.
            until:     Only entries at or before this UTC datetime.
            limit:     Maximum number of entries to return (default 100).

        Returns:
            List of matching entry dicts, newest first.
        """
        results = []
        for entry in reversed(self.read_all()):
            if agent_id and entry.get("agent_id") != agent_id:
                continue
            if action and entry.get("action") != action:
                continue
            if decision and entry.get("decision") != decision:
                continue
            if since:
                ts = datetime.fromisoformat(entry["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < since:
                    continue
            if until:
                ts = datetime.fromisoformat(entry["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts > until:
                    continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics over the full audit log.

        Returns:
            Dict with ``total``, ``by_decision``, ``by_agent``, ``by_action``.
        """
        all_entries = self.read_all()
        by_decision: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        by_action: dict[str, int] = {}

        for e in all_entries:
            d = e.get("decision", "UNKNOWN")
            by_decision[d] = by_decision.get(d, 0) + 1

            a = e.get("agent_id", "unknown")
            by_agent[a] = by_agent.get(a, 0) + 1

            act = e.get("action", "unknown")
            by_action[act] = by_action.get(act, 0) + 1

        return {
            "total": len(all_entries),
            "by_decision": by_decision,
            "by_agent": by_agent,
            "by_action": by_action,
        }
