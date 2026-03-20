# runtime/enforcer.py — BiasOps runtime enforcement.
#
# The single entry point that answers:
#   "Is this agent allowed to perform this action, in this context, right now?"
#
# Execution order:
#   1. SAGA verification — is this agent attested for this skill?
#   2. Policy evaluation — do active policies permit this action in this context?
#   3. Decision — ALLOW | DENY | REQUIRE_HUMAN
#   4. Audit — write immutable record regardless of outcome

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from biasops.engine import PolicyEngine
from biasops.runtime.audit import AuditEntry, AuditStore
from biasops.saga.attestation import AttestationStatus
from biasops.saga.registry import AttestationRegistry
from biasops.saga.verifier import SAGAVerifier, VerificationResult

logger = logging.getLogger(__name__)

_DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "policies"
_DEFAULT_ATTESTATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "attestations"
_DEFAULT_AUDIT_PATH = Path(__file__).resolve().parent.parent.parent / "audit.jsonl"


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class DecisionResult(str):
    """The three possible outcomes of a runtime check."""
    pass


ALLOW = DecisionResult("ALLOW")
DENY = DecisionResult("DENY")
REQUIRE_HUMAN = DecisionResult("REQUIRE_HUMAN")


@dataclass
class CheckResult:
    """Full output of a BiasOps runtime check.

    Attributes:
        decision:            ALLOW | DENY | REQUIRE_HUMAN
        agent_id:            Agent that was checked.
        action:              Action the agent requested.
        context:             Runtime context passed by the agent.
        reasons:             Ordered list of human-readable decision reasons.
        required_action:     What the agent must do instead (on DENY).
        policies_evaluated:  Policy IDs that were evaluated.
        attestation_status:  SAGA verification result.
        regulatory_refs:     Regulatory articles cited.
        policy_version:      Version string of the highest-priority policy.
        requires_human_review: True when SAGA scope requires human-in-loop.
        audit_id:            ID of the written audit log entry.
        latency_ms:          Total check latency in milliseconds.
    """

    decision: DecisionResult
    agent_id: str
    action: str
    context: dict[str, Any]
    reasons: list[str] = field(default_factory=list)
    required_action: str = ""
    policies_evaluated: list[str] = field(default_factory=list)
    attestation_status: str = AttestationStatus.UNKNOWN.value
    regulatory_refs: list[str] = field(default_factory=list)
    policy_version: str = ""
    requires_human_review: bool = False
    audit_id: str = ""
    latency_ms: float = 0.0

    @property
    def is_allowed(self) -> bool:
        return self.decision == ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "agent_id": self.agent_id,
            "action": self.action,
            "context": self.context,
            "reasons": self.reasons,
            "required_action": self.required_action,
            "policies_evaluated": self.policies_evaluated,
            "attestation_status": self.attestation_status,
            "regulatory_refs": self.regulatory_refs,
            "policy_version": self.policy_version,
            "requires_human_review": self.requires_human_review,
            "audit_id": self.audit_id,
            "latency_ms": round(self.latency_ms, 2),
        }


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------


class RuntimeEnforcer:
    """BiasOps runtime enforcement engine.

    Wires SAGA verification and policy evaluation together into a single
    ``check()`` call. Every check is logged to the audit store regardless
    of outcome.

    Args:
        policies_dir:      Directory containing policy YAML files.
        attestations_dir:  Directory containing attestation YAML files.
        audit_path:        Path to the append-only audit JSONL log.
        skip_saga:         If True, skip SAGA verification (useful for
                           policies-only mode in early deployment).
    """

    def __init__(
        self,
        policies_dir: str | Path | None = None,
        attestations_dir: str | Path | None = None,
        audit_path: str | Path | None = None,
        skip_saga: bool = False,
    ) -> None:
        self._engine = PolicyEngine(
            policies_dir=policies_dir or _DEFAULT_POLICIES_DIR
        )
        self._attestation_registry = AttestationRegistry(
            attestations_dir=attestations_dir or _DEFAULT_ATTESTATIONS_DIR
        )
        self._verifier = SAGAVerifier(self._attestation_registry)
        self._audit = AuditStore(path=audit_path or _DEFAULT_AUDIT_PATH)
        self._skip_saga = skip_saga

    # ------------------------------------------------------------------
    # Core public interface
    # ------------------------------------------------------------------

    def check(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Check whether an agent is allowed to perform an action right now.

        This is the single entry point for all runtime governance.
        Call this before every consequential agent action.

        Args:
            agent_id: The agent's identifier (must match its attestation).
            action:   The action/skill the agent wants to perform.
            context:  Runtime context. Relevant keys:
                        ``jurisdiction`` — e.g. "EU", "US"
                        ``risk_level``   — e.g. "low", "medium", "high"
                        ``data_type``    — e.g. "PII", "financial"
                        ``environment``  — e.g. "production", "staging"
                        ``model``        — model identifier in use
                        ``automated``    — True if no human in the loop

        Returns:
            A :class:`CheckResult` with decision, reasons, and audit ID.

        Example::

            result = enforcer.check(
                agent_id="fraud-investigator-v2",
                action="freeze_account",
                context={
                    "jurisdiction": "EU",
                    "risk_level": "high",
                    "model": "gpt-4o-validated-v2",
                    "automated": True,
                }
            )
            if not result.is_allowed:
                route_to(result.required_action)
        """
        start = time.perf_counter()
        ctx = context or {}

        # Step 1 — SAGA verification
        saga_result = self._run_saga(agent_id, action, ctx)

        # Step 2 — If SAGA hard-fails, deny immediately without policy eval
        if saga_result is not None and not saga_result.is_authorized:
            return self._build_result(
                agent_id=agent_id,
                action=action,
                context=ctx,
                decision=DENY,
                reasons=saga_result.reasons,
                required_action="Contact your model validation team to "
                                "obtain or renew attestation for this skill.",
                policies_evaluated=[],
                attestation_status=saga_result.status.value,
                requires_human_review=False,
                start=start,
            )

        attestation_status = (
            saga_result.status.value if saga_result else AttestationStatus.UNKNOWN.value
        )
        requires_human_review = saga_result.requires_human_review if saga_result else False

        # Step 3 — Build model metadata for policy evaluation
        # Only pass fields explicitly in context — don't inject defaults
        # that would incorrectly trigger deployment-scan policies at runtime.
        model_metadata = self._context_to_metadata(ctx, action, saga_result)

        # Step 4 — Policy evaluation scoped to jurisdiction when available
        jurisdiction = ctx.get("jurisdiction")
        if jurisdiction:
            report = self._engine.evaluate_by_jurisdiction(model_metadata, jurisdiction)
            # If no jurisdiction-specific policies, fall back to global ones
            if not report.policies_evaluated:
                report = self._engine.evaluate_by_jurisdiction(model_metadata, "Global")
        else:
            report = self._engine.evaluate(model_metadata)

        policies_evaluated = report.policies_evaluated
        regulatory_refs = self._extract_regulatory_refs(report.violations)
        policy_version = self._highest_policy_version(policies_evaluated)

        # Step 5 — Determine final decision
        if requires_human_review:
            decision = REQUIRE_HUMAN
            reasons = [
                f"SAGA attestation requires human review for skill '{action}'."
            ] + [v.message for v in report.violations]
            required_action = "escalate_to_human_queue"

        elif report.violations:
            blocking = [
                v for v in report.violations
                if self._is_blocking(v.policy_id, report)
            ]
            if blocking:
                decision = DENY
                reasons = [v.message for v in blocking]
                required_action = self._suggest_required_action(action, ctx)
            else:
                # Warn-only violations — allow but flag
                decision = ALLOW
                reasons = (
                    ["Action permitted with warnings."]
                    + [v.message for v in report.violations]
                )
                required_action = ""
        else:
            decision = ALLOW
            reasons = ["All SAGA and policy checks passed."]
            required_action = ""

        return self._build_result(
            agent_id=agent_id,
            action=action,
            context=ctx,
            decision=decision,
            reasons=reasons,
            required_action=required_action,
            policies_evaluated=policies_evaluated,
            attestation_status=attestation_status,
            regulatory_refs=regulatory_refs,
            policy_version=policy_version,
            requires_human_review=requires_human_review,
            start=start,
        )

    def check_delegation(
        self,
        calling_agent_id: str,
        called_agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Check whether one agent may delegate an action to another.

        Used in multi-agent pipelines to prevent unauthorized capability
        propagation through agent-to-agent calls.

        Args:
            calling_agent_id: The agent attempting to delegate.
            called_agent_id:  The agent that would receive the task.
            action:           The skill/action being delegated.
            context:          Runtime context dict.

        Returns:
            A :class:`CheckResult` for the delegation check.
        """
        start = time.perf_counter()
        ctx = context or {}

        delegation_result = self._verifier.verify_delegation(
            calling_agent_id, called_agent_id, action, ctx
        )

        if delegation_result.is_authorized:
            decision = ALLOW
            reasons = delegation_result.reasons
            required_action = ""
        else:
            decision = DENY
            reasons = delegation_result.reasons
            required_action = (
                f"Obtain delegation rights for '{called_agent_id}' "
                f"on skill '{action}' from your model validation team."
            )

        return self._build_result(
            agent_id=calling_agent_id,
            action=f"delegate:{action}→{called_agent_id}",
            context=ctx,
            decision=decision,
            reasons=reasons,
            required_action=required_action,
            policies_evaluated=[],
            attestation_status=delegation_result.status.value,
            start=start,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_saga(
        self, agent_id: str, action: str, context: dict[str, Any]
    ) -> VerificationResult | None:
        """Run SAGA verification, returning None if skip_saga is set."""
        if self._skip_saga:
            return None
        return self._verifier.verify(agent_id, action, context)

    def _context_to_metadata(
        self,
        context: dict[str, Any],
        action: str,
        saga_result: VerificationResult | None,
    ) -> dict[str, Any]:
        """Translate runtime context into policy evaluation metadata.

        Only passes fields explicitly present in context — avoids injecting
        defaults that would incorrectly trigger deployment-scan policies
        designed to evaluate static model metadata, not runtime actions.
        """
        metadata: dict[str, Any] = dict(context)

        # Surface SAGA-derived fields for policy evaluation
        if saga_result and saga_result.skill_record:
            sr = saga_result.skill_record
            metadata.setdefault("skill_attested", True)
            metadata.setdefault(
                "human_review_required",
                sr.context_scope.requires_human_review,
            )

        return metadata

    def _is_blocking(self, policy_id: str, report: Any) -> bool:
        """Return True if the policy for this violation is in block mode."""
        policy = self._engine.get_policy_by_id(policy_id)
        if policy is None:
            return True  # unknown policy — conservative default
        from biasops.models import EnforcementMode
        return policy.enforcement_mode == EnforcementMode.BLOCK

    def _extract_regulatory_refs(self, violations: list) -> list[str]:
        """Extract unique regulation citations from violations."""
        seen: set[str] = set()
        refs: list[str] = []
        for v in violations:
            if v.regulation_citation and v.regulation_citation not in seen:
                seen.add(v.regulation_citation)
                refs.append(v.regulation_citation)
        return refs

    def _highest_policy_version(self, policy_ids: list[str]) -> str:
        """Return the version of the first matched policy, or empty string."""
        for pid in policy_ids:
            p = self._engine.get_policy_by_id(pid)
            if p:
                return p.version
        return ""

    def _suggest_required_action(self, action: str, context: dict[str, Any]) -> str:
        """Suggest a remediation action based on what was denied."""
        if context.get("jurisdiction") in ("EU",):
            return "escalate_to_human_queue"
        if context.get("risk_level") == "high":
            return "escalate_to_human_queue"
        return f"request_approval_for:{action}"

    def _build_result(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any],
        decision: DecisionResult,
        reasons: list[str],
        required_action: str,
        policies_evaluated: list[str],
        attestation_status: str,
        start: float,
        regulatory_refs: list[str] | None = None,
        policy_version: str = "",
        requires_human_review: bool = False,
    ) -> CheckResult:
        """Build, log, and return the final CheckResult."""
        latency_ms = (time.perf_counter() - start) * 1000

        entry = AuditEntry(
            agent_id=agent_id,
            action=action,
            context=context,
            decision=decision,
            reasons=reasons,
            policies_evaluated=policies_evaluated,
            attestation_status=attestation_status,
            required_action=required_action,
            regulatory_refs=regulatory_refs or [],
            policy_version=policy_version,
            latency_ms=latency_ms,
        )
        audit_id = self._audit.write(entry)

        logger.info(
            "[BiasOps] %s | agent=%s action=%s audit=%s",
            decision, agent_id, action, audit_id,
        )

        return CheckResult(
            decision=decision,
            agent_id=agent_id,
            action=action,
            context=context,
            reasons=reasons,
            required_action=required_action,
            policies_evaluated=policies_evaluated,
            attestation_status=attestation_status,
            regulatory_refs=regulatory_refs or [],
            policy_version=policy_version,
            requires_human_review=requires_human_review,
            audit_id=audit_id,
            latency_ms=latency_ms,
        )
