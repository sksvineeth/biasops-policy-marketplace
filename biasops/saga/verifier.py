# saga/verifier.py — SAGA runtime verifier.
# The single function that answers:
#   "Is this agent authorized to perform this skill in this context right now?"
#
# Called by the runtime enforcer before policy evaluation.
# Fast, deterministic, fully logged.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from biasops.saga.attestation import (
    AgentAttestation,
    AttestationStatus,
    DelegationPolicy,
    SkillAttestation,
)
from biasops.saga.registry import AttestationRegistry


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Output of a SAGA verification check.

    Attributes:
        status:         The attestation status (VALID, EXPIRED, OUT_OF_SCOPE …).
        agent_id:       The agent that was checked.
        skill:          The skill that was checked.
        context:        The runtime context that was evaluated.
        reasons:        List of human-readable reasons for the status.
        attestation:    The AgentAttestation found, if any.
        skill_record:   The SkillAttestation found, if any.
        requires_human_review: Whether the scope requires human review.
        checked_at:     UTC timestamp of the check.
    """

    status: AttestationStatus
    agent_id: str
    skill: str
    context: dict[str, Any]
    reasons: list[str] = field(default_factory=list)
    attestation: AgentAttestation | None = None
    skill_record: SkillAttestation | None = None
    requires_human_review: bool = False
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_authorized(self) -> bool:
        """Return True only when status is VALID."""
        return self.status == AttestationStatus.VALID

    def to_dict(self) -> dict:
        """Serialise to a plain dict for logging and API responses."""
        return {
            "status": self.status.value,
            "agent_id": self.agent_id,
            "skill": self.skill,
            "is_authorized": self.is_authorized,
            "reasons": self.reasons,
            "requires_human_review": self.requires_human_review,
            "checked_at": self.checked_at.isoformat(),
            "attestation": {
                "agent_id": self.attestation.agent_id,
                "version": self.attestation.version,
                "tenant": self.attestation.tenant,
                "revoked": self.attestation.revoked,
            } if self.attestation else None,
            "skill_record": {
                "name": self.skill_record.name,
                "attested_by": self.skill_record.attested_by,
                "attested_by_role": self.skill_record.attested_by_role,
                "valid_until": self.skill_record.valid_until.isoformat(),
                "delegation": self.skill_record.delegation.value,
            } if self.skill_record else None,
        }


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class SAGAVerifier:
    """Runtime verifier that checks agent skill attestations.

    Runs a sequence of checks in order, short-circuiting on the first
    failure. All checks are logged for the audit trail.

    Check sequence:
        1. Agent exists in registry
        2. Agent is not revoked
        3. Agent has the requested skill
        4. Skill is not expired
        5. Runtime context is within the skill's scope
        6. Model in use is approved for this skill (if provided in context)

    Args:
        registry: The :class:`AttestationRegistry` to look up agents from.
    """

    def __init__(self, registry: AttestationRegistry) -> None:
        self._registry = registry

    def verify(
        self,
        agent_id: str,
        skill: str,
        context: dict[str, Any] | None = None,
    ) -> VerificationResult:
        """Verify that an agent is authorized to perform a skill in a context.

        Args:
            agent_id: The agent's self-reported identifier.
            skill:    The skill/action the agent wants to perform.
            context:  Runtime context dict. Relevant keys:
                      ``jurisdiction``, ``risk_level``, ``data_type``,
                      ``environment``, ``model`` (model identifier).

        Returns:
            A :class:`VerificationResult` with status and full reasoning.
        """
        ctx = context or {}

        # 1. Agent lookup
        attestation = self._registry.get(agent_id)
        if attestation is None:
            return VerificationResult(
                status=AttestationStatus.UNKNOWN,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Agent '{agent_id}' not found in attestation registry. "
                    "Register the agent before it can be authorized to act."
                ],
            )

        # 2. Revocation check
        if attestation.revoked:
            reason = attestation.revoke_reason or "No reason provided."
            return VerificationResult(
                status=AttestationStatus.REVOKED,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=[f"Agent '{agent_id}' has been revoked. Reason: {reason}"],
                attestation=attestation,
            )

        # 3. Skill lookup
        skill_record = attestation.get_skill(skill)
        if skill_record is None:
            available = attestation.skill_names()
            return VerificationResult(
                status=AttestationStatus.UNKNOWN,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Skill '{skill}' is not attested for agent '{agent_id}'. "
                    f"Attested skills: {available or ['none']}."
                ],
                attestation=attestation,
            )

        # 4. Expiry check
        if skill_record.is_expired():
            return VerificationResult(
                status=AttestationStatus.EXPIRED,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Attestation for skill '{skill}' expired on "
                    f"{skill_record.valid_until.isoformat()}. "
                    "Re-attestation required before this skill can be used."
                ],
                attestation=attestation,
                skill_record=skill_record,
            )

        # 5. Context scope check
        if not skill_record.is_in_scope(ctx):
            scope = skill_record.context_scope
            reasons = [
                f"Skill '{skill}' is out of scope for the provided context."
            ]
            if scope.jurisdictions and ctx.get("jurisdiction") not in scope.jurisdictions:
                reasons.append(
                    f"Jurisdiction '{ctx.get('jurisdiction')}' not in "
                    f"allowed list: {scope.jurisdictions}."
                )
            if scope.risk_levels and ctx.get("risk_level") not in scope.risk_levels:
                reasons.append(
                    f"Risk level '{ctx.get('risk_level')}' not in "
                    f"allowed list: {scope.risk_levels}."
                )
            if scope.data_types and ctx.get("data_type") not in scope.data_types:
                reasons.append(
                    f"Data type '{ctx.get('data_type')}' not in "
                    f"allowed list: {scope.data_types}."
                )
            if scope.environments and ctx.get("environment") not in scope.environments:
                reasons.append(
                    f"Environment '{ctx.get('environment')}' not in "
                    f"allowed list: {scope.environments}."
                )
            return VerificationResult(
                status=AttestationStatus.OUT_OF_SCOPE,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=reasons,
                attestation=attestation,
                skill_record=skill_record,
            )

        # 6. Model constraint check
        model_id = ctx.get("model")
        if model_id and not skill_record.model_constraints.allows(model_id):
            constraints = skill_record.model_constraints
            return VerificationResult(
                status=AttestationStatus.OUT_OF_SCOPE,
                agent_id=agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Model '{model_id}' is not approved for skill '{skill}'. "
                    f"Approved: {constraints.approved or ['any']}. "
                    f"Prohibited: {constraints.prohibited}."
                ],
                attestation=attestation,
                skill_record=skill_record,
            )

        # All checks passed
        return VerificationResult(
            status=AttestationStatus.VALID,
            agent_id=agent_id,
            skill=skill,
            context=ctx,
            reasons=["All attestation checks passed."],
            attestation=attestation,
            skill_record=skill_record,
            requires_human_review=skill_record.context_scope.requires_human_review,
        )

    def verify_delegation(
        self,
        calling_agent_id: str,
        called_agent_id: str,
        skill: str,
        context: dict[str, Any] | None = None,
    ) -> VerificationResult:
        """Verify that one agent may delegate a skill to another agent.

        This is the multi-agent chain control. In a pipeline where Agent A
        calls Agent B, both must be verified: A must have delegation rights,
        and B must be on A's allowlist (or delegation=ANY).

        Args:
            calling_agent_id: The agent attempting to delegate.
            called_agent_id:  The agent receiving the delegation.
            skill:            The skill being delegated.
            context:          Runtime context dict.

        Returns:
            A :class:`VerificationResult` for the delegation check.
        """
        ctx = context or {}

        # First verify the calling agent has the skill itself
        caller_result = self.verify(calling_agent_id, skill, ctx)
        if not caller_result.is_authorized:
            return VerificationResult(
                status=caller_result.status,
                agent_id=calling_agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Calling agent '{calling_agent_id}' is not authorized for "
                    f"skill '{skill}' — cannot delegate what it cannot do."
                ] + caller_result.reasons,
                attestation=caller_result.attestation,
                skill_record=caller_result.skill_record,
            )

        skill_record = caller_result.skill_record
        assert skill_record is not None  # guaranteed by is_authorized

        # Check delegation policy
        if skill_record.delegation == DelegationPolicy.NONE:
            return VerificationResult(
                status=AttestationStatus.OUT_OF_SCOPE,
                agent_id=calling_agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Skill '{skill}' has delegation=NONE — "
                    f"agent '{calling_agent_id}' cannot delegate this skill "
                    f"to '{called_agent_id}' or any other agent."
                ],
                attestation=caller_result.attestation,
                skill_record=skill_record,
            )

        if skill_record.delegation == DelegationPolicy.ALLOWLIST:
            if called_agent_id not in skill_record.allowed_delegates:
                return VerificationResult(
                    status=AttestationStatus.OUT_OF_SCOPE,
                    agent_id=calling_agent_id,
                    skill=skill,
                    context=ctx,
                    reasons=[
                        f"Agent '{called_agent_id}' is not in the allowed delegates "
                        f"list for skill '{skill}'. "
                        f"Allowed: {skill_record.allowed_delegates}."
                    ],
                    attestation=caller_result.attestation,
                    skill_record=skill_record,
                )

        # delegation=ANY or called_agent_id is on the allowlist
        # Also verify the called agent can actually perform the skill
        called_result = self.verify(called_agent_id, skill, ctx)
        if not called_result.is_authorized:
            return VerificationResult(
                status=called_result.status,
                agent_id=called_agent_id,
                skill=skill,
                context=ctx,
                reasons=[
                    f"Called agent '{called_agent_id}' is not authorized for "
                    f"skill '{skill}' — delegation target must also be attested."
                ] + called_result.reasons,
                attestation=called_result.attestation,
                skill_record=called_result.skill_record,
            )

        return VerificationResult(
            status=AttestationStatus.VALID,
            agent_id=called_agent_id,
            skill=skill,
            context=ctx,
            reasons=[
                f"Delegation from '{calling_agent_id}' to '{called_agent_id}' "
                f"for skill '{skill}' is authorized."
            ],
            attestation=called_result.attestation,
            skill_record=called_result.skill_record,
            requires_human_review=called_result.requires_human_review,
        )
