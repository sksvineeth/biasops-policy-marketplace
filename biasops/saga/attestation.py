# saga/attestation.py — Skill Attestation and Governance Architecture (SAGA)
# Core schema for agent identity and capability claims.
#
# An Attestation is a signed human assertion that:
#   "Agent X is authorized to perform Skill Y in Context Z
#    using Model M, validated by Person P, valid until Date D."
#
# This is the patent core. Nothing else in the market formalizes
# per-skill, per-context, per-model authorization for AI agents
# with human sign-off and expiry.

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AttestationStatus(str, Enum):
    """Current validity state of an attestation."""

    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"   # agent/skill exists but context doesn't match
    UNKNOWN = "UNKNOWN"             # agent or skill not found in registry


class DelegationPolicy(str, Enum):
    """Controls whether an agent can delegate a skill to another agent.

    This governs multi-agent chains — Agent A calling Agent B.
    Without delegation control, governance only covers the entry point.
    """

    NONE = "none"           # cannot delegate this skill to any agent
    ALLOWLIST = "allowlist" # can only delegate to agents listed in allowed_delegates
    ANY = "any"             # can delegate to any attested agent (use with caution)


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class ContextScope(BaseModel):
    """Defines the deployment contexts in which a skill attestation is valid.

    All fields are optional — omitting a field means "no restriction on
    this dimension." Supplying a value means the runtime context must
    match one of the listed values for the attestation to be considered
    in-scope.

    Attributes:
        jurisdictions:   Allowed legal jurisdictions (e.g. ``["US", "EU"]``).
        risk_levels:     Allowed risk classifications (e.g. ``["low", "medium"]``).
        data_types:      Allowed data classifications (e.g. ``["PII", "financial"]``).
        environments:    Allowed deployment environments (e.g. ``["production"]``).
        requires_human_review: If True, a human must review before action executes.
    """

    model_config = {"frozen": True}

    jurisdictions: list[str] = Field(
        default_factory=list,
        description="Allowed jurisdictions. Empty = no restriction.",
        examples=[["US", "UK"]],
    )
    risk_levels: list[str] = Field(
        default_factory=list,
        description="Allowed risk levels. Empty = no restriction.",
        examples=[["low", "medium"]],
    )
    data_types: list[str] = Field(
        default_factory=list,
        description="Allowed data classifications. Empty = no restriction.",
        examples=[["PII", "financial"]],
    )
    environments: list[str] = Field(
        default_factory=list,
        description="Allowed deployment environments. Empty = no restriction.",
        examples=[["production", "staging"]],
    )
    requires_human_review: bool = Field(
        default=False,
        description="If True, human review is required before this skill executes.",
    )


class ModelConstraint(BaseModel):
    """Specifies which models are approved or prohibited for a skill.

    Attributes:
        approved:   Model identifiers explicitly approved for this skill.
                    Empty list means any model is approved (use with caution).
        prohibited: Model identifiers explicitly prohibited. Takes precedence
                    over approved — a model in both lists is denied.
    """

    model_config = {"frozen": True}

    approved: list[str] = Field(
        default_factory=list,
        description="Approved model identifiers. Empty = any model allowed.",
        examples=[["gpt-4o-validated-v2", "claude-3-5-sonnet"]],
    )
    prohibited: list[str] = Field(
        default_factory=list,
        description="Prohibited model identifiers. Overrides approved list.",
        examples=[["gpt-4o-latest"]],
    )

    def allows(self, model_id: str) -> bool:
        """Return True if model_id is permitted under these constraints.

        Args:
            model_id: The model identifier to check.

        Returns:
            False if model_id is in prohibited. True if approved is empty
            (any model allowed) or model_id is in approved.
        """
        if model_id in self.prohibited:
            return False
        if not self.approved:
            return True
        return model_id in self.approved


class SkillAttestation(BaseModel):
    """A single attested skill — one capability of an agent.

    Each skill has its own scope, model constraints, delegation policy,
    and expiry. An agent can have many skills; each is independently
    attested and independently enforceable.

    Attributes:
        name:               Skill identifier (e.g. ``"freeze_account"``).
        description:        What this skill does.
        attested_by:        Email or ID of the human who validated this skill.
        attested_by_role:   Their role/title for audit purposes.
        attested_on:        When the attestation was granted.
        valid_until:        Expiry — after this date the skill is EXPIRED.
        context_scope:      Deployment contexts where this skill is valid.
        model_constraints:  Approved/prohibited models for this skill.
        delegation:         Whether this skill can be delegated to other agents.
        allowed_delegates:  If delegation=ALLOWLIST, which agent IDs may receive.
        notes:              Free-text notes for audit trail.
    """

    name: str = Field(
        ...,
        description="Skill identifier matching the action name the agent performs.",
        examples=["freeze_account", "file_sar_report", "summarize_document"],
    )
    description: str = Field(
        default="",
        description="Human-readable description of what this skill does.",
    )
    attested_by: str = Field(
        ...,
        description="Email or identifier of the human who approved this skill.",
        examples=["sarah.chen@jpmorgan.com"],
    )
    attested_by_role: str = Field(
        default="",
        description="Role or title of the attestor for audit purposes.",
        examples=["Model Validation Lead", "Chief Risk Officer"],
    )
    attested_on: datetime = Field(
        ...,
        description="UTC timestamp when the attestation was granted.",
    )
    valid_until: datetime = Field(
        ...,
        description="UTC expiry timestamp. After this, status becomes EXPIRED.",
    )
    context_scope: ContextScope = Field(
        default_factory=ContextScope,
        description="Deployment contexts in which this skill is valid.",
    )
    model_constraints: ModelConstraint = Field(
        default_factory=ModelConstraint,
        description="Model approval/prohibition rules for this skill.",
    )
    delegation: DelegationPolicy = Field(
        default=DelegationPolicy.NONE,
        description="Whether this skill can be delegated to other agents.",
    )
    allowed_delegates: list[str] = Field(
        default_factory=list,
        description="Agent IDs allowed to receive delegation. "
        "Only used when delegation=ALLOWLIST.",
    )
    notes: str = Field(
        default="",
        description="Free-text notes for the audit trail.",
    )

    @model_validator(mode="after")
    def validate_delegation_allowlist(self) -> SkillAttestation:
        """Ensure allowed_delegates is set when delegation=ALLOWLIST."""
        if self.delegation == DelegationPolicy.ALLOWLIST and not self.allowed_delegates:
            raise ValueError(
                f"Skill '{self.name}': delegation=ALLOWLIST requires "
                "at least one entry in allowed_delegates."
            )
        return self

    @model_validator(mode="after")
    def validate_dates(self) -> SkillAttestation:
        """Ensure attested_on is before valid_until."""
        if self.attested_on >= self.valid_until:
            raise ValueError(
                f"Skill '{self.name}': attested_on must be before valid_until."
            )
        return self

    def is_expired(self) -> bool:
        """Return True if the attestation has passed its valid_until date."""
        return datetime.now(timezone.utc) > self.valid_until

    def is_in_scope(self, context: dict[str, Any]) -> bool:
        """Return True if the provided runtime context matches this scope.

        Checks each constrained dimension. An empty list means no restriction
        on that dimension — any value passes.

        Args:
            context: Runtime context dict from the agent. Expected keys:
                     ``jurisdiction``, ``risk_level``, ``data_type``,
                     ``environment``.

        Returns:
            True if context satisfies all scope constraints.
        """
        scope = self.context_scope

        if scope.jurisdictions:
            if context.get("jurisdiction") not in scope.jurisdictions:
                return False

        if scope.risk_levels:
            if context.get("risk_level") not in scope.risk_levels:
                return False

        if scope.data_types:
            if context.get("data_type") not in scope.data_types:
                return False

        if scope.environments:
            if context.get("environment") not in scope.environments:
                return False

        return True


# ---------------------------------------------------------------------------
# Agent attestation — the top-level object
# ---------------------------------------------------------------------------


class AgentAttestation(BaseModel):
    """Complete attestation record for an AI agent.

    One YAML file per agent. Contains agent identity metadata and the
    full list of attested skills. Each skill is independently scoped
    and independently enforceable.

    Attributes:
        agent_id:    Unique agent identifier matching what agents self-report.
        tenant:      Organisation or team that owns this agent.
        version:     Agent version string — attestations are version-specific.
        description: What this agent does.
        owner:       Team or person responsible for this agent.
        skills:      List of attested skills, each with its own scope and expiry.
        created_at:  When this attestation record was created.
        revoked:     If True, all skills are treated as REVOKED regardless of expiry.
        revoke_reason: Why the agent was revoked.
    """

    agent_id: str = Field(
        ...,
        description="Unique identifier for the agent.",
        examples=["fraud-investigator-v2"],
    )
    tenant: str = Field(
        ...,
        description="Organisation or team that owns and operates this agent.",
        examples=["jpmorgan-prod", "acme-compliance"],
    )
    version: str = Field(
        ...,
        description="Agent version — attestations are version-specific.",
        examples=["2.1.4"],
    )
    description: str = Field(
        default="",
        description="What this agent does and where it is deployed.",
    )
    owner: str = Field(
        default="",
        description="Team or person responsible for this agent.",
        examples=["fraud-risk-engineering@jpmorgan.com"],
    )
    skills: list[SkillAttestation] = Field(
        default_factory=list,
        description="Attested skills. Each skill is independently scoped.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when this attestation record was created.",
    )
    revoked: bool = Field(
        default=False,
        description="If True, all skills are REVOKED regardless of individual expiry.",
    )
    revoke_reason: str = Field(
        default="",
        description="Reason for revocation — populated when revoked=True.",
    )

    def get_skill(self, skill_name: str) -> SkillAttestation | None:
        """Return the SkillAttestation for a given skill name, or None."""
        for skill in self.skills:
            if skill.name == skill_name:
                return skill
        return None

    def skill_names(self) -> list[str]:
        """Return all attested skill names for this agent."""
        return [s.name for s in self.skills]
