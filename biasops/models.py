# models.py — Pydantic v2 models representing policies, violations, and evaluation reports.
# Central data definitions shared across the BiasOps Policy Marketplace codebase.

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    """Severity tiers used to classify policy risk and violation impact."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EnforcementMode(str, Enum):
    """Controls how a policy violation is handled at evaluation time.

    - **warn**: log the violation but allow the pipeline to continue.
    - **block**: halt the pipeline and require remediation before proceeding.
    - **audit**: record the violation for later review without blocking.
    """

    WARN = "warn"
    BLOCK = "block"
    AUDIT = "audit"


class ReportStatus(str, Enum):
    """Overall outcome of a policy evaluation run."""

    PASS = "PASS"
    FAIL = "FAIL"


# ---------------------------------------------------------------------------
# Helper for UUID default factories
# ---------------------------------------------------------------------------


def _uuid_str() -> str:
    """Return a new UUID4 as a string for use as a field default factory."""
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    """Return the current UTC timestamp for use as a field default factory."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class RegulationReference(BaseModel):
    """A pointer to a specific regulatory article that a policy addresses.

    Attributes:
        article:       The article or section identifier (e.g. "Article 6(1)").
        url:           A direct URL to the regulation text.
        jurisdiction:  The legal jurisdiction that issued the regulation
                       (e.g. "EU", "US-Federal", "CA").
    """

    model_config = {"frozen": True}

    article: str = Field(
        ...,
        description="Article or section identifier within the regulation.",
        examples=["Article 6(1)", "Section 5(a)"],
    )
    url: str = Field(
        ...,
        description="Direct URL to the regulation text.",
        examples=["https://eur-lex.europa.eu/eli/reg/2024/1689"],
    )
    jurisdiction: str = Field(
        ...,
        description="Legal jurisdiction that issued the regulation.",
        examples=["EU", "US-Federal"],
    )


class Policy(BaseModel):
    """A single bias-detection policy document.

    Each policy targets a specific domain and jurisdiction, references the
    regulations it helps satisfy, and declares the logic used to detect bias
    along with the enforcement behaviour when violations are found.

    Attributes:
        id:                     Unique identifier for the policy.
        name:                   Human-readable policy name.
        version:                Semantic version string (e.g. "1.0.0").
        domain:                 Application domain the policy applies to
                                (e.g. "hiring", "lending", "healthcare").
        jurisdiction:           Primary legal jurisdiction.
        regulation_references:  List of regulations this policy addresses.
        bias_types_addressed:   Bias categories covered (e.g. "gender",
                                "racial", "age").
        risk_level:             Overall risk classification.
        enforcement_mode:       Action taken when a violation is detected.
        policy_logic:           Declarative rule tree evaluated by the engine.
        remediation_steps:      Ordered list of recommended fixes.
        created_at:             Timestamp when the policy was authored.
        maintained_by:          Name or identifier of the maintainer.
        applies_to:             Optional list of model or system identifiers
                                this policy targets.
    """

    model_config = {"strict": True}

    id: str = Field(
        ...,
        description="Unique identifier for the policy.",
        examples=["pol-eu-ai-act-gender-001"],
    )
    name: str = Field(
        ...,
        description="Human-readable policy name.",
        examples=["EU AI Act Gender Bias Check"],
    )
    version: str = Field(
        ...,
        description="Semantic version string.",
        pattern=r"^\d+\.\d+\.\d+",
        examples=["1.0.0"],
    )
    domain: str = Field(
        ...,
        description="Application domain the policy applies to.",
        examples=["hiring", "lending", "healthcare"],
    )
    jurisdiction: str = Field(
        ...,
        description="Primary legal jurisdiction.",
        examples=["EU", "US-Federal"],
    )
    regulation_references: list[RegulationReference] = Field(
        ...,
        description="Regulations this policy helps satisfy.",
        min_length=1,
    )
    bias_types_addressed: list[str] = Field(
        ...,
        description="Bias categories covered by this policy.",
        min_length=1,
        examples=[["gender", "racial"]],
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Overall risk classification of the policy.",
    )
    enforcement_mode: EnforcementMode = Field(
        ...,
        description="Action taken when a violation is detected.",
    )
    policy_logic: dict = Field(
        ...,
        description="Declarative rule tree evaluated by the engine.",
    )
    remediation_steps: list[str] = Field(
        ...,
        description="Ordered list of recommended remediation actions.",
        min_length=1,
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when the policy was authored.",
    )
    maintained_by: str = Field(
        ...,
        description="Name or identifier of the policy maintainer.",
        examples=["BiasOps Core Team"],
    )
    applies_to: list[str] = Field(
        default_factory=list,
        description="Model or system identifiers this policy targets. "
        "Empty list means the policy applies universally.",
    )


class Violation(BaseModel):
    """A single policy violation produced when a check fails during evaluation.

    Created automatically by the evaluation engine whenever a policy rule
    detects non-compliance.  Each violation captures enough context —
    severity, citation, and remediation guidance — for downstream consumers
    to act on the finding.

    Attributes:
        violation_id:       Auto-generated UUID identifying this violation.
        policy_id:          The ``Policy.id`` that produced this violation.
        severity:           Impact severity of the violation.
        message:            Human-readable description of the finding.
        regulation_citation: Specific regulation article cited.
        detected_at:        UTC timestamp when the violation was detected
                            (defaults to now).
        remediation_steps:  Recommended actions to resolve the violation.
    """

    violation_id: str = Field(
        default_factory=_uuid_str,
        description="Auto-generated UUID identifying this violation.",
    )
    policy_id: str = Field(
        ...,
        description="Identifier of the policy that produced this violation.",
    )
    severity: RiskLevel = Field(
        ...,
        description="Impact severity of the violation.",
    )
    message: str = Field(
        ...,
        description="Human-readable description of the finding.",
    )
    regulation_citation: str = Field(
        ...,
        description="Specific regulation article cited for this violation.",
        examples=["EU AI Act, Article 6(1)"],
    )
    detected_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the violation was detected.",
    )
    remediation_steps: list[str] = Field(
        ...,
        description="Recommended actions to resolve the violation.",
        min_length=1,
    )


class PolicyReport(BaseModel):
    """Final output of a policy evaluation scan.

    Aggregates all violations found during a run, provides a severity
    breakdown summary, and records which policies were evaluated against
    what model metadata.

    Attributes:
        report_id:               Auto-generated UUID for this report.
        status:                  Overall PASS / FAIL outcome.
        violations:              List of violations detected during the scan.
        summary:                 Count of violations grouped by severity.
        model_metadata_snapshot: Point-in-time snapshot of the model metadata
                                 that was evaluated.
        evaluated_at:            UTC timestamp when the evaluation completed
                                 (defaults to now).
        policies_evaluated:      List of ``Policy.id`` values that were
                                 included in this evaluation run.
    """

    report_id: str = Field(
        default_factory=_uuid_str,
        description="Auto-generated UUID identifying this report.",
    )
    status: ReportStatus = Field(
        ...,
        description="Overall PASS / FAIL outcome of the evaluation.",
    )
    violations: list[Violation] = Field(
        default_factory=list,
        description="Violations detected during the scan.",
    )
    summary: dict = Field(
        default_factory=dict,
        description="Count of violations grouped by severity level.",
        examples=[{"LOW": 0, "MEDIUM": 1, "HIGH": 0, "CRITICAL": 0}],
    )
    model_metadata_snapshot: dict = Field(
        default_factory=dict,
        description="Point-in-time snapshot of evaluated model metadata.",
    )
    evaluated_at: datetime = Field(
        default_factory=_utc_now,
        description="UTC timestamp when the evaluation completed.",
    )
    policies_evaluated: list[str] = Field(
        default_factory=list,
        description="Policy identifiers included in this evaluation run.",
    )
