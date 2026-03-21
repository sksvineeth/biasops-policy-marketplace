# mcp_server/tools.py — BiasOps MCP tool definitions.
#
# Five tools that expose the BiasOps runtime to any MCP-compatible agent.
# Claude calls these tools to govern itself and other agents.
#
# Tool contract: every tool returns a plain dict — structured, readable,
# and serialisable. No exceptions bubble out; errors are returned as
# structured responses the agent can reason over.

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Any

from biasops.runtime.audit import AuditStore
from biasops.runtime.enforcer import RuntimeEnforcer
from biasops.saga.attestation import (
    AgentAttestation,
    ContextScope,
    DelegationPolicy,
    ModelConstraint,
    SkillAttestation,
)
from biasops.saga.registry import AttestationRegistry
from biasops.saga.verifier import SAGAVerifier

# ---------------------------------------------------------------------------
# Shared singletons — initialised once at import time
# ---------------------------------------------------------------------------

_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"
_ATTESTATIONS_DIR = Path(__file__).resolve().parent.parent / "attestations"
_AUDIT_PATH = Path(__file__).resolve().parent.parent / "audit.jsonl"

_enforcer = RuntimeEnforcer(
    policies_dir=_POLICIES_DIR,
    attestations_dir=_ATTESTATIONS_DIR,
    audit_path=_AUDIT_PATH,
)
_attestation_registry = AttestationRegistry(attestations_dir=_ATTESTATIONS_DIR)
_verifier = SAGAVerifier(_attestation_registry)
_audit = AuditStore(path=_AUDIT_PATH)


# ---------------------------------------------------------------------------
# Tool 1 — evaluate_policy
# ---------------------------------------------------------------------------


def evaluate_policy(
    agent_id: str,
    action: str,
    jurisdiction: str = "",
    risk_level: str = "",
    model: str = "",
    environment: str = "production",
    data_type: str = "",
    automated: bool = True,
    extra_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check whether an agent is permitted to perform an action right now.

    This is the core BiasOps governance check. Call this before every
    consequential agent action. Returns ALLOW, DENY, or REQUIRE_HUMAN
    with full reasoning and an immutable audit ID.

    Args:
        agent_id:      The agent's identifier (must match its attestation).
        action:        The action/skill the agent wants to perform.
        jurisdiction:  Legal jurisdiction (e.g. "EU", "US", "UK").
        risk_level:    Risk classification (e.g. "low", "medium", "high").
        model:         Model identifier currently in use.
        environment:   Deployment environment (e.g. "production", "staging").
        data_type:     Data classification (e.g. "PII", "financial").
        automated:     True if no human is in the loop.
        extra_context: Any additional context fields.

    Returns:
        Dict with keys: decision, reasons, required_action, attestation_status,
        policies_evaluated, regulatory_refs, audit_id, latency_ms.
    """
    try:
        context: dict[str, Any] = {}
        if jurisdiction:
            context["jurisdiction"] = jurisdiction
        if risk_level:
            context["risk_level"] = risk_level
        if model:
            context["model"] = model
        if environment:
            context["environment"] = environment
        if data_type:
            context["data_type"] = data_type
        context["automated"] = automated
        if extra_context:
            context.update(extra_context)

        result = _enforcer.check(agent_id=agent_id, action=action, context=context)
        return result.to_dict()

    except Exception as exc:
        return {
            "decision": "ERROR",
            "agent_id": agent_id,
            "action": action,
            "reasons": [f"BiasOps internal error: {exc}"],
            "error": traceback.format_exc(),
        }


# ---------------------------------------------------------------------------
# Tool 2 — verify_agent
# ---------------------------------------------------------------------------


def verify_agent(
    agent_id: str,
    skill: str,
    jurisdiction: str = "",
    risk_level: str = "",
    model: str = "",
    environment: str = "",
    data_type: str = "",
) -> dict[str, Any]:
    """Check an agent's attestation status for a specific skill.

    Unlike evaluate_policy, this runs SAGA verification only — no policy
    evaluation. Use this to quickly check whether an agent is attested
    before attempting an action, or to inspect attestation details.

    Args:
        agent_id:     The agent identifier to look up.
        skill:        The skill to check attestation for.
        jurisdiction: Optional jurisdiction context.
        risk_level:   Optional risk level context.
        model:        Optional model identifier.
        environment:  Optional environment context.
        data_type:    Optional data classification.

    Returns:
        Dict with keys: status, is_authorized, reasons, agent_id, skill,
        attestation (agent metadata), skill_record (skill metadata).
    """
    try:
        context: dict[str, Any] = {}
        if jurisdiction:
            context["jurisdiction"] = jurisdiction
        if risk_level:
            context["risk_level"] = risk_level
        if model:
            context["model"] = model
        if environment:
            context["environment"] = environment
        if data_type:
            context["data_type"] = data_type

        result = _verifier.verify(agent_id=agent_id, skill=skill, context=context)
        return result.to_dict()

    except Exception as exc:
        return {
            "status": "ERROR",
            "agent_id": agent_id,
            "skill": skill,
            "is_authorized": False,
            "reasons": [f"BiasOps internal error: {exc}"],
        }


# ---------------------------------------------------------------------------
# Tool 3 — attest_skill
# ---------------------------------------------------------------------------


def attest_skill(
    agent_id: str,
    agent_version: str,
    tenant: str,
    skill: str,
    attested_by: str,
    attested_by_role: str,
    valid_days: int = 180,
    allowed_jurisdictions: list[str] | None = None,
    allowed_risk_levels: list[str] | None = None,
    approved_models: list[str] | None = None,
    prohibited_models: list[str] | None = None,
    requires_human_review: bool = False,
    delegation: str = "none",
    allowed_delegates: list[str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Register a new skill attestation for an agent.

    Creates or updates the agent's attestation file with a new skill claim.
    This is the human sign-off step — the attestor is asserting that this
    agent is authorized to perform this skill under the stated constraints.

    Args:
        agent_id:               Unique agent identifier.
        agent_version:          Agent semantic version.
        tenant:                 Organisation that owns this agent.
        skill:                  Skill name being attested.
        attested_by:            Email or ID of the human approver.
        attested_by_role:       Approver's role/title.
        valid_days:             How many days until this attestation expires.
        allowed_jurisdictions:  Jurisdictions where skill is valid (empty=all).
        allowed_risk_levels:    Risk levels permitted (empty=all).
        approved_models:        Approved model IDs (empty=any).
        prohibited_models:      Blocked model IDs.
        requires_human_review:  If True, human-in-loop required.
        delegation:             "none" | "allowlist" | "any"
        allowed_delegates:      Agent IDs that may receive delegation.
        notes:                  Free-text attestation notes.

    Returns:
        Dict with keys: success, agent_id, skill, valid_until,
        attestation_file, message.
    """
    try:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=valid_days)

        delegation_policy = DelegationPolicy(delegation)

        skill_attestation = SkillAttestation(
            name=skill,
            attested_by=attested_by,
            attested_by_role=attested_by_role,
            attested_on=now,
            valid_until=expiry,
            context_scope=ContextScope(
                jurisdictions=allowed_jurisdictions or [],
                risk_levels=allowed_risk_levels or [],
                requires_human_review=requires_human_review,
            ),
            model_constraints=ModelConstraint(
                approved=approved_models or [],
                prohibited=prohibited_models or [],
            ),
            delegation=delegation_policy,
            allowed_delegates=allowed_delegates or [],
            notes=notes,
        )

        # Load or create agent attestation
        existing = _attestation_registry.get(agent_id)
        if existing:
            # Add new skill, replacing any existing attestation for same skill
            existing_skills = [s for s in existing.skills if s.name != skill]
            updated = AgentAttestation(
                agent_id=existing.agent_id,
                tenant=existing.tenant,
                version=agent_version or existing.version,
                description=existing.description,
                owner=existing.owner,
                skills=existing_skills + [skill_attestation],
                created_at=existing.created_at,
                revoked=existing.revoked,
                revoke_reason=existing.revoke_reason,
            )
        else:
            updated = AgentAttestation(
                agent_id=agent_id,
                tenant=tenant,
                version=agent_version,
                skills=[skill_attestation],
                created_at=now,
            )

        dest = _attestation_registry.save(updated)

        return {
            "success": True,
            "agent_id": agent_id,
            "skill": skill,
            "attested_by": attested_by,
            "valid_until": expiry.isoformat(),
            "valid_days": valid_days,
            "attestation_file": str(dest),
            "message": (
                f"Skill '{skill}' attested for agent '{agent_id}' "
                f"by {attested_by} ({attested_by_role}). "
                f"Valid until {expiry.strftime('%Y-%m-%d')}."
            ),
        }

    except Exception as exc:
        return {
            "success": False,
            "agent_id": agent_id,
            "skill": skill,
            "error": str(exc),
            "message": f"Attestation failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Tool 4 — get_regulatory_coverage
# ---------------------------------------------------------------------------


def get_regulatory_coverage(
    framework: str = "EU_AI_Act",
    domain: str = "",
    agent_id: str = "",
) -> dict[str, Any]:
    """Map loaded policies to a regulatory framework's articles.

    Shows which regulatory requirements are covered by active policies,
    which are partially covered, and which have gaps. Enterprise buyers
    use this to demonstrate compliance coverage to regulators.

    Args:
        framework: Regulatory framework to map against.
                   Options: "EU_AI_Act", "NIST_RMF", "GDPR", "ECOA", "all"
        domain:    Optional domain filter (e.g. "financial-services").
        agent_id:  Optional — show coverage relevant to a specific agent.

    Returns:
        Dict with keys: framework, total_policies, coverage_map,
        covered_articles, gaps, summary.
    """
    try:
        from biasops.engine import PolicyEngine

        engine = PolicyEngine(policies_dir=_POLICIES_DIR)
        policies = engine.get_loaded_policies()

        if domain:
            policies = [p for p in policies if p.domain == domain]

        # Build coverage map: article → list of policy IDs that cover it
        coverage_map: dict[str, list[str]] = {}
        framework_lower = framework.lower().replace("_", " ").replace(" ", "")

        for policy in policies:
            for ref in policy.regulation_references:
                article_key = ref.article
                # Filter by framework if specified
                if framework.lower() not in ("all", ""):
                    ref_key = ref.article.lower().replace(" ", "").replace("_", "")
                    fw_key = framework_lower
                    # Match common framework names
                    matches = any([
                        fw_key in ref_key,
                        "euaiact" in fw_key and "euaiact" in ref_key,
                        "nist" in fw_key and "nist" in ref_key,
                        "gdpr" in fw_key and "gdpr" in ref_key,
                        "ecoa" in fw_key and "ecoa" in ref_key,
                    ])
                    if not matches:
                        continue

                if article_key not in coverage_map:
                    coverage_map[article_key] = []
                if policy.id not in coverage_map[article_key]:
                    coverage_map[article_key].append(policy.id)

        covered = sorted(coverage_map.keys())

        # Summarise by risk level
        policy_risk: dict[str, str] = {p.id: p.risk_level.value for p in policies}

        coverage_detail = []
        for article, policy_ids in sorted(coverage_map.items()):
            risks = [policy_risk.get(pid, "UNKNOWN") for pid in policy_ids]
            highest = max(
                risks,
                key=lambda r: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(r)
                if r in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else -1,
                default="UNKNOWN",
            )
            coverage_detail.append({
                "article": article,
                "covered_by": policy_ids,
                "policy_count": len(policy_ids),
                "highest_risk": highest,
            })

        return {
            "framework": framework,
            "domain_filter": domain or "all",
            "total_policies_evaluated": len(policies),
            "covered_article_count": len(covered),
            "coverage_detail": coverage_detail,
            "summary": (
                f"{len(covered)} regulatory articles covered across "
                f"{len(policies)} active policies"
                + (f" in domain '{domain}'" if domain else "")
                + "."
            ),
        }

    except Exception as exc:
        return {
            "framework": framework,
            "error": str(exc),
            "summary": f"Coverage check failed: {exc}",
        }


# ---------------------------------------------------------------------------
# Tool 5 — list_applicable_policies
# ---------------------------------------------------------------------------


def list_applicable_policies(
    jurisdiction: str = "",
    domain: str = "",
    risk_level: str = "",
    agent_id: str = "",
    action: str = "",
) -> dict[str, Any]:
    """Given a context, return all policies that would apply.

    Useful for pre-flight checks, compliance discovery, and explaining
    to an agent why certain actions require specific conditions.

    Args:
        jurisdiction: Filter by jurisdiction (e.g. "EU", "US").
        domain:       Filter by policy domain.
        risk_level:   Filter by risk level ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL").
        agent_id:     Optional — also show the agent's attestation status.
        action:       Optional — also check SAGA for this agent+action.

    Returns:
        Dict with keys: total, policies (list of policy summaries),
        agent_attestation (if agent_id provided), context.
    """
    try:
        from biasops.engine import PolicyEngine

        engine = PolicyEngine(policies_dir=_POLICIES_DIR)
        all_policies = engine.get_loaded_policies()

        # Filter
        filtered = all_policies
        if jurisdiction:
            filtered = [
                p for p in filtered
                if p.jurisdiction in (jurisdiction, "Global")
            ]
        if domain:
            filtered = [p for p in filtered if p.domain == domain]
        if risk_level:
            filtered = [
                p for p in filtered
                if p.risk_level.value == risk_level.upper()
            ]

        policy_list = [
            {
                "id": p.id,
                "name": p.name,
                "version": p.version,
                "domain": p.domain,
                "jurisdiction": p.jurisdiction,
                "risk_level": p.risk_level.value,
                "enforcement_mode": p.enforcement_mode.value,
                "regulation_refs": [
                    r.article for r in p.regulation_references
                ],
                "checks_count": len(p.checks) + len(p.policy_logic),
            }
            for p in sorted(filtered, key=lambda p: p.risk_level.value, reverse=True)
        ]

        result: dict[str, Any] = {
            "total": len(policy_list),
            "context": {
                "jurisdiction": jurisdiction or "any",
                "domain": domain or "any",
                "risk_level": risk_level or "any",
            },
            "policies": policy_list,
        }

        # SAGA check if agent + action provided
        if agent_id and action:
            context: dict[str, Any] = {}
            if jurisdiction:
                context["jurisdiction"] = jurisdiction
            saga_result = _verifier.verify(agent_id, action, context)
            result["agent_attestation"] = {
                "agent_id": agent_id,
                "action": action,
                "status": saga_result.status.value,
                "is_authorized": saga_result.is_authorized,
                "reasons": saga_result.reasons,
            }

        return result

    except Exception as exc:
        return {
            "total": 0,
            "policies": [],
            "error": str(exc),
        }
