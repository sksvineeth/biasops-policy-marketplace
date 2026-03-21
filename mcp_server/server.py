# mcp_server/server.py — BiasOps MCP server.
#
# Exposes BiasOps governance as MCP tools callable by Claude and any
# MCP-compatible agent. Run with:
#
#   python -m mcp_server.server
#   or: biasops-mcp (after pip install)
#
# Claude Desktop config (~/.claude_desktop_config.json):
# {
#   "mcpServers": {
#     "biasops": {
#       "command": "python",
#       "args": ["-m", "mcp_server.server"],
#       "cwd": "/path/to/biasops-policy-marketplace"
#     }
#   }
# }

from __future__ import annotations

from fastmcp import FastMCP

from mcp_server.tools import (
    attest_skill,
    evaluate_policy,
    get_regulatory_coverage,
    list_applicable_policies,
    verify_agent,
)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="BiasOps",
    instructions=(
        "BiasOps is the AI governance runtime. Use these tools to check "
        "whether an agent is authorized to perform an action before it acts. "
        "\n\n"
        "Typical workflow:\n"
        "1. Call evaluate_policy before any consequential action.\n"
        "2. If DENY — use the required_action field to route correctly.\n"
        "3. If REQUIRE_HUMAN — escalate before proceeding.\n"
        "4. If ALLOW — proceed. The audit_id proves governance was enforced.\n"
        "\n"
        "Use verify_agent to inspect attestation status without running "
        "full policy evaluation. Use list_applicable_policies to discover "
        "which rules apply to a given context. Use get_regulatory_coverage "
        "to produce compliance reports for regulators."
    ),
)


# ---------------------------------------------------------------------------
# Register tools
# ---------------------------------------------------------------------------

@mcp.tool(
    description=(
        "Check whether an agent is permitted to perform an action right now. "
        "Returns ALLOW, DENY, or REQUIRE_HUMAN with full reasoning and an "
        "immutable audit ID. Call this before every consequential agent action. "
        "On DENY, use required_action to determine next steps."
    )
)
def evaluate_policy_tool(
    agent_id: str,
    action: str,
    jurisdiction: str = "",
    risk_level: str = "",
    model: str = "",
    environment: str = "production",
    data_type: str = "",
    automated: bool = True,
) -> dict:
    """Evaluate whether an agent action is permitted under active policies."""
    return evaluate_policy(
        agent_id=agent_id,
        action=action,
        jurisdiction=jurisdiction,
        risk_level=risk_level,
        model=model,
        environment=environment,
        data_type=data_type,
        automated=automated,
    )


@mcp.tool(
    description=(
        "Check an agent's attestation status for a specific skill. "
        "Returns VALID, EXPIRED, REVOKED, OUT_OF_SCOPE, or UNKNOWN. "
        "Use this to inspect attestation details without running full "
        "policy evaluation."
    )
)
def verify_agent_tool(
    agent_id: str,
    skill: str,
    jurisdiction: str = "",
    risk_level: str = "",
    model: str = "",
    environment: str = "",
) -> dict:
    """Verify an agent's attestation for a specific skill."""
    return verify_agent(
        agent_id=agent_id,
        skill=skill,
        jurisdiction=jurisdiction,
        risk_level=risk_level,
        model=model,
        environment=environment,
    )


@mcp.tool(
    description=(
        "Register a new skill attestation for an agent — the human sign-off "
        "step. Creates or updates the agent's attestation file. The attestor "
        "is asserting this agent is authorized to perform this skill under "
        "the stated constraints."
    )
)
def attest_skill_tool(
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
) -> dict:
    """Attest a skill for an agent."""
    return attest_skill(
        agent_id=agent_id,
        agent_version=agent_version,
        tenant=tenant,
        skill=skill,
        attested_by=attested_by,
        attested_by_role=attested_by_role,
        valid_days=valid_days,
        allowed_jurisdictions=allowed_jurisdictions,
        allowed_risk_levels=allowed_risk_levels,
        approved_models=approved_models,
        prohibited_models=prohibited_models,
        requires_human_review=requires_human_review,
        delegation=delegation,
        allowed_delegates=allowed_delegates,
        notes=notes,
    )


@mcp.tool(
    description=(
        "Map loaded policies to a regulatory framework's articles. "
        "Shows which requirements are covered and which have gaps. "
        "Use this to produce compliance reports for regulators or auditors. "
        "Supported frameworks: EU_AI_Act, NIST_RMF, GDPR, ECOA, all."
    )
)
def get_regulatory_coverage_tool(
    framework: str = "EU_AI_Act",
    domain: str = "",
) -> dict:
    """Get regulatory coverage map for a framework."""
    return get_regulatory_coverage(framework=framework, domain=domain)


@mcp.tool(
    description=(
        "Given a context, return all policies that would apply. "
        "Use this for pre-flight compliance discovery, or to explain "
        "to an agent why certain actions require specific conditions. "
        "Optionally include agent_id and action to also check attestation status."
    )
)
def list_applicable_policies_tool(
    jurisdiction: str = "",
    domain: str = "",
    risk_level: str = "",
    agent_id: str = "",
    action: str = "",
) -> dict:
    """List all policies applicable to a given context."""
    return list_applicable_policies(
        jurisdiction=jurisdiction,
        domain=domain,
        risk_level=risk_level,
        agent_id=agent_id,
        action=action,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
