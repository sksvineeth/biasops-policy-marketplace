# test_mcp.py — Tests for the five BiasOps MCP tools.
# Tests call the tool functions directly (not over the MCP transport).

from __future__ import annotations


from mcp_server.tools import (
    attest_skill,
    evaluate_policy,
    get_regulatory_coverage,
    list_applicable_policies,
    verify_agent,
)


# ---------------------------------------------------------------------------
# Tool 1: evaluate_policy
# ---------------------------------------------------------------------------


def test_evaluate_policy_returns_decision():
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="summarize_transaction",
        environment="production",
    )
    assert "decision" in r
    assert r["decision"] in ("ALLOW", "DENY", "REQUIRE_HUMAN", "ERROR")
    assert "audit_id" in r
    assert "reasons" in r


def test_evaluate_policy_eu_freeze_denied():
    """Core demo scenario — EU freeze must be DENY."""
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        jurisdiction="EU",
        risk_level="high",
        model="gpt-4o-validated-v2",
        automated=True,
    )
    assert r["decision"] == "DENY"
    assert r["attestation_status"] == "OUT_OF_SCOPE"


def test_evaluate_policy_us_freeze_allowed():
    """Core demo scenario — US low-risk freeze must be ALLOW."""
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        jurisdiction="US",
        risk_level="low",
        model="gpt-4o-validated-v2",
        environment="production",
        data_type="financial",
    )
    assert r["decision"] == "ALLOW"
    assert r["attestation_status"] == "VALID"


def test_evaluate_policy_prohibited_model_denied():
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        jurisdiction="US",
        risk_level="low",
        model="gpt-4o-latest",
        environment="production",
        data_type="financial",
    )
    assert r["decision"] == "DENY"
    assert "gpt-4o-latest" in " ".join(r["reasons"])


def test_evaluate_policy_unknown_agent_denied():
    r = evaluate_policy(
        agent_id="ghost-agent-not-real",
        action="freeze_account",
    )
    assert r["decision"] == "DENY"
    assert r["attestation_status"] == "UNKNOWN"


def test_evaluate_policy_has_audit_id():
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="summarize_transaction",
        environment="production",
    )
    assert r["audit_id"].startswith("chk_")


def test_evaluate_policy_has_latency():
    r = evaluate_policy(
        agent_id="fraud-investigator-v2",
        action="summarize_transaction",
        environment="production",
    )
    assert r["latency_ms"] > 0


# ---------------------------------------------------------------------------
# Tool 2: verify_agent
# ---------------------------------------------------------------------------


def test_verify_agent_valid():
    r = verify_agent(
        agent_id="fraud-investigator-v2",
        skill="summarize_transaction",
        environment="production",
    )
    assert r["status"] == "VALID"
    assert r["is_authorized"] is True


def test_verify_agent_eu_freeze_out_of_scope():
    r = verify_agent(
        agent_id="fraud-investigator-v2",
        skill="freeze_account",
        jurisdiction="EU",
    )
    assert r["status"] == "OUT_OF_SCOPE"
    assert r["is_authorized"] is False
    assert len(r["reasons"]) > 0


def test_verify_agent_unknown_returns_unknown():
    r = verify_agent(agent_id="nonexistent-agent", skill="any_skill")
    assert r["status"] == "UNKNOWN"
    assert r["is_authorized"] is False


def test_verify_agent_unknown_skill():
    r = verify_agent(
        agent_id="fraud-investigator-v2",
        skill="do_something_not_attested",
    )
    assert r["status"] == "UNKNOWN"
    assert r["is_authorized"] is False


def test_verify_agent_has_attestation_metadata():
    r = verify_agent(
        agent_id="fraud-investigator-v2",
        skill="summarize_transaction",
        environment="production",
    )
    assert r["attestation"] is not None
    assert r["attestation"]["agent_id"] == "fraud-investigator-v2"
    assert r["skill_record"] is not None
    assert r["skill_record"]["name"] == "summarize_transaction"


# ---------------------------------------------------------------------------
# Tool 3: attest_skill
# ---------------------------------------------------------------------------


def test_attest_skill_creates_attestation():
    r = attest_skill(
        agent_id="test-agent-mcp-001",
        agent_version="1.0.0",
        tenant="test-org",
        skill="summarize_report",
        attested_by="tester@example.com",
        attested_by_role="Test Lead",
        valid_days=30,
        notes="Created by MCP test suite.",
    )
    assert r["success"] is True
    assert r["agent_id"] == "test-agent-mcp-001"
    assert r["skill"] == "summarize_report"
    assert "valid_until" in r
    assert "attestation_file" in r


def test_attest_skill_with_constraints():
    r = attest_skill(
        agent_id="test-agent-mcp-002",
        agent_version="1.0.0",
        tenant="test-org",
        skill="flag_transaction",
        attested_by="compliance@example.com",
        attested_by_role="Compliance Officer",
        valid_days=90,
        allowed_jurisdictions=["US", "UK"],
        allowed_risk_levels=["low", "medium"],
        approved_models=["gpt-4o-validated-v2"],
        prohibited_models=["gpt-4o-latest"],
        requires_human_review=False,
    )
    assert r["success"] is True

    # Verify it can now be looked up
    v = verify_agent(
        agent_id="test-agent-mcp-002",
        skill="flag_transaction",
        jurisdiction="US",
        risk_level="low",
    )
    assert v["status"] == "VALID"


def test_attest_skill_with_delegation():
    r = attest_skill(
        agent_id="test-agent-mcp-003",
        agent_version="1.0.0",
        tenant="test-org",
        skill="escalate_case",
        attested_by="manager@example.com",
        attested_by_role="Operations Manager",
        valid_days=60,
        delegation="allowlist",
        allowed_delegates=["human-review-agent-v1"],
    )
    assert r["success"] is True


def test_attest_skill_out_of_jurisdiction_denied_after():
    attest_skill(
        agent_id="test-agent-mcp-004",
        agent_version="1.0.0",
        tenant="test-org",
        skill="restricted_action",
        attested_by="approver@example.com",
        attested_by_role="Risk Lead",
        valid_days=30,
        allowed_jurisdictions=["US"],  # EU excluded
    )
    v = verify_agent(
        agent_id="test-agent-mcp-004",
        skill="restricted_action",
        jurisdiction="EU",
    )
    assert v["status"] == "OUT_OF_SCOPE"


# ---------------------------------------------------------------------------
# Tool 4: get_regulatory_coverage
# ---------------------------------------------------------------------------


def test_coverage_eu_ai_act():
    r = get_regulatory_coverage(framework="EU_AI_Act")
    assert "coverage_detail" in r
    assert r["covered_article_count"] > 0
    assert "EU AI Act" in r["summary"] or r["covered_article_count"] > 0


def test_coverage_gdpr():
    r = get_regulatory_coverage(framework="GDPR")
    assert "coverage_detail" in r
    assert r["total_policies_evaluated"] > 0


def test_coverage_all_frameworks():
    r = get_regulatory_coverage(framework="all")
    assert r["covered_article_count"] > 0


def test_coverage_with_domain_filter():
    r = get_regulatory_coverage(framework="all", domain="financial-services")
    assert r["domain_filter"] == "financial-services"
    # All evaluated policies should be financial-services
    assert r["total_policies_evaluated"] > 0


def test_coverage_returns_policy_ids():
    r = get_regulatory_coverage(framework="EU_AI_Act")
    for item in r["coverage_detail"]:
        assert "article" in item
        assert "covered_by" in item
        assert isinstance(item["covered_by"], list)


# ---------------------------------------------------------------------------
# Tool 5: list_applicable_policies
# ---------------------------------------------------------------------------


def test_list_applicable_no_filter():
    r = list_applicable_policies()
    assert "total" in r
    assert "policies" in r
    assert r["total"] > 0


def test_list_applicable_eu_filter():
    r = list_applicable_policies(jurisdiction="EU")
    assert r["total"] > 0
    for p in r["policies"]:
        assert p["jurisdiction"] in ("EU", "Global")


def test_list_applicable_domain_filter():
    r = list_applicable_policies(domain="financial-services")
    assert r["total"] > 0
    for p in r["policies"]:
        assert p["domain"] == "financial-services"


def test_list_applicable_with_agent_check():
    r = list_applicable_policies(
        jurisdiction="EU",
        agent_id="fraud-investigator-v2",
        action="freeze_account",
    )
    assert "agent_attestation" in r
    assert r["agent_attestation"]["agent_id"] == "fraud-investigator-v2"
    assert r["agent_attestation"]["status"] == "OUT_OF_SCOPE"


def test_list_applicable_critical_only():
    r = list_applicable_policies(risk_level="CRITICAL")
    for p in r["policies"]:
        assert p["risk_level"] == "CRITICAL"


def test_list_applicable_policy_fields():
    r = list_applicable_policies(jurisdiction="EU")
    for p in r["policies"]:
        for field in ("id", "name", "version", "domain", "risk_level",
                      "enforcement_mode", "regulation_refs"):
            assert field in p, f"Missing field '{field}' in policy {p.get('id')}"
