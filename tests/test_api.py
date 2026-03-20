# test_api.py — Tests for the FastAPI REST endpoints.

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from biasops.api import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# GET /policies
# ---------------------------------------------------------------------------


def test_list_policies_returns_list():
    r = client.get("/policies")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_policies_fields():
    r = client.get("/policies")
    policies = r.json()
    if policies:
        p = policies[0]
        for field in ("id", "name", "version", "domain", "jurisdiction", "risk_level"):
            assert field in p, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# GET /policies/{id}
# ---------------------------------------------------------------------------


def test_get_policy_not_found():
    r = client.get("/policies/NONEXISTENT-POLICY-999")
    assert r.status_code == 404


def test_get_policy_found():
    listing = client.get("/policies").json()
    if not listing:
        pytest.skip("No policies loaded")
    policy_id = listing[0]["id"]
    r = client.get(f"/policies/{policy_id}")
    assert r.status_code == 200
    assert r.json()["id"] == policy_id


# ---------------------------------------------------------------------------
# POST /validate
# ---------------------------------------------------------------------------


VALID_POLICY = {
    "id": "TEST-001",
    "name": "Test Policy",
    "version": "1.0.0",
    "domain": "hiring",
    "jurisdiction": "US",
    "risk_level": "HIGH",
    "enforcement_mode": "block",
    "maintained_by": "Test Team",
    "bias_types_addressed": ["gender"],
    "regulation_references": [
        {
            "article": "Title VII",
            "url": "https://example.com",
            "jurisdiction": "US",
        }
    ],
    "policy_logic": {"selection_rate_min_threshold": 0.80},
    "remediation_steps": ["Fix it."],
    "created_at": "2026-01-01T00:00:00Z",
}


def test_validate_valid_policy():
    r = client.post("/validate", json={"policy": VALID_POLICY})
    assert r.status_code == 200
    body = r.json()
    assert body["is_valid"] is True
    assert body["errors"] == []


def test_validate_missing_required_field():
    bad = {k: v for k, v in VALID_POLICY.items() if k != "name"}
    r = client.post("/validate", json={"policy": bad})
    assert r.status_code == 200
    body = r.json()
    assert body["is_valid"] is False
    assert len(body["errors"]) > 0


def test_validate_empty_policy():
    r = client.post("/validate", json={"policy": {}})
    assert r.status_code == 200
    assert r.json()["is_valid"] is False


# ---------------------------------------------------------------------------
# POST /evaluate
# ---------------------------------------------------------------------------

PASSING_METADATA = {
    "adverse_impact_ratio": 0.90,
    "demographic_parity": 0.04,
    "has_bias_audit": True,
    "human_oversight_present": True,
    "explainability_score": 0.80,
    "right_to_contest_documented": True,
    "data_minimization_compliant": True,
    "transparency_notice_provided": True,
    "selection_rate_disparity": 0.90,
    "demographic_proxy_variables": False,
    "adverse_action_documented": True,
    "bias_audit_completed": True,
    "protected_class_analysis_completed": True,
    # EU AI Act fields
    "risk_management_system_documented": True,
    "technical_documentation_complete": True,
    "data_governance_policy_present": True,
    "human_oversight_mechanism_defined": True,
    "conformity_assessment_completed": True,
    "transparency_information_provided": True,
    "accuracy_metrics_documented": True,
    "robustness_testing_completed": True,
    "cybersecurity_measures_implemented": True,
    "post_market_monitoring_plan_present": True,
    "incident_reporting_mechanism_defined": True,
    "accuracy_score": 0.90,
    "robustness_score": 0.85,
    "automatic_logging_enabled": True,
    "quality_management_system_documented": True,
    "eu_ai_act_database_registered": True,
    "training_data_bias_assessment_completed": True,
    "dataset_representativeness_documented": True,
    "ai_disclosure_mechanism_implemented": True,
    "toxicity_evaluation_completed_if_generative": True,
    # ECOA fields
    "adverse_impact_ratio_min_threshold": 0.85,
    "statistical_significance_max_threshold": 0.03,
    "demographic_proxy_variables_must_be_false": False,
    "lda_search_documented": True,
}

FAILING_METADATA = {
    "adverse_impact_ratio": 0.60,
    "demographic_parity": 0.20,
    "has_bias_audit": False,
    "human_oversight_present": False,
    "explainability_score": 0.30,
    "right_to_contest_documented": False,
    "selection_rate_disparity": 0.50,
    "demographic_proxy_variables": True,
}


def test_evaluate_returns_report():
    r = client.post("/evaluate", json={"model_metadata": PASSING_METADATA})
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "violations" in body
    assert "policies_evaluated" in body
    assert "summary" in body


def test_evaluate_failing_metadata_has_violations():
    r = client.post("/evaluate", json={"model_metadata": FAILING_METADATA})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "FAIL"
    assert len(body["violations"]) > 0


# ---------------------------------------------------------------------------
# POST /evaluate/domain
# ---------------------------------------------------------------------------


def test_evaluate_by_domain_valid():
    r = client.post(
        "/evaluate/domain",
        json={"model_metadata": FAILING_METADATA, "domain": "financial-services"},
    )
    # 200 if policies exist for that domain, 404 if not
    assert r.status_code in (200, 404)


def test_evaluate_by_domain_unknown():
    r = client.post(
        "/evaluate/domain",
        json={"model_metadata": {}, "domain": "nonexistent-domain-xyz"},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /evaluate/jurisdiction
# ---------------------------------------------------------------------------


def test_evaluate_by_jurisdiction_eu():
    r = client.post(
        "/evaluate/jurisdiction",
        json={"model_metadata": FAILING_METADATA, "jurisdiction": "EU"},
    )
    assert r.status_code in (200, 404)


def test_evaluate_by_jurisdiction_unknown():
    r = client.post(
        "/evaluate/jurisdiction",
        json={"model_metadata": {}, "jurisdiction": "MARS"},
    )
    assert r.status_code == 404

