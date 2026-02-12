# test_policies.py — Integration tests for the seed policy YAML files.
# Verifies loading, schema validation, and engine evaluation for each policy.

from __future__ import annotations

from pathlib import Path

import pytest

from biasops.engine import PolicyEngine
from biasops.loader import load_policy
from biasops.models import (
    EnforcementMode,
    Policy,
    ReportStatus,
    RiskLevel,
)
from biasops.validator import validate_policy_file

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_POLICIES_ROOT = Path(__file__).resolve().parent.parent / "policies"

_EU_AI_ACT_HIGH_RISK = (
    _POLICIES_ROOT
    / "enterprise-compliance"
    / "eu-ai-act"
    / "eu_ai_act_high_risk_system.yaml"
)
_EU_AI_ACT_PROHIBITED = (
    _POLICIES_ROOT
    / "enterprise-compliance"
    / "eu-ai-act"
    / "eu_ai_act_prohibited_practices.yaml"
)
_GDPR_ART22 = (
    _POLICIES_ROOT
    / "enterprise-compliance"
    / "gdpr"
    / "gdpr_article22_automated_decision.yaml"
)
_EEOC_TITLE7 = (
    _POLICIES_ROOT
    / "hr-employment"
    / "hiring-bias"
    / "eeoc_title7_hiring_disparate_impact.yaml"
)

ALL_POLICY_PATHS = [_EU_AI_ACT_HIGH_RISK, _EU_AI_ACT_PROHIBITED, _GDPR_ART22, _EEOC_TITLE7]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _engine_with(policy: Policy) -> PolicyEngine:
    """Build an engine pre-loaded with a single policy (no filesystem scan)."""
    engine = PolicyEngine(policies_dir=Path("/tmp/__nonexistent_dir__"))
    engine._registry[policy.id] = policy
    return engine


# ---------------------------------------------------------------------------
# Loading tests — all policy files parse and produce valid Policy objects
# ---------------------------------------------------------------------------


class TestPolicyFileLoading:
    """Every seed policy YAML should load without errors."""

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_load_policy(self, path: Path) -> None:
        policy = load_policy(path)
        assert isinstance(policy, Policy)

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_validate_policy_schema(self, path: Path) -> None:
        result = validate_policy_file(path)
        assert result.is_valid is True, f"Schema errors: {result.errors}"

    def test_eu_ai_act_high_risk_identity(self) -> None:
        policy = load_policy(_EU_AI_ACT_HIGH_RISK)
        assert policy.id == "EU-AI-ACT-001"
        assert policy.name == "EU AI Act - High Risk AI System Obligations"
        assert policy.version == "1.0.0"
        assert policy.domain == "enterprise-compliance"
        assert policy.jurisdiction == "EU"
        assert policy.risk_level == RiskLevel.CRITICAL
        assert policy.enforcement_mode == EnforcementMode.BLOCK

    def test_eu_ai_act_prohibited_identity(self) -> None:
        policy = load_policy(_EU_AI_ACT_PROHIBITED)
        assert policy.id == "EU-AI-ACT-002"
        assert policy.name == "EU AI Act - Prohibited AI Practices"
        assert policy.risk_level == RiskLevel.CRITICAL
        assert policy.enforcement_mode == EnforcementMode.BLOCK

    def test_gdpr_art22_identity(self) -> None:
        policy = load_policy(_GDPR_ART22)
        assert policy.id == "GDPR-ART22-001"
        assert policy.jurisdiction == "EU"
        assert policy.risk_level == RiskLevel.CRITICAL

    def test_eeoc_title7_identity(self) -> None:
        policy = load_policy(_EEOC_TITLE7)
        assert policy.id == "EEOC-TITLE7-001"
        assert policy.jurisdiction == "US"
        assert policy.domain == "hr-employment"

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_maintained_by_present(self, path: Path) -> None:
        policy = load_policy(path)
        assert len(policy.maintained_by) > 0

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_regulation_references_non_empty(self, path: Path) -> None:
        policy = load_policy(path)
        assert len(policy.regulation_references) >= 1
        for ref in policy.regulation_references:
            assert ref.article
            assert ref.url.startswith("https://")

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_remediation_steps_non_empty(self, path: Path) -> None:
        policy = load_policy(path)
        assert len(policy.remediation_steps) >= 1

    @pytest.mark.parametrize("path", ALL_POLICY_PATHS, ids=lambda p: p.stem)
    def test_applies_to_populated(self, path: Path) -> None:
        """All seed policies should specify their applies_to scope."""
        policy = load_policy(path)
        assert len(policy.applies_to) >= 1


# ---------------------------------------------------------------------------
# EU AI Act — High Risk System (EU-AI-ACT-001)
# ---------------------------------------------------------------------------


class TestEuAiActHighRisk:
    """Engine evaluation tests for the EU AI Act High Risk System policy."""

    @pytest.fixture()
    def policy(self) -> Policy:
        return load_policy(_EU_AI_ACT_HIGH_RISK)

    @pytest.fixture()
    def compliant_metadata(self) -> dict:
        return {
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
            "accuracy_score": 0.85,
            "robustness_score": 0.80,
        }

    def test_fully_compliant_passes(self, policy: Policy, compliant_metadata: dict) -> None:
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS
        assert report.violations == []

    def test_fully_noncompliant_fails(self, policy: Policy) -> None:
        metadata = {
            "risk_management_system_documented": False,
            "technical_documentation_complete": False,
            "data_governance_policy_present": False,
            "human_oversight_mechanism_defined": False,
            "conformity_assessment_completed": False,
            "transparency_information_provided": False,
            "accuracy_metrics_documented": False,
            "robustness_testing_completed": False,
            "cybersecurity_measures_implemented": False,
            "post_market_monitoring_plan_present": False,
            "incident_reporting_mechanism_defined": False,
            "accuracy_score": 0.50,
            "robustness_score": 0.40,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        assert report.status == ReportStatus.FAIL
        # 11 must_be_true checks + 2 min_threshold checks = 13 violations
        assert len(report.violations) == 13

    def test_accuracy_below_threshold_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["accuracy_score"] = 0.60
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1
        assert "accuracy_score" in report.violations[0].message
        assert "below min threshold" in report.violations[0].message

    def test_robustness_below_threshold_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["robustness_score"] = 0.50
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert any("robustness_score" in v.message for v in report.violations)

    def test_accuracy_at_threshold_passes(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        """Exactly at the min threshold should pass (not strictly less)."""
        compliant_metadata["accuracy_score"] = 0.75
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS

    def test_robustness_at_threshold_passes(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["robustness_score"] = 0.70
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS

    def test_missing_human_oversight_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["human_oversight_mechanism_defined"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1
        assert "human_oversight_mechanism_defined" in report.violations[0].message

    def test_violation_severity_is_critical(self, policy: Policy) -> None:
        """All violations from this CRITICAL-risk policy should be CRITICAL."""
        engine = _engine_with(policy)
        report = engine.evaluate({"accuracy_score": 0.50})
        violations_with_severity = [
            v for v in report.violations if v.severity == RiskLevel.CRITICAL
        ]
        assert len(violations_with_severity) == len(report.violations)

    def test_violation_citation_references_eu(self, policy: Policy, compliant_metadata: dict) -> None:
        compliant_metadata["accuracy_score"] = 0.50
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert "EU" in report.violations[0].regulation_citation

    def test_remediation_steps_forwarded(self, policy: Policy, compliant_metadata: dict) -> None:
        compliant_metadata["accuracy_score"] = 0.50
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert len(report.violations[0].remediation_steps) > 0
        assert any("risk management" in s.lower() for s in report.violations[0].remediation_steps)

    def test_regulation_references_cover_key_articles(self, policy: Policy) -> None:
        articles = [ref.article for ref in policy.regulation_references]
        assert any("Article 9" in a for a in articles)
        assert any("Article 14" in a for a in articles)
        assert any("Annex III" in a for a in articles)


# ---------------------------------------------------------------------------
# EU AI Act — Prohibited Practices (EU-AI-ACT-002)
# ---------------------------------------------------------------------------


class TestEuAiActProhibited:
    """Engine evaluation tests for the EU AI Act Prohibited Practices policy."""

    @pytest.fixture()
    def policy(self) -> Policy:
        return load_policy(_EU_AI_ACT_PROHIBITED)

    @pytest.fixture()
    def compliant_metadata(self) -> dict:
        return {
            "subliminal_manipulation_techniques": False,
            "vulnerability_exploitation_present": False,
            "social_scoring_system": False,
            "realtime_biometric_surveillance_public": False,
            "emotion_recognition_workplace_school": False,
            "biometric_categorisation_sensitive_attributes": False,
            "predictive_policing_individual": False,
            "facial_recognition_database_scraping": False,
        }

    def test_fully_compliant_passes(self, policy: Policy, compliant_metadata: dict) -> None:
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS
        assert report.violations == []

    def test_fully_noncompliant_fails(self, policy: Policy) -> None:
        metadata = {
            "subliminal_manipulation_techniques": True,
            "vulnerability_exploitation_present": True,
            "social_scoring_system": True,
            "realtime_biometric_surveillance_public": True,
            "emotion_recognition_workplace_school": True,
            "biometric_categorisation_sensitive_attributes": True,
            "predictive_policing_individual": True,
            "facial_recognition_database_scraping": True,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 8

    def test_single_prohibited_practice_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["social_scoring_system"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1
        assert "social_scoring_system" in report.violations[0].message
        assert "must be false" in report.violations[0].message

    def test_subliminal_manipulation_violation(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["subliminal_manipulation_techniques"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert len(report.violations) == 1
        assert "subliminal_manipulation_techniques" in report.violations[0].message

    def test_biometric_surveillance_violation(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["realtime_biometric_surveillance_public"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert "realtime_biometric_surveillance_public" in report.violations[0].message

    def test_emotion_recognition_violation(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["emotion_recognition_workplace_school"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL

    def test_multiple_prohibited_practices(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["predictive_policing_individual"] = True
        compliant_metadata["facial_recognition_database_scraping"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 2

    def test_all_violations_are_critical(self, policy: Policy) -> None:
        metadata = {
            "subliminal_manipulation_techniques": True,
            "vulnerability_exploitation_present": True,
            "social_scoring_system": True,
            "realtime_biometric_surveillance_public": True,
            "emotion_recognition_workplace_school": True,
            "biometric_categorisation_sensitive_attributes": True,
            "predictive_policing_individual": True,
            "facial_recognition_database_scraping": True,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        for v in report.violations:
            assert v.severity == RiskLevel.CRITICAL

    def test_citation_references_article_5(self, policy: Policy, compliant_metadata: dict) -> None:
        compliant_metadata["social_scoring_system"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert "Article 5" in report.violations[0].regulation_citation

    def test_bias_types_cover_all_prohibited_categories(self, policy: Policy) -> None:
        expected = {
            "subliminal-manipulation",
            "vulnerability-exploitation",
            "social-scoring",
            "real-time-biometric-surveillance",
            "emotion-recognition-misuse",
            "biometric-categorisation-misuse",
            "predictive-policing-bias",
        }
        assert expected.issubset(set(policy.bias_types_addressed))


# ---------------------------------------------------------------------------
# GDPR Article 22 — Automated Decision-Making (GDPR-ART22-001)
# ---------------------------------------------------------------------------


class TestGdprArticle22:
    """Engine evaluation tests for the GDPR Article 22 policy."""

    @pytest.fixture()
    def policy(self) -> Policy:
        return load_policy(_GDPR_ART22)

    @pytest.fixture()
    def compliant_metadata(self) -> dict:
        return {
            "human_oversight_present": True,
            "explainability_score": 0.80,
            "right_to_contest_documented": True,
            "data_minimization_compliant": True,
            "transparency_notice_provided": True,
        }

    def test_fully_compliant_passes(self, policy: Policy, compliant_metadata: dict) -> None:
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS
        assert report.violations == []

    def test_fully_noncompliant_fails(self, policy: Policy) -> None:
        metadata = {
            "human_oversight_present": False,
            "explainability_score": 0.30,
            "right_to_contest_documented": False,
            "data_minimization_compliant": False,
            "transparency_notice_provided": False,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        assert report.status == ReportStatus.FAIL
        # 4 must_be_true checks + 1 min_threshold = 5 violations
        assert len(report.violations) == 5

    def test_explainability_below_threshold_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["explainability_score"] = 0.50
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert any("explainability_score" in v.message for v in report.violations)
        assert any("below min threshold" in v.message for v in report.violations)

    def test_explainability_at_threshold_passes(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["explainability_score"] = 0.65
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS

    def test_missing_human_oversight_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["human_oversight_present"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1
        assert "human_oversight_present" in report.violations[0].message

    def test_missing_right_to_contest_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["right_to_contest_documented"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL

    def test_citation_references_gdpr(self, policy: Policy, compliant_metadata: dict) -> None:
        compliant_metadata["human_oversight_present"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert "GDPR" in report.violations[0].regulation_citation or \
               "Article 22" in report.violations[0].regulation_citation

    def test_applies_to_automated_decisions(self, policy: Policy) -> None:
        assert "credit scoring" in policy.applies_to
        assert "hiring" in policy.applies_to


# ---------------------------------------------------------------------------
# EEOC Title VII — Hiring Disparate Impact (EEOC-TITLE7-001)
# ---------------------------------------------------------------------------


class TestEeocTitle7:
    """Engine evaluation tests for the EEOC Title VII hiring policy."""

    @pytest.fixture()
    def policy(self) -> Policy:
        return load_policy(_EEOC_TITLE7)

    @pytest.fixture()
    def compliant_metadata(self) -> dict:
        return {
            "selection_rate_disparity": 0.70,
            "demographic_proxy_variables": False,
            "adverse_action_documented": True,
            "bias_audit_completed": True,
            "protected_class_analysis_completed": True,
        }

    def test_fully_compliant_passes(self, policy: Policy, compliant_metadata: dict) -> None:
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS
        assert report.violations == []

    def test_fully_noncompliant_fails(self, policy: Policy) -> None:
        metadata = {
            "selection_rate_disparity": 0.90,
            "demographic_proxy_variables": True,
            "adverse_action_documented": False,
            "bias_audit_completed": False,
            "protected_class_analysis_completed": False,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        assert report.status == ReportStatus.FAIL
        # 1 max_threshold + 1 must_be_false + 3 must_be_true = 5 violations
        assert len(report.violations) == 5

    def test_selection_rate_above_threshold_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["selection_rate_disparity"] = 0.90
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert any("selection_rate_disparity" in v.message for v in report.violations)
        assert any("exceeds max threshold" in v.message for v in report.violations)

    def test_selection_rate_at_threshold_passes(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        """Exactly at the 0.80 threshold should pass."""
        compliant_metadata["selection_rate_disparity"] = 0.80
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.PASS

    def test_demographic_proxy_present_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["demographic_proxy_variables"] = True
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert any("demographic_proxy_variables" in v.message for v in report.violations)
        assert any("must be false" in v.message for v in report.violations)

    def test_missing_bias_audit_fails(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["bias_audit_completed"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1

    def test_all_violations_are_critical(self, policy: Policy) -> None:
        """EEOC policy is CRITICAL risk, so violations should be CRITICAL."""
        metadata = {
            "selection_rate_disparity": 0.90,
            "demographic_proxy_variables": True,
            "adverse_action_documented": False,
            "bias_audit_completed": False,
            "protected_class_analysis_completed": False,
        }
        engine = _engine_with(policy)
        report = engine.evaluate(metadata)
        for v in report.violations:
            assert v.severity == RiskLevel.CRITICAL

    def test_citation_references_title_vii(
        self, policy: Policy, compliant_metadata: dict
    ) -> None:
        compliant_metadata["bias_audit_completed"] = False
        engine = _engine_with(policy)
        report = engine.evaluate(compliant_metadata)
        citation = report.violations[0].regulation_citation
        assert "Title VII" in citation or "EEOC" in citation

    def test_applies_to_hiring_systems(self, policy: Policy) -> None:
        assert "hiring models" in policy.applies_to
        assert "resume screening" in policy.applies_to

    def test_bias_types_cover_disparate_impact(self, policy: Policy) -> None:
        assert "disparate-impact" in policy.bias_types_addressed
        assert "adverse-impact" in policy.bias_types_addressed


# ---------------------------------------------------------------------------
# Cross-policy engine tests — multiple policies loaded together
# ---------------------------------------------------------------------------


class TestCrossPolicyEvaluation:
    """Evaluation with multiple real policies loaded simultaneously."""

    @pytest.fixture()
    def engine(self) -> PolicyEngine:
        engine = PolicyEngine(policies_dir=Path("/tmp/__nonexistent_dir__"))
        for path in ALL_POLICY_PATHS:
            policy = load_policy(path)
            engine._registry[policy.id] = policy
        return engine

    def test_all_policies_loaded(self, engine: PolicyEngine) -> None:
        assert len(engine.get_loaded_policies()) == 4
        ids = {p.id for p in engine.get_loaded_policies()}
        assert ids == {"EU-AI-ACT-001", "EU-AI-ACT-002", "GDPR-ART22-001", "EEOC-TITLE7-001"}

    def test_filter_by_eu_jurisdiction(self, engine: PolicyEngine) -> None:
        report = engine.evaluate_by_jurisdiction({}, jurisdiction="EU")
        assert set(report.policies_evaluated) == {
            "EU-AI-ACT-001",
            "EU-AI-ACT-002",
            "GDPR-ART22-001",
        }

    def test_filter_by_us_jurisdiction(self, engine: PolicyEngine) -> None:
        report = engine.evaluate_by_jurisdiction({}, jurisdiction="US")
        assert report.policies_evaluated == ["EEOC-TITLE7-001"]

    def test_filter_by_enterprise_compliance_domain(self, engine: PolicyEngine) -> None:
        report = engine.evaluate_by_domain({}, domain="enterprise-compliance")
        ids = set(report.policies_evaluated)
        assert "EU-AI-ACT-001" in ids
        assert "EU-AI-ACT-002" in ids
        assert "GDPR-ART22-001" in ids
        assert "EEOC-TITLE7-001" not in ids

    def test_filter_by_hr_employment_domain(self, engine: PolicyEngine) -> None:
        report = engine.evaluate_by_domain({}, domain="hr-employment")
        assert report.policies_evaluated == ["EEOC-TITLE7-001"]

    def test_nonexistent_jurisdiction_returns_empty(self, engine: PolicyEngine) -> None:
        report = engine.evaluate_by_jurisdiction({}, jurisdiction="AU")
        assert report.status == ReportStatus.PASS
        assert report.policies_evaluated == []

    def test_full_evaluation_with_empty_metadata(self, engine: PolicyEngine) -> None:
        """All keys missing from metadata should produce PASS (skipped checks)."""
        report = engine.evaluate({})
        assert report.status == ReportStatus.PASS
        assert report.violations == []
        assert len(report.policies_evaluated) == 4
