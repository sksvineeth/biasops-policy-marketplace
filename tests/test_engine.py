# test_engine.py — Tests for the PolicyEngine evaluation logic.

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from biasops.engine import PolicyEngine
from biasops.models import (
    EnforcementMode,
    Policy,
    PolicyReport,
    ReportStatus,
    RiskLevel,
    Violation,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_BASE_POLICY_DICT: dict = {
    "id": "pol-test-001",
    "name": "Test Policy",
    "version": "1.0.0",
    "domain": "hiring",
    "jurisdiction": "EU",
    "regulation_references": [
        {
            "article": "Article 6(1)",
            "url": "https://eur-lex.europa.eu/eli/reg/2024/1689",
            "jurisdiction": "EU",
        }
    ],
    "bias_types_addressed": ["gender"],
    "risk_level": "HIGH",
    "enforcement_mode": "block",
    "policy_logic": {},
    "remediation_steps": ["Retrain with balanced data"],
    "created_at": "2024-06-01T00:00:00Z",
    "maintained_by": "BiasOps Core Team",
}


def _make_policy(overrides: dict | None = None) -> Policy:
    """Create a Policy from the base dict, merging *overrides*."""
    data = {**_BASE_POLICY_DICT, **(overrides or {})}
    return Policy.model_validate(data, strict=False)


def _write_policy_yaml(path: Path, overrides: dict | None = None) -> Path:
    """Write a minimal valid policy YAML to *path* and return it."""
    import yaml

    data = {**_BASE_POLICY_DICT, **(overrides or {})}
    path.write_text(yaml.dump(data, sort_keys=False), encoding="utf-8")
    return path


def _engine_with(*policies: Policy) -> PolicyEngine:
    """Build an engine with a pre-loaded registry (no filesystem needed)."""
    engine = PolicyEngine(policies_dir=Path("/tmp/__nonexistent_dir__"))
    for p in policies:
        engine._registry[p.id] = p
    return engine


# ---------------------------------------------------------------------------
# Init / registry
# ---------------------------------------------------------------------------


class TestEngineInit:
    """PolicyEngine construction and registry helpers."""

    def test_loads_from_directory(self, tmp_path: Path) -> None:
        """Policies in the directory should be loaded at init time."""
        _write_policy_yaml(tmp_path / "a.yaml", {"id": "pol-a"})
        _write_policy_yaml(tmp_path / "b.yaml", {"id": "pol-b"})

        engine = PolicyEngine(policies_dir=tmp_path)
        assert len(engine.get_loaded_policies()) == 2
        assert {p.id for p in engine.get_loaded_policies()} == {"pol-a", "pol-b"}

    def test_missing_directory_starts_empty(self, tmp_path: Path) -> None:
        """A non-existent directory should produce an empty engine."""
        engine = PolicyEngine(policies_dir=tmp_path / "nope")
        assert engine.get_loaded_policies() == []

    def test_load_single_policy(self, tmp_path: Path) -> None:
        """load_policy() should add a policy to the registry."""
        engine = PolicyEngine(policies_dir=tmp_path / "nope")
        _write_policy_yaml(tmp_path / "new.yaml", {"id": "pol-new"})
        policy = engine.load_policy(tmp_path / "new.yaml")
        assert policy.id == "pol-new"
        assert engine.get_policy_by_id("pol-new") is policy

    def test_get_policy_by_id_returns_none(self) -> None:
        """A missing id should return None."""
        engine = _engine_with()
        assert engine.get_policy_by_id("nonexistent") is None


# ---------------------------------------------------------------------------
# evaluate() — full sweep
# ---------------------------------------------------------------------------


class TestEvaluate:
    """Tests for evaluate() over all loaded policies."""

    def test_pass_when_all_below_max(self) -> None:
        """Model values under the max threshold should produce PASS."""
        policy = _make_policy({
            "id": "pol-max",
            "enforcement_mode": "block",
            "policy_logic": {"demographic_parity_max_threshold": 0.2},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"demographic_parity": 0.1})

        assert isinstance(report, PolicyReport)
        assert report.status == ReportStatus.PASS
        assert report.violations == []
        assert "pol-max" in report.policies_evaluated

    def test_fail_when_above_max_block(self) -> None:
        """A value exceeding max threshold on a block policy should FAIL."""
        policy = _make_policy({
            "id": "pol-block",
            "enforcement_mode": "block",
            "policy_logic": {"demographic_parity_max_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"demographic_parity": 0.5})

        assert report.status == ReportStatus.FAIL
        assert len(report.violations) == 1
        assert report.violations[0].policy_id == "pol-block"
        assert report.summary["HIGH"] == 1

    def test_warn_policy_violation_is_still_pass(self) -> None:
        """Violations from a warn policy should NOT set status to FAIL."""
        policy = _make_policy({
            "id": "pol-warn",
            "enforcement_mode": "warn",
            "policy_logic": {"demographic_parity_max_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"demographic_parity": 0.5})

        assert report.status == ReportStatus.PASS
        assert len(report.violations) == 1

    def test_audit_policy_violation_is_still_pass(self) -> None:
        """Violations from an audit policy should NOT set status to FAIL."""
        policy = _make_policy({
            "id": "pol-audit",
            "enforcement_mode": "audit",
            "policy_logic": {"demographic_parity_max_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"demographic_parity": 0.5})

        assert report.status == ReportStatus.PASS
        assert len(report.violations) == 1

    def test_no_policies_returns_pass(self) -> None:
        """An empty engine should return PASS with no violations."""
        engine = _engine_with()
        report = engine.evaluate({"anything": 42})

        assert report.status == ReportStatus.PASS
        assert report.violations == []
        assert report.policies_evaluated == []

    def test_report_contains_metadata_snapshot(self) -> None:
        """The report should carry a copy of the input metadata."""
        engine = _engine_with()
        meta = {"score": 0.9}
        report = engine.evaluate(meta)
        assert report.model_metadata_snapshot == meta

    def test_summary_counts_by_severity(self) -> None:
        """Summary dict should correctly tally violations by severity."""
        p1 = _make_policy({
            "id": "pol-high",
            "risk_level": "HIGH",
            "enforcement_mode": "block",
            "policy_logic": {"metric_a_max_threshold": 0.1},
        })
        p2 = _make_policy({
            "id": "pol-crit",
            "enforcement_mode": "warn",
            "policy_logic": {"metric_b_block_threshold": 0.1},
        })
        engine = _engine_with(p1, p2)
        report = engine.evaluate({"metric_a": 0.5, "metric_b": 0.5})

        assert report.summary["HIGH"] == 1
        assert report.summary["CRITICAL"] == 1


# ---------------------------------------------------------------------------
# Threshold suffix variants
# ---------------------------------------------------------------------------


class TestThresholdSuffixes:
    """Each suffix type should trigger (or not) correctly."""

    def test_max_threshold_pass(self) -> None:
        """Value at exactly the threshold should pass (not strictly greater)."""
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"score_max_threshold": 0.5},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"score": 0.5})
        assert report.violations == []

    def test_max_threshold_fail(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"score_max_threshold": 0.5},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"score": 0.6})
        assert len(report.violations) == 1
        assert "exceeds max threshold" in report.violations[0].message

    def test_min_threshold_pass(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"coverage_min_threshold": 0.8},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"coverage": 0.9})
        assert report.violations == []

    def test_min_threshold_fail(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"coverage_min_threshold": 0.8},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"coverage": 0.5})
        assert len(report.violations) == 1
        assert "below min threshold" in report.violations[0].message

    def test_must_be_true_pass(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"has_bias_audit_must_be_true": True},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"has_bias_audit": True})
        assert report.violations == []

    def test_must_be_true_fail(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"has_bias_audit_must_be_true": True},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"has_bias_audit": False})
        assert len(report.violations) == 1
        assert "must be true" in report.violations[0].message

    def test_must_be_false_pass(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"uses_prohibited_feature_must_be_false": False},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"uses_prohibited_feature": False})
        assert report.violations == []

    def test_must_be_false_fail(self) -> None:
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"uses_prohibited_feature_must_be_false": False},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"uses_prohibited_feature": True})
        assert len(report.violations) == 1
        assert "must be false" in report.violations[0].message

    def test_block_threshold_severity_is_critical(self) -> None:
        """_block_threshold violations should always be CRITICAL."""
        policy = _make_policy({
            "id": "p",
            "risk_level": "LOW",
            "policy_logic": {"score_block_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"score": 0.5})
        assert report.violations[0].severity == RiskLevel.CRITICAL

    def test_warn_threshold_severity_is_high(self) -> None:
        """_warn_threshold violations should always be HIGH."""
        policy = _make_policy({
            "id": "p",
            "risk_level": "LOW",
            "policy_logic": {"score_warn_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"score": 0.5})
        assert report.violations[0].severity == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# Violation details
# ---------------------------------------------------------------------------


class TestViolationDetails:
    """Violations should carry correct citation and remediation data."""

    def test_regulation_citation(self) -> None:
        """Citation should be built from the policy's regulation references."""
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"bias_score_max_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"bias_score": 0.5})
        v = report.violations[0]
        assert "EU" in v.regulation_citation
        assert "Article 6(1)" in v.regulation_citation

    def test_remediation_steps_from_policy(self) -> None:
        """Violation remediation_steps should come from the originating policy."""
        policy = _make_policy({
            "id": "p",
            "remediation_steps": ["Step A", "Step B"],
            "policy_logic": {"bias_score_max_threshold": 0.1},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"bias_score": 0.5})
        assert report.violations[0].remediation_steps == ["Step A", "Step B"]

    def test_violation_has_auto_generated_id(self) -> None:
        """Each violation should get a unique UUID."""
        policy = _make_policy({
            "id": "p",
            "policy_logic": {"x_max_threshold": 0.0, "y_max_threshold": 0.0},
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"x": 1, "y": 1})
        ids = [v.violation_id for v in report.violations]
        assert len(set(ids)) == 2  # unique


# ---------------------------------------------------------------------------
# evaluate_by_domain / evaluate_by_jurisdiction
# ---------------------------------------------------------------------------


class TestFilteredEvaluation:
    """Domain and jurisdiction filtering."""

    def test_evaluate_by_domain_only_matching(self) -> None:
        """Only policies whose domain matches should run."""
        hiring = _make_policy({
            "id": "pol-hiring",
            "domain": "hiring",
            "policy_logic": {"score_max_threshold": 0.1},
        })
        lending = _make_policy({
            "id": "pol-lending",
            "domain": "lending",
            "policy_logic": {"score_max_threshold": 0.1},
        })
        engine = _engine_with(hiring, lending)
        report = engine.evaluate_by_domain({"score": 0.5}, domain="hiring")

        assert report.policies_evaluated == ["pol-hiring"]
        assert len(report.violations) == 1
        assert report.violations[0].policy_id == "pol-hiring"

    def test_evaluate_by_domain_no_match(self) -> None:
        """A domain with no policies should produce PASS and empty list."""
        policy = _make_policy({"id": "pol-hiring", "domain": "hiring"})
        engine = _engine_with(policy)
        report = engine.evaluate_by_domain({}, domain="healthcare")
        assert report.status == ReportStatus.PASS
        assert report.policies_evaluated == []

    def test_evaluate_by_jurisdiction_only_matching(self) -> None:
        """Only policies whose jurisdiction matches should run."""
        eu = _make_policy({
            "id": "pol-eu",
            "jurisdiction": "EU",
            "policy_logic": {"score_max_threshold": 0.1},
        })
        us = _make_policy({
            "id": "pol-us",
            "jurisdiction": "US-Federal",
            "policy_logic": {"score_max_threshold": 0.1},
        })
        engine = _engine_with(eu, us)
        report = engine.evaluate_by_jurisdiction({"score": 0.5}, jurisdiction="EU")

        assert report.policies_evaluated == ["pol-eu"]
        assert len(report.violations) == 1
        assert report.violations[0].policy_id == "pol-eu"

    def test_evaluate_by_jurisdiction_no_match(self) -> None:
        """A jurisdiction with no policies should produce PASS."""
        policy = _make_policy({"id": "pol-eu", "jurisdiction": "EU"})
        engine = _engine_with(policy)
        report = engine.evaluate_by_jurisdiction({}, jurisdiction="AU")
        assert report.status == ReportStatus.PASS
        assert report.policies_evaluated == []


# ---------------------------------------------------------------------------
# Missing metadata keys
# ---------------------------------------------------------------------------


class TestMissingMetadata:
    """Missing metadata keys should be skipped with a warning log."""

    def test_missing_key_skipped_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A metric absent from metadata should log a warning and skip."""
        policy = _make_policy({
            "id": "pol-missing",
            "policy_logic": {"nonexistent_metric_max_threshold": 0.1},
        })
        engine = _engine_with(policy)

        with caplog.at_level(logging.WARNING, logger="biasops.engine"):
            report = engine.evaluate({})

        assert report.violations == []
        assert any("nonexistent_metric" in r.message for r in caplog.records)

    def test_present_keys_still_evaluated(self) -> None:
        """Keys that are present should still be checked even when others are missing."""
        policy = _make_policy({
            "id": "pol-mixed",
            "policy_logic": {
                "missing_key_max_threshold": 0.1,
                "present_key_max_threshold": 0.1,
            },
        })
        engine = _engine_with(policy)
        report = engine.evaluate({"present_key": 0.5})

        assert len(report.violations) == 1
        assert report.violations[0].message.startswith("'present_key'")


# ---------------------------------------------------------------------------
# Multiple policies / mixed scenarios
# ---------------------------------------------------------------------------


class TestMultiplePolicies:
    """Evaluation across several policies at once."""

    def test_multiple_policies_aggregated(self) -> None:
        """Violations from different policies should all appear in one report."""
        p1 = _make_policy({
            "id": "pol-1",
            "enforcement_mode": "warn",
            "policy_logic": {"a_max_threshold": 0.0},
        })
        p2 = _make_policy({
            "id": "pol-2",
            "enforcement_mode": "block",
            "policy_logic": {"b_max_threshold": 0.0},
        })
        engine = _engine_with(p1, p2)
        report = engine.evaluate({"a": 1, "b": 1})

        assert len(report.violations) == 2
        assert report.status == ReportStatus.FAIL  # because pol-2 is block
        assert set(report.policies_evaluated) == {"pol-1", "pol-2"}

    def test_block_and_warn_mix(self) -> None:
        """A mix where only the warn policy fires should still be PASS."""
        block_ok = _make_policy({
            "id": "pol-block-ok",
            "enforcement_mode": "block",
            "policy_logic": {"safe_max_threshold": 0.5},
        })
        warn_bad = _make_policy({
            "id": "pol-warn-bad",
            "enforcement_mode": "warn",
            "policy_logic": {"risky_max_threshold": 0.1},
        })
        engine = _engine_with(block_ok, warn_bad)
        report = engine.evaluate({"safe": 0.1, "risky": 0.5})

        assert report.status == ReportStatus.PASS
        assert len(report.violations) == 1
        assert report.violations[0].policy_id == "pol-warn-bad"
