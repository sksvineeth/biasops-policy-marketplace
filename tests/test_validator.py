# test_validator.py — Tests for schema validation, file validation, directory
# scanning, and cross-policy conflict detection.

from pathlib import Path

import pytest

from biasops.models import Policy
from biasops.validator import (
    ConflictWarning,
    ValidationResult,
    detect_conflicts,
    validate_all_policies,
    validate_policy_file,
    validate_policy_schema,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_POLICY_DICT: dict = {
    "id": "pol-test-001",
    "name": "Test Gender Bias Policy",
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
    "policy_logic": {
        "operator": "and",
        "rules": [
            {"metric": "demographic_parity", "threshold": 0.1, "operator": "less_than"}
        ],
    },
    "remediation_steps": ["Retrain with balanced data"],
    "created_at": "2024-06-01T00:00:00Z",
    "maintained_by": "BiasOps Core Team",
}

VALID_POLICY_YAML = """\
id: pol-test-001
name: Test Gender Bias Policy
version: "1.0.0"
domain: hiring
jurisdiction: EU
regulation_references:
  - article: "Article 6(1)"
    url: "https://eur-lex.europa.eu/eli/reg/2024/1689"
    jurisdiction: EU
bias_types_addressed:
  - gender
risk_level: HIGH
enforcement_mode: block
policy_logic:
  operator: and
  rules:
    - metric: demographic_parity
      threshold: 0.1
      operator: less_than
remediation_steps:
  - Retrain with balanced data
created_at: "2024-06-01T00:00:00Z"
maintained_by: BiasOps Core Team
"""


def _make_policy(
    *,
    id: str = "pol-001",
    jurisdiction: str = "EU",
    metric: str = "demographic_parity",
    threshold: float = 0.1,
) -> Policy:
    """Build a minimal Policy with one rule for conflict-detection tests."""
    return Policy.model_validate(
        {
            **VALID_POLICY_DICT,
            "id": id,
            "jurisdiction": jurisdiction,
            "policy_logic": {
                "operator": "and",
                "rules": [{"metric": metric, "threshold": threshold}],
            },
        },
        strict=False,
    )


# ---------------------------------------------------------------------------
# validate_policy_schema
# ---------------------------------------------------------------------------


class TestValidatePolicySchema:
    """Tests for validate_policy_schema()."""

    def test_valid_dict_passes(self) -> None:
        """A complete, well-formed dict should be valid with no errors."""
        result = validate_policy_schema(VALID_POLICY_DICT)
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert result.errors == []

    def test_empty_dict_fails(self) -> None:
        """An empty dict should report errors for every required field."""
        result = validate_policy_schema({})
        assert result.is_valid is False
        assert len(result.errors) > 0

    def test_missing_single_field(self) -> None:
        """Removing one required field should produce exactly one error."""
        incomplete = {k: v for k, v in VALID_POLICY_DICT.items() if k != "name"}
        result = validate_policy_schema(incomplete)
        assert result.is_valid is False
        assert any("name" in e for e in result.errors)

    def test_bad_risk_level_enum(self) -> None:
        """An invalid enum value should be caught."""
        bad = {**VALID_POLICY_DICT, "risk_level": "EXTREME"}
        result = validate_policy_schema(bad)
        assert result.is_valid is False
        assert any("risk_level" in e for e in result.errors)

    def test_bad_enforcement_mode_enum(self) -> None:
        """An invalid enforcement_mode should be caught."""
        bad = {**VALID_POLICY_DICT, "enforcement_mode": "nuke"}
        result = validate_policy_schema(bad)
        assert result.is_valid is False
        assert any("enforcement_mode" in e for e in result.errors)

    def test_bad_version_pattern(self) -> None:
        """A non-semver version should be caught."""
        bad = {**VALID_POLICY_DICT, "version": "latest"}
        result = validate_policy_schema(bad)
        assert result.is_valid is False
        assert any("version" in e for e in result.errors)

    def test_empty_regulation_references(self) -> None:
        """An empty regulation_references list should be caught by minItems."""
        bad = {**VALID_POLICY_DICT, "regulation_references": []}
        result = validate_policy_schema(bad)
        assert result.is_valid is False
        assert any("regulation_references" in e for e in result.errors)

    def test_extra_field_rejected(self) -> None:
        """additionalProperties: false should reject unknown keys."""
        bad = {**VALID_POLICY_DICT, "surprise_field": "oops"}
        result = validate_policy_schema(bad)
        assert result.is_valid is False

    def test_warning_when_applies_to_empty(self) -> None:
        """A valid policy without applies_to should get a warning."""
        result = validate_policy_schema(VALID_POLICY_DICT)
        assert any("applies_to" in w for w in result.warnings)

    def test_no_warning_when_applies_to_present(self) -> None:
        """A valid policy with applies_to populated should get no warning."""
        with_applies = {**VALID_POLICY_DICT, "applies_to": ["model-v1"]}
        result = validate_policy_schema(with_applies)
        assert result.is_valid is True
        assert not any("applies_to" in w for w in result.warnings)

    def test_errors_are_human_readable(self) -> None:
        """Error strings should start with a JSON-path-like prefix."""
        result = validate_policy_schema({})
        for err in result.errors:
            assert err.startswith("$")


# ---------------------------------------------------------------------------
# validate_policy_file
# ---------------------------------------------------------------------------


class TestValidatePolicyFile:
    """Tests for validate_policy_file()."""

    def test_valid_yaml_file(self, tmp_path: Path) -> None:
        """A valid YAML file should produce a passing ValidationResult."""
        p = tmp_path / "good.yaml"
        p.write_text(VALID_POLICY_YAML, encoding="utf-8")
        result = validate_policy_file(p)
        assert result.is_valid is True
        assert result.filename == str(p)

    def test_missing_file(self, tmp_path: Path) -> None:
        """A non-existent file should return is_valid=False with file-not-found."""
        result = validate_policy_file(tmp_path / "nope.yaml")
        assert result.is_valid is False
        assert any("file not found" in e for e in result.errors)

    def test_malformed_yaml(self, tmp_path: Path) -> None:
        """Broken YAML should return is_valid=False."""
        bad = tmp_path / "broken.yaml"
        bad.write_text("{{{{not yaml", encoding="utf-8")
        result = validate_policy_file(bad)
        assert result.is_valid is False
        assert any("malformed YAML" in e for e in result.errors)

    def test_non_mapping_root(self, tmp_path: Path) -> None:
        """A YAML list root should return is_valid=False."""
        bad = tmp_path / "list.yaml"
        bad.write_text("- one\n- two\n", encoding="utf-8")
        result = validate_policy_file(bad)
        assert result.is_valid is False
        assert any("mapping" in e for e in result.errors)

    def test_errors_include_filename(self, tmp_path: Path) -> None:
        """Every error string should contain the file path."""
        bad = tmp_path / "incomplete.yaml"
        bad.write_text("id: only-an-id\n", encoding="utf-8")
        result = validate_policy_file(bad)
        assert result.is_valid is False
        for err in result.errors:
            assert "incomplete.yaml" in err

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        """Plain string paths should work."""
        p = tmp_path / "good.yaml"
        p.write_text(VALID_POLICY_YAML, encoding="utf-8")
        result = validate_policy_file(str(p))
        assert result.is_valid is True


# ---------------------------------------------------------------------------
# validate_all_policies
# ---------------------------------------------------------------------------


class TestValidateAllPolicies:
    """Tests for validate_all_policies()."""

    def test_mixed_directory(self, tmp_path: Path) -> None:
        """Valid and invalid files should both appear in results."""
        (tmp_path / "good.yaml").write_text(VALID_POLICY_YAML, encoding="utf-8")
        (tmp_path / "bad.yaml").write_text("id: only-an-id\n", encoding="utf-8")

        results = validate_all_policies(tmp_path)
        assert len(results) == 2

        good_key = str(tmp_path / "good.yaml")
        bad_key = str(tmp_path / "bad.yaml")
        assert results[good_key].is_valid is True
        assert results[bad_key].is_valid is False

    def test_recursive_scan(self, tmp_path: Path) -> None:
        """Subdirectories should be scanned."""
        sub = tmp_path / "nested" / "deep"
        sub.mkdir(parents=True)
        (sub / "policy.yaml").write_text(VALID_POLICY_YAML, encoding="utf-8")

        results = validate_all_policies(tmp_path)
        assert len(results) == 1
        assert list(results.values())[0].is_valid is True

    def test_skips_gitkeep(self, tmp_path: Path) -> None:
        """.gitkeep files should not appear in results."""
        (tmp_path / ".gitkeep").write_text("", encoding="utf-8")
        results = validate_all_policies(tmp_path)
        assert len(results) == 0

    def test_missing_directory(self, tmp_path: Path) -> None:
        """A nonexistent directory should return an empty dict."""
        results = validate_all_policies(tmp_path / "nonexistent")
        assert results == {}

    def test_never_crashes(self, tmp_path: Path) -> None:
        """Even broken YAML files should not crash the scan."""
        (tmp_path / "good.yaml").write_text(VALID_POLICY_YAML, encoding="utf-8")
        (tmp_path / "crash.yaml").write_text("{{{{syntax horror", encoding="utf-8")

        results = validate_all_policies(tmp_path)
        assert len(results) == 2
        assert all(isinstance(v, ValidationResult) for v in results.values())


# ---------------------------------------------------------------------------
# detect_conflicts
# ---------------------------------------------------------------------------


class TestDetectConflicts:
    """Tests for detect_conflicts()."""

    def test_no_conflict_same_threshold(self) -> None:
        """Policies with identical thresholds for the same metric should not conflict."""
        p1 = _make_policy(id="pol-a", threshold=0.1)
        p2 = _make_policy(id="pol-b", threshold=0.1)
        assert detect_conflicts([p1, p2]) == []

    def test_conflict_different_threshold(self) -> None:
        """Different thresholds for the same metric/jurisdiction should conflict."""
        p1 = _make_policy(id="pol-a", threshold=0.1)
        p2 = _make_policy(id="pol-b", threshold=0.2)
        conflicts = detect_conflicts([p1, p2])
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], ConflictWarning)
        assert conflicts[0].policy_id_1 == "pol-a"
        assert conflicts[0].policy_id_2 == "pol-b"
        assert "demographic_parity" in conflicts[0].conflict_description
        assert "EU" in conflicts[0].conflict_description

    def test_no_conflict_different_jurisdictions(self) -> None:
        """Same metric but different jurisdictions should not conflict."""
        p1 = _make_policy(id="pol-a", jurisdiction="EU", threshold=0.1)
        p2 = _make_policy(id="pol-b", jurisdiction="US-Federal", threshold=0.2)
        assert detect_conflicts([p1, p2]) == []

    def test_no_conflict_different_metrics(self) -> None:
        """Different metrics in the same jurisdiction should not conflict."""
        p1 = _make_policy(id="pol-a", metric="demographic_parity", threshold=0.1)
        p2 = _make_policy(id="pol-b", metric="equal_opportunity", threshold=0.2)
        assert detect_conflicts([p1, p2]) == []

    def test_multiple_conflicts(self) -> None:
        """Three policies with pairwise differences should produce 3 conflicts."""
        p1 = _make_policy(id="pol-a", threshold=0.1)
        p2 = _make_policy(id="pol-b", threshold=0.2)
        p3 = _make_policy(id="pol-c", threshold=0.3)
        conflicts = detect_conflicts([p1, p2, p3])
        assert len(conflicts) == 3

    def test_empty_list(self) -> None:
        """An empty policy list should produce zero conflicts."""
        assert detect_conflicts([]) == []

    def test_single_policy(self) -> None:
        """A single policy cannot conflict with itself."""
        assert detect_conflicts([_make_policy()]) == []

    def test_nested_rules_detected(self) -> None:
        """Rules buried inside nested operator groups should still be found."""
        nested_policy = Policy.model_validate(
            {
                **VALID_POLICY_DICT,
                "id": "pol-nested",
                "policy_logic": {
                    "operator": "or",
                    "conditions": [
                        {
                            "operator": "and",
                            "rules": [
                                {"metric": "demographic_parity", "threshold": 0.05}
                            ],
                        }
                    ],
                },
            },
            strict=False,
        )
        flat_policy = _make_policy(id="pol-flat", threshold=0.1)
        conflicts = detect_conflicts([nested_policy, flat_policy])
        assert len(conflicts) == 1

    def test_no_rules_in_logic(self) -> None:
        """Policies with empty policy_logic should not produce conflicts."""
        p1 = Policy.model_validate(
            {**VALID_POLICY_DICT, "id": "pol-empty-a", "policy_logic": {}},
            strict=False,
        )
        p2 = Policy.model_validate(
            {**VALID_POLICY_DICT, "id": "pol-empty-b", "policy_logic": {}},
            strict=False,
        )
        assert detect_conflicts([p1, p2]) == []

    def test_conflict_recommendation_mentions_policy_ids(self) -> None:
        """The recommendation string should reference both policy IDs."""
        p1 = _make_policy(id="alpha", threshold=0.1)
        p2 = _make_policy(id="beta", threshold=0.5)
        conflicts = detect_conflicts([p1, p2])
        assert "alpha" in conflicts[0].recommendation
        assert "beta" in conflicts[0].recommendation
