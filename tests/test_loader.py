# test_loader.py — Tests for policy file loading and directory discovery.

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from biasops.loader import PolicyLoadError, load_policies_from_directory, load_policy, load_policy_from_dict
from biasops.models import Policy

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

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
  rules: []
remediation_steps:
  - Retrain with balanced data
created_at: "2024-06-01T00:00:00Z"
maintained_by: BiasOps Core Team
"""

VALID_POLICY_DICT = {
    "id": "pol-test-dict-001",
    "name": "Dict Policy",
    "version": "1.0.0",
    "domain": "lending",
    "jurisdiction": "US-Federal",
    "regulation_references": [
        {
            "article": "Section 5(a)",
            "url": "https://example.com/reg",
            "jurisdiction": "US-Federal",
        }
    ],
    "bias_types_addressed": ["racial"],
    "risk_level": "MEDIUM",
    "enforcement_mode": "warn",
    "policy_logic": {"operator": "or", "rules": []},
    "remediation_steps": ["Audit training data"],
    "created_at": "2024-06-01T00:00:00Z",
    "maintained_by": "Test Author",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_yaml_file(tmp_path: Path) -> Path:
    """Write a valid policy YAML to a temp file and return its path."""
    p = tmp_path / "valid_policy.yaml"
    p.write_text(VALID_POLICY_YAML, encoding="utf-8")
    return p


@pytest.fixture()
def policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory tree with valid, invalid, and gitkeep files."""
    # valid file
    (tmp_path / "good.yaml").write_text(VALID_POLICY_YAML, encoding="utf-8")

    # nested valid file
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "also_good.yaml").write_text(VALID_POLICY_YAML, encoding="utf-8")

    # invalid file (missing required fields)
    (tmp_path / "bad.yaml").write_text("id: only-an-id\n", encoding="utf-8")

    # .gitkeep — must be skipped
    (tmp_path / ".gitkeep").write_text("", encoding="utf-8")

    return tmp_path


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    """Tests for load_policy()."""

    def test_loads_valid_yaml(self, valid_yaml_file: Path) -> None:
        """A well-formed YAML file should produce a Policy instance."""
        policy = load_policy(valid_yaml_file)
        assert isinstance(policy, Policy)
        assert policy.id == "pol-test-001"
        assert policy.risk_level.value == "HIGH"
        assert policy.enforcement_mode.value == "block"
        assert policy.applies_to == []

    def test_file_not_found(self, tmp_path: Path) -> None:
        """A non-existent path should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            load_policy(tmp_path / "nope.yaml")

    def test_malformed_yaml(self, tmp_path: Path) -> None:
        """Broken YAML syntax should raise PolicyLoadError."""
        bad = tmp_path / "broken.yaml"
        bad.write_text("{{{{not: yaml", encoding="utf-8")
        with pytest.raises(PolicyLoadError, match="Malformed YAML"):
            load_policy(bad)

    def test_non_mapping_root(self, tmp_path: Path) -> None:
        """A YAML file whose root is a list should raise PolicyLoadError."""
        bad = tmp_path / "list_root.yaml"
        bad.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError, match="Expected a YAML mapping"):
            load_policy(bad)

    def test_validation_error_includes_filename(self, tmp_path: Path) -> None:
        """A schema-invalid file should raise PolicyLoadError mentioning the file."""
        bad = tmp_path / "incomplete.yaml"
        bad.write_text("id: only-an-id\n", encoding="utf-8")
        with pytest.raises(PolicyLoadError, match="incomplete.yaml") as exc_info:
            load_policy(bad)
        # The original ValidationError is chained as __cause__
        assert isinstance(exc_info.value.__cause__, ValidationError)

    def test_accepts_string_path(self, valid_yaml_file: Path) -> None:
        """load_policy should accept a plain string path, not just Path objects."""
        policy = load_policy(str(valid_yaml_file))
        assert policy.id == "pol-test-001"


# ---------------------------------------------------------------------------
# load_policies_from_directory
# ---------------------------------------------------------------------------


class TestLoadPoliciesFromDirectory:
    """Tests for load_policies_from_directory()."""

    def test_loads_valid_skips_invalid(
        self, policy_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Valid files load; invalid files are warned and skipped."""
        with caplog.at_level(logging.WARNING, logger="biasops.loader"):
            policies = load_policies_from_directory(policy_dir)

        # Two valid files (good.yaml + sub/also_good.yaml)
        assert len(policies) == 2
        assert all(isinstance(p, Policy) for p in policies)

        # The bad file should produce a warning
        assert any("bad.yaml" in record.message for record in caplog.records)

    def test_skips_gitkeep(self, policy_dir: Path) -> None:
        """.gitkeep files must not be processed."""
        policies = load_policies_from_directory(policy_dir)
        loaded_names = {p.id for p in policies}
        # If .gitkeep were loaded, we'd get an error or an extra entry
        assert "gitkeep" not in str(loaded_names)

    def test_directory_not_found(self, tmp_path: Path) -> None:
        """A missing directory should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Policy directory not found"):
            load_policies_from_directory(tmp_path / "nonexistent")

    def test_empty_directory(self, tmp_path: Path) -> None:
        """An empty directory should return an empty list."""
        assert load_policies_from_directory(tmp_path) == []


# ---------------------------------------------------------------------------
# load_policy_from_dict
# ---------------------------------------------------------------------------


class TestLoadPolicyFromDict:
    """Tests for load_policy_from_dict()."""

    def test_loads_valid_dict(self) -> None:
        """A complete dict should produce a Policy instance."""
        policy = load_policy_from_dict(VALID_POLICY_DICT)
        assert isinstance(policy, Policy)
        assert policy.id == "pol-test-dict-001"
        assert policy.domain == "lending"

    def test_invalid_dict_raises_validation_error(self) -> None:
        """A dict missing required fields should raise ValidationError."""
        with pytest.raises(ValidationError):
            load_policy_from_dict({"id": "incomplete"})
