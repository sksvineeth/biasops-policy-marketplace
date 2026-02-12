# test_cli.py — Tests for the Typer CLI commands.

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from biasops.cli import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_BASE_POLICY: dict = {
    "id": "pol-cli-001",
    "name": "CLI Test Policy",
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
    "policy_logic": {"demographic_parity_max_threshold": 0.2},
    "remediation_steps": ["Retrain with balanced data"],
    "created_at": "2024-06-01T00:00:00Z",
    "maintained_by": "BiasOps Core Team",
}


def _write_policy(directory: Path, overrides: dict | None = None) -> Path:
    """Write a valid policy YAML into *directory* and return the file path."""
    data = {**_BASE_POLICY, **(overrides or {})}
    path = directory / f"{data['id']}.yaml"
    path.write_text(yaml.dump(data, sort_keys=False), encoding="utf-8")
    return path


def _write_metadata(directory: Path, metadata: dict) -> Path:
    """Write a metadata JSON file and return its path."""
    path = directory / "metadata.json"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


class TestVersion:
    """Global --version flag."""

    def test_version_flag(self) -> None:
        """--version should print the version and exit 0."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """Tests for ``biasops validate <policy_path>``."""

    def test_valid_policy(self, tmp_path: Path) -> None:
        """A valid policy file should print VALID and exit 0."""
        policy_file = _write_policy(tmp_path)
        result = runner.invoke(app, ["validate", str(policy_file)])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_missing_file(self, tmp_path: Path) -> None:
        """A non-existent file should print INVALID and exit 1."""
        result = runner.invoke(app, ["validate", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_invalid_policy(self, tmp_path: Path) -> None:
        """A schema-invalid file should print INVALID with errors and exit 1."""
        bad = tmp_path / "bad.yaml"
        bad.write_text("id: only-an-id\n", encoding="utf-8")
        result = runner.invoke(app, ["validate", str(bad)])
        assert result.exit_code == 1
        assert "INVALID" in result.output
        # Should show at least one error line mentioning a missing field
        assert "name" in result.output or "required" in result.output.lower()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


class TestScanCommand:
    """Tests for ``biasops scan <policies_dir> <metadata_json>``."""

    def test_scan_pass(self, tmp_path: Path) -> None:
        """Clean metadata should produce PASS and exit 0."""
        _write_policy(tmp_path)
        meta_file = _write_metadata(tmp_path, {"demographic_parity": 0.1})
        result = runner.invoke(app, ["scan", str(tmp_path), str(meta_file)])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_scan_fail(self, tmp_path: Path) -> None:
        """Metadata violating a block policy should produce FAIL and exit 1."""
        _write_policy(tmp_path)
        meta_file = _write_metadata(tmp_path, {"demographic_parity": 0.9})
        result = runner.invoke(app, ["scan", str(tmp_path), str(meta_file)])
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "Violations found: 1" in result.output

    def test_scan_shows_violation_details(self, tmp_path: Path) -> None:
        """Violation output should include severity, policy id, and fix."""
        _write_policy(tmp_path)
        meta_file = _write_metadata(tmp_path, {"demographic_parity": 0.9})
        result = runner.invoke(app, ["scan", str(tmp_path), str(meta_file)])
        assert "pol-cli-001" in result.output
        assert "Regulation:" in result.output
        assert "Fix:" in result.output

    def test_scan_missing_metadata_file(self, tmp_path: Path) -> None:
        """A non-existent metadata file should print error and exit 1."""
        _write_policy(tmp_path)
        result = runner.invoke(
            app, ["scan", str(tmp_path), str(tmp_path / "nope.json")]
        )
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "Error" in result.output


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestListCommand:
    """Tests for ``biasops list <policies_dir>``."""

    def test_list_shows_policies(self, tmp_path: Path) -> None:
        """All loaded policies should appear in the table output."""
        _write_policy(tmp_path, {"id": "pol-a", "name": "Policy A", "domain": "hiring"})
        _write_policy(tmp_path, {"id": "pol-b", "name": "Policy B", "domain": "lending"})
        result = runner.invoke(app, ["list", str(tmp_path)])
        assert result.exit_code == 0
        assert "pol-a" in result.output
        assert "pol-b" in result.output
        assert "Policy A" in result.output
        assert "Policy B" in result.output
        assert "Total: 2" in result.output

    def test_list_empty_directory(self, tmp_path: Path) -> None:
        """An empty directory should say no policies found."""
        result = runner.invoke(app, ["list", str(tmp_path)])
        assert result.exit_code == 0
        assert "No policies found" in result.output

    def test_list_missing_directory(self, tmp_path: Path) -> None:
        """A nonexistent directory should print error and exit 1."""
        result = runner.invoke(app, ["list", str(tmp_path / "nope")])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# check-conflicts
# ---------------------------------------------------------------------------


class TestCheckConflictsCommand:
    """Tests for ``biasops check-conflicts <policies_dir>``."""

    def test_no_conflicts(self, tmp_path: Path) -> None:
        """Policies with no threshold conflicts should print clean and exit 0."""
        _write_policy(tmp_path, {"id": "pol-a"})
        _write_policy(tmp_path, {"id": "pol-b"})
        result = runner.invoke(app, ["check-conflicts", str(tmp_path)])
        assert result.exit_code == 0
        assert "No conflicts detected" in result.output

    def test_conflict_detected(self, tmp_path: Path) -> None:
        """Policies with contradicting thresholds should report conflict and exit 1."""
        _write_policy(
            tmp_path,
            {
                "id": "pol-x",
                "policy_logic": {
                    "operator": "and",
                    "rules": [{"metric": "dp", "threshold": 0.1}],
                },
            },
        )
        _write_policy(
            tmp_path,
            {
                "id": "pol-y",
                "policy_logic": {
                    "operator": "and",
                    "rules": [{"metric": "dp", "threshold": 0.5}],
                },
            },
        )
        result = runner.invoke(app, ["check-conflicts", str(tmp_path)])
        assert result.exit_code == 1
        assert "conflict" in result.output.lower()
        assert "pol-x" in result.output
        assert "pol-y" in result.output

    def test_check_conflicts_missing_directory(self, tmp_path: Path) -> None:
        """A nonexistent directory should print error and exit 1."""
        result = runner.invoke(app, ["check-conflicts", str(tmp_path / "nope")])
        assert result.exit_code == 1
