# test_registry.py — Tests for the PolicyRegistry and module-level helpers.

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from biasops.registry import PolicyRegistry


@pytest.fixture()
def registry():
    return PolicyRegistry()


# ---------------------------------------------------------------------------
# list_policies
# ---------------------------------------------------------------------------


def test_list_returns_list(registry):
    results = registry.list_policies()
    assert isinstance(results, list)
    assert len(results) > 0


def test_list_fields(registry):
    for p in registry.list_policies():
        for field in ("id", "name", "version", "domain", "jurisdiction", "risk_level"):
            assert field in p, f"Missing field '{field}' in {p.get('id')}"


def test_list_filter_domain(registry):
    results = registry.list_policies(domain="financial-services")
    assert all(p["domain"] == "financial-services" for p in results)
    assert len(results) > 0


def test_list_filter_jurisdiction_eu(registry):
    results = registry.list_policies(jurisdiction="EU")
    assert all(p["jurisdiction"] == "EU" for p in results)
    assert len(results) > 0


def test_list_filter_risk_level(registry):
    results = registry.list_policies(risk_level="CRITICAL")
    assert all(p["risk_level"] == "CRITICAL" for p in results)


def test_list_filter_enforcement_block(registry):
    results = registry.list_policies(enforcement_mode="block")
    assert all(p["enforcement_mode"] == "block" for p in results)


def test_list_filter_no_match(registry):
    results = registry.list_policies(domain="nonexistent-domain-xyz")
    assert results == []


def test_list_sorted(registry):
    results = registry.list_policies()
    domains = [p["domain"] for p in results]
    assert domains == sorted(domains)


# ---------------------------------------------------------------------------
# fetch_policy
# ---------------------------------------------------------------------------


def test_fetch_known_policy(registry):
    policy = registry.fetch_policy("ECOA-001")
    assert policy.id == "ECOA-001"
    assert policy.name is not None


def test_fetch_with_correct_version(registry):
    policy = registry.fetch_policy("ECOA-001", version="1.0.0")
    assert policy.id == "ECOA-001"


def test_fetch_wrong_version_raises(registry):
    with pytest.raises(KeyError, match="not found"):
        registry.fetch_policy("ECOA-001", version="99.0.0")


def test_fetch_nonexistent_raises(registry):
    with pytest.raises(KeyError, match="not found"):
        registry.fetch_policy("DOES-NOT-EXIST-001")


# ---------------------------------------------------------------------------
# publish_policy
# ---------------------------------------------------------------------------


def test_publish_valid_policy(registry, tmp_path):
    src = tmp_path / "test_policy.yaml"
    src.write_text(
        """
id: TEST-PUBLISH-001
name: Publish Test Policy
version: 1.0.0
domain: general
jurisdiction: Global
risk_level: LOW
enforcement_mode: audit
maintained_by: Test Suite
bias_types_addressed:
  - test-bias
regulation_references:
  - article: "Test Article 1"
    url: "https://example.com"
    jurisdiction: Global
policy_logic:
  test_metric_max_threshold: 0.50
remediation_steps:
  - "Fix the test metric."
created_at: "2026-01-01T00:00:00Z"
"""
    )
    temp_registry = PolicyRegistry(policies_dir=tmp_path / "registry")
    dest = temp_registry.publish_policy(src, domain_subfolder="general")
    assert dest.exists()
    assert dest.name == "test_policy.yaml"


def test_publish_overwrite_false_raises(registry, tmp_path):
    src = tmp_path / "ecoa_disparate_impact.yaml"
    real = Path("policies/financial-services/ecoa_disparate_impact.yaml")
    if not real.exists():
        pytest.skip("ECOA policy file not found")
    shutil.copy(real, src)

    temp_registry = PolicyRegistry(policies_dir=tmp_path / "registry")
    dest_dir = tmp_path / "registry" / "financial-services"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    dest.write_text("placeholder")

    with pytest.raises(FileExistsError):
        temp_registry.publish_policy(src, domain_subfolder="financial-services", overwrite=False)


def test_publish_nonexistent_source_raises(registry, tmp_path):
    temp_registry = PolicyRegistry(policies_dir=tmp_path / "registry")
    with pytest.raises(FileNotFoundError):
        temp_registry.publish_policy(tmp_path / "does_not_exist.yaml")


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_search_by_regulation(registry):
    results = registry.search("GDPR")
    assert len(results) > 0
    assert any("GDPR" in p["id"] or "GDPR" in p["name"] for p in results)


def test_search_by_domain(registry):
    results = registry.search("financial")
    assert len(results) > 0


def test_search_case_insensitive(registry):
    lower = registry.search("gdpr")
    upper = registry.search("GDPR")
    assert len(lower) == len(upper)


def test_search_no_results(registry):
    results = registry.search("zzznomatchxxx")
    assert results == []


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


def test_stats_structure(registry):
    s = registry.stats()
    assert "total" in s
    assert "by_domain" in s
    assert "by_jurisdiction" in s
    assert "by_risk_level" in s
    assert "by_enforcement_mode" in s


def test_stats_total_matches_list(registry):
    s = registry.stats()
    listed = registry.list_policies()
    assert s["total"] == len(listed)


def test_stats_eu_present(registry):
    s = registry.stats()
    assert "EU" in s["by_jurisdiction"]


# ---------------------------------------------------------------------------
# Registry API endpoints
# ---------------------------------------------------------------------------


from fastapi.testclient import TestClient
from biasops.api import app

client = TestClient(app)


def test_registry_list_endpoint():
    r = client.get("/registry")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_registry_list_filter_domain():
    r = client.get("/registry?domain=financial-services")
    assert r.status_code == 200
    for p in r.json():
        assert p["domain"] == "financial-services"


def test_registry_list_filter_jurisdiction():
    r = client.get("/registry?jurisdiction=EU")
    assert r.status_code == 200
    for p in r.json():
        assert p["jurisdiction"] == "EU"


def test_registry_stats_endpoint():
    r = client.get("/registry/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] > 0
    assert "by_domain" in body


def test_registry_search_endpoint():
    r = client.get("/registry/search?q=GDPR")
    assert r.status_code == 200
    assert len(r.json()) > 0


def test_registry_search_short_query():
    r = client.get("/registry/search?q=G")
    assert r.status_code == 422


def test_registry_search_no_results():
    r = client.get("/registry/search?q=zzznomatch")
    assert r.status_code == 200
    assert r.json() == []
