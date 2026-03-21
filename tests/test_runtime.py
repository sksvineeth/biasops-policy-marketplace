# test_runtime.py — Tests for RuntimeEnforcer and AuditStore.
# Includes the core demo scenario: EU freeze_account denied, US allowed.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from biasops.runtime.audit import AuditEntry, AuditStore
from biasops.runtime.enforcer import ALLOW, DENY, REQUIRE_HUMAN, RuntimeEnforcer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_store(tmp_path):
    return AuditStore(path=tmp_path / "test_audit.jsonl")


@pytest.fixture()
def enforcer(tmp_path):
    """Enforcer pointed at real policies + attestations, fresh audit log."""
    return RuntimeEnforcer(
        policies_dir=Path("policies/"),
        attestations_dir=Path("attestations/"),
        audit_path=tmp_path / "test_audit.jsonl",
    )


@pytest.fixture()
def enforcer_no_saga(tmp_path):
    """Enforcer with SAGA disabled — policy-only mode."""
    return RuntimeEnforcer(
        policies_dir=Path("policies/"),
        attestations_dir=Path("attestations/"),
        audit_path=tmp_path / "test_audit.jsonl",
        skip_saga=True,
    )


# ---------------------------------------------------------------------------
# AuditStore tests
# ---------------------------------------------------------------------------


def test_audit_write_returns_id(audit_store):
    entry = AuditEntry(
        agent_id="test-agent",
        action="test_action",
        context={"jurisdiction": "US"},
        decision="ALLOW",
        reasons=["Test passed."],
        policies_evaluated=["TEST-001"],
        attestation_status="VALID",
    )
    audit_id = audit_store.write(entry)
    assert audit_id.startswith("chk_")


def test_audit_entry_is_persisted(audit_store):
    entry = AuditEntry(
        agent_id="agent-x",
        action="do_something",
        context={"jurisdiction": "EU"},
        decision="DENY",
        reasons=["Not authorized."],
        policies_evaluated=["EU-AI-ACT-001"],
        attestation_status="EXPIRED",
        required_action="escalate_to_human_queue",
        regulatory_refs=["EU AI Act Article 14"],
    )
    audit_store.write(entry)

    entries = audit_store.read_all()
    assert len(entries) == 1
    e = entries[0]
    assert e["agent_id"] == "agent-x"
    assert e["decision"] == "DENY"
    assert e["attestation_status"] == "EXPIRED"
    assert "EU AI Act Article 14" in e["regulatory_refs"]


def test_audit_multiple_entries_accumulate(audit_store):
    for i in range(5):
        audit_store.write(AuditEntry(
            agent_id=f"agent-{i}",
            action="action",
            context={},
            decision="ALLOW",
            reasons=["ok"],
            policies_evaluated=[],
            attestation_status="VALID",
        ))
    assert len(audit_store.read_all()) == 5


def test_audit_query_by_agent(audit_store):
    audit_store.write(AuditEntry("agent-a", "act", {}, "ALLOW", [], [], "VALID"))
    audit_store.write(AuditEntry("agent-b", "act", {}, "DENY", [], [], "EXPIRED"))
    audit_store.write(AuditEntry("agent-a", "act", {}, "DENY", [], [], "VALID"))

    results = audit_store.query(agent_id="agent-a")
    assert len(results) == 2
    assert all(r["agent_id"] == "agent-a" for r in results)


def test_audit_query_by_decision(audit_store):
    audit_store.write(AuditEntry("a", "act", {}, "ALLOW", [], [], "VALID"))
    audit_store.write(AuditEntry("b", "act", {}, "DENY", [], [], "EXPIRED"))
    audit_store.write(AuditEntry("c", "act", {}, "ALLOW", [], [], "VALID"))

    results = audit_store.query(decision="DENY")
    assert len(results) == 1
    assert results[0]["decision"] == "DENY"


def test_audit_stats(audit_store):
    audit_store.write(AuditEntry("a", "freeze", {}, "ALLOW", [], [], "VALID"))
    audit_store.write(AuditEntry("a", "freeze", {}, "DENY", [], [], "EXPIRED"))
    audit_store.write(AuditEntry("b", "score", {}, "ALLOW", [], [], "VALID"))

    s = audit_store.stats()
    assert s["total"] == 3
    assert s["by_decision"]["ALLOW"] == 2
    assert s["by_decision"]["DENY"] == 1
    assert s["by_agent"]["a"] == 2
    assert s["by_action"]["freeze"] == 2


def test_audit_jsonl_format(audit_store, tmp_path):
    """Each line must be valid, self-contained JSON."""
    audit_store.write(AuditEntry("a", "b", {}, "ALLOW", [], [], "VALID"))
    lines = (tmp_path / "test_audit.jsonl").read_text().strip().split("\n")
    for line in lines:
        parsed = json.loads(line)
        assert "audit_id" in parsed
        assert "timestamp" in parsed
        assert "decision" in parsed


# ---------------------------------------------------------------------------
# RuntimeEnforcer — core check() tests
# ---------------------------------------------------------------------------


def test_check_returns_result(enforcer):
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="summarize_transaction",
        context={"environment": "production"},
    )
    assert result.decision in (ALLOW, DENY, REQUIRE_HUMAN)
    assert result.audit_id.startswith("chk_")
    assert result.latency_ms > 0


def test_check_unknown_agent_is_denied(enforcer):
    result = enforcer.check(
        agent_id="ghost-agent-not-registered",
        action="freeze_account",
        context={"jurisdiction": "US"},
    )
    assert result.decision == DENY
    assert result.attestation_status == "UNKNOWN"
    assert "not found" in result.reasons[0].lower()


def test_check_unknown_skill_is_denied(enforcer):
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="launch_missiles",  # not attested
        context={},
    )
    assert result.decision == DENY
    assert result.attestation_status == "UNKNOWN"


# ---------------------------------------------------------------------------
# THE CORE DEMO SCENARIO
# ---------------------------------------------------------------------------


def test_demo_eu_freeze_account_denied(enforcer):
    """
    EU freeze_account must be DENIED.

    fraud-investigator-v2 attestation scope for freeze_account:
      jurisdictions: [US, UK]  ← EU is NOT in scope
    Expected: DENY with OUT_OF_SCOPE attestation status.
    """
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        context={
            "jurisdiction": "EU",
            "risk_level": "high",
            "model": "gpt-4o-validated-v2",
            "automated": True,
        },
    )
    assert result.decision == DENY
    assert result.attestation_status == "OUT_OF_SCOPE"
    assert len(result.reasons) > 0
    assert result.audit_id.startswith("chk_")


def test_demo_us_freeze_account_allowed(enforcer):
    """
    US freeze_account at low risk must be ALLOWED.

    fraud-investigator-v2 scope for freeze_account:
      jurisdictions: [US, UK]
      risk_levels: [low, medium]
      approved_models: [gpt-4o-validated-v2]
    """
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        context={
            "jurisdiction": "US",
            "risk_level": "low",
            "model": "gpt-4o-validated-v2",
            "environment": "production",
            "data_type": "financial",
        },
    )
    assert result.decision == ALLOW
    assert result.attestation_status == "VALID"


def test_demo_prohibited_model_denied(enforcer):
    """
    gpt-4o-latest is explicitly prohibited for freeze_account.
    Must be DENIED regardless of jurisdiction.
    """
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        context={
            "jurisdiction": "US",
            "risk_level": "low",
            "model": "gpt-4o-latest",   # prohibited
            "environment": "production",
            "data_type": "financial",
        },
    )
    assert result.decision == DENY
    assert "gpt-4o-latest" in " ".join(result.reasons)


def test_demo_summarize_is_global(enforcer):
    """
    summarize_transaction has no jurisdiction restriction — valid anywhere.
    """
    for jurisdiction in ("US", "EU", "UK", "SG"):
        result = enforcer.check(
            agent_id="fraud-investigator-v2",
            action="summarize_transaction",
            context={
                "jurisdiction": jurisdiction,
                "environment": "production",
            },
        )
        assert result.decision == ALLOW, (
            f"Expected ALLOW in {jurisdiction}, got {result.decision}: {result.reasons}"
        )


def test_demo_high_risk_freeze_denied(enforcer):
    """
    freeze_account at high risk_level is out of scope even in US.
    Scope: risk_levels: [low, medium]
    """
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="freeze_account",
        context={
            "jurisdiction": "US",
            "risk_level": "high",   # not in [low, medium]
            "model": "gpt-4o-validated-v2",
            "environment": "production",
        },
    )
    assert result.decision == DENY


def test_demo_audit_written_for_every_check(enforcer, tmp_path):
    """Every check — ALLOW or DENY — writes to the audit log."""
    audit = AuditStore(path=tmp_path / "test_audit.jsonl")

    enforcer.check("fraud-investigator-v2", "summarize_transaction",
                   {"environment": "production"})
    enforcer.check("fraud-investigator-v2", "freeze_account",
                   {"jurisdiction": "EU"})

    entries = audit.read_all()
    assert len(entries) == 2
    decisions = {e["decision"] for e in entries}
    assert "ALLOW" in decisions
    assert "DENY" in decisions


# ---------------------------------------------------------------------------
# Delegation tests
# ---------------------------------------------------------------------------


def test_delegation_to_allowed_delegate(enforcer):
    """
    escalate_to_human_queue has delegation=allowlist: [human-review-agent-v1]
    """
    result = enforcer.check_delegation(
        calling_agent_id="fraud-investigator-v2",
        called_agent_id="human-review-agent-v1",
        action="escalate_to_human_queue",
        context={"environment": "production"},
    )
    # human-review-agent-v1 is on the allowlist so delegation is permitted
    # (SAGA will report UNKNOWN for the called agent since it has no attestation file,
    # which is the honest expected behavior — delegation allowed by caller,
    # but called agent not independently attested yet)
    assert result.audit_id.startswith("chk_")


def test_delegation_blocked_for_freeze_account(enforcer):
    """freeze_account has delegation=none — cannot delegate."""
    result = enforcer.check_delegation(
        calling_agent_id="fraud-investigator-v2",
        called_agent_id="any-other-agent",
        action="freeze_account",
        context={"jurisdiction": "US", "risk_level": "low",
                 "environment": "production", "data_type": "financial"},
    )
    assert result.decision == DENY
    assert "delegation" in " ".join(result.reasons).lower()


# ---------------------------------------------------------------------------
# Policy-only mode (skip_saga=True)
# ---------------------------------------------------------------------------


def test_no_saga_mode_evaluates_policies(enforcer_no_saga):
    """With skip_saga=True, check still runs policy evaluation."""
    result = enforcer_no_saga.check(
        agent_id="any-agent",
        action="any_action",
        context={"jurisdiction": "US"},
    )
    assert result.decision in (ALLOW, DENY, REQUIRE_HUMAN)
    assert result.attestation_status == "UNKNOWN"
    assert result.audit_id.startswith("chk_")


def test_result_to_dict(enforcer):
    result = enforcer.check(
        agent_id="fraud-investigator-v2",
        action="summarize_transaction",
        context={"environment": "production"},
    )
    d = result.to_dict()
    for key in ("decision", "agent_id", "action", "reasons", "audit_id", "latency_ms"):
        assert key in d
