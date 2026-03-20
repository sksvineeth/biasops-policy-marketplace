# test_saga.py — Tests for SAGA attestation, registry, and verifier.

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from biasops.saga.attestation import (
    AgentAttestation,
    AttestationStatus,
    ContextScope,
    DelegationPolicy,
    ModelConstraint,
    SkillAttestation,
)
from biasops.saga.registry import AttestationRegistry, AttestationLoadError
from biasops.saga.verifier import SAGAVerifier


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)
FUTURE = NOW + timedelta(days=180)
PAST = NOW - timedelta(days=1)


def make_skill(
    name: str = "freeze_account",
    jurisdictions: list[str] | None = None,
    risk_levels: list[str] | None = None,
    data_types: list[str] | None = None,
    approved_models: list[str] | None = None,
    prohibited_models: list[str] | None = None,
    delegation: DelegationPolicy = DelegationPolicy.NONE,
    allowed_delegates: list[str] | None = None,
    expires_in: timedelta = timedelta(days=180),
    requires_human_review: bool = False,
) -> SkillAttestation:
    return SkillAttestation(
        name=name,
        attested_by="sarah.chen@acme.com",
        attested_by_role="Model Validation Lead",
        attested_on=NOW - timedelta(days=1),
        valid_until=NOW + expires_in,
        context_scope=ContextScope(
            jurisdictions=jurisdictions or [],
            risk_levels=risk_levels or [],
            data_types=data_types or [],
            requires_human_review=requires_human_review,
        ),
        model_constraints=ModelConstraint(
            approved=approved_models or [],
            prohibited=prohibited_models or [],
        ),
        delegation=delegation,
        allowed_delegates=allowed_delegates or [],
    )


def make_agent(
    agent_id: str = "fraud-investigator-v2",
    skills: list[SkillAttestation] | None = None,
    revoked: bool = False,
    revoke_reason: str = "",
) -> AgentAttestation:
    return AgentAttestation(
        agent_id=agent_id,
        tenant="acme-prod",
        version="2.1.4",
        created_at=NOW - timedelta(days=30),
        skills=skills or [make_skill()],
        revoked=revoked,
        revoke_reason=revoke_reason,
    )


@pytest.fixture()
def registry(tmp_path):
    reg = AttestationRegistry(attestations_dir=tmp_path / "attestations")
    reg.register(make_agent())
    return reg


@pytest.fixture()
def verifier(registry):
    return SAGAVerifier(registry)


# ---------------------------------------------------------------------------
# AttestationStatus checks
# ---------------------------------------------------------------------------


def test_valid_skill_is_authorized(verifier):
    result = verifier.verify("fraud-investigator-v2", "freeze_account")
    assert result.status == AttestationStatus.VALID
    assert result.is_authorized


def test_unknown_agent(verifier):
    result = verifier.verify("nonexistent-agent", "freeze_account")
    assert result.status == AttestationStatus.UNKNOWN
    assert not result.is_authorized


def test_unknown_skill(verifier):
    result = verifier.verify("fraud-investigator-v2", "delete_database")
    assert result.status == AttestationStatus.UNKNOWN
    assert not result.is_authorized


def test_revoked_agent(verifier, registry):
    revoked = make_agent(revoked=True, revoke_reason="Security incident 2026-03-01")
    registry.register(revoked)
    result = verifier.verify("fraud-investigator-v2", "freeze_account")
    assert result.status == AttestationStatus.REVOKED
    assert "Security incident" in result.reasons[0]


def test_expired_skill(registry):
    agent = make_agent(
        skills=[
            SkillAttestation(
                name="freeze_account",
                attested_by="sarah.chen@acme.com",
                attested_by_role="Model Validation Lead",
                attested_on=NOW - timedelta(days=10),   # attested 10 days ago
                valid_until=NOW - timedelta(seconds=1),  # expired 1 second ago
            )
        ]
    )
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify("fraud-investigator-v2", "freeze_account")
    assert result.status == AttestationStatus.EXPIRED
    assert "expired" in result.reasons[0].lower()


# ---------------------------------------------------------------------------
# Context scope checks
# ---------------------------------------------------------------------------


def test_jurisdiction_in_scope(registry):
    agent = make_agent(skills=[make_skill(jurisdictions=["US", "UK"])])
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"jurisdiction": "US"}
    )
    assert result.is_authorized


def test_jurisdiction_out_of_scope(registry):
    agent = make_agent(skills=[make_skill(jurisdictions=["US", "UK"])])
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"jurisdiction": "EU"}
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE
    assert not result.is_authorized
    assert "EU" in " ".join(result.reasons)


def test_risk_level_out_of_scope(registry):
    agent = make_agent(skills=[make_skill(risk_levels=["low", "medium"])])
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"risk_level": "high"}
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE


def test_no_scope_restriction_passes_any_context(verifier):
    # Empty scope lists = no restriction
    result = verifier.verify(
        "fraud-investigator-v2",
        "freeze_account",
        {"jurisdiction": "EU", "risk_level": "high"},
    )
    assert result.is_authorized


def test_requires_human_review_propagates(registry):
    agent = make_agent(
        skills=[make_skill(requires_human_review=True)]
    )
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify("fraud-investigator-v2", "freeze_account", {})
    assert result.is_authorized
    assert result.requires_human_review is True


# ---------------------------------------------------------------------------
# Model constraint checks
# ---------------------------------------------------------------------------


def test_approved_model_passes(registry):
    agent = make_agent(
        skills=[make_skill(approved_models=["gpt-4o-validated-v2"])]
    )
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"model": "gpt-4o-validated-v2"}
    )
    assert result.is_authorized


def test_prohibited_model_denied(registry):
    agent = make_agent(
        skills=[make_skill(prohibited_models=["gpt-4o-latest"])]
    )
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"model": "gpt-4o-latest"}
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE
    assert "gpt-4o-latest" in " ".join(result.reasons)


def test_unapproved_model_denied_when_allowlist_set(registry):
    agent = make_agent(
        skills=[make_skill(approved_models=["gpt-4o-validated-v2"])]
    )
    registry.register(agent)
    verifier = SAGAVerifier(registry)
    result = verifier.verify(
        "fraud-investigator-v2", "freeze_account", {"model": "some-random-model"}
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE


def test_no_model_in_context_skips_model_check(verifier):
    # No model key in context = skip model check
    result = verifier.verify("fraud-investigator-v2", "freeze_account", {})
    assert result.is_authorized


# ---------------------------------------------------------------------------
# Delegation checks
# ---------------------------------------------------------------------------


def test_delegation_none_blocks_delegation(registry):
    caller = make_agent(
        agent_id="caller-agent",
        skills=[make_skill(delegation=DelegationPolicy.NONE)],
    )
    called = make_agent(agent_id="called-agent")
    registry.register(caller)
    registry.register(called)
    verifier = SAGAVerifier(registry)

    result = verifier.verify_delegation(
        "caller-agent", "called-agent", "freeze_account"
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE
    assert "delegation=NONE" in " ".join(result.reasons)


def test_delegation_allowlist_permits_listed_agent(registry):
    caller = make_agent(
        agent_id="caller-agent",
        skills=[
            make_skill(
                delegation=DelegationPolicy.ALLOWLIST,
                allowed_delegates=["called-agent"],
            )
        ],
    )
    called = make_agent(agent_id="called-agent")
    registry.register(caller)
    registry.register(called)
    verifier = SAGAVerifier(registry)

    result = verifier.verify_delegation(
        "caller-agent", "called-agent", "freeze_account"
    )
    assert result.is_authorized


def test_delegation_allowlist_blocks_unlisted_agent(registry):
    caller = make_agent(
        agent_id="caller-agent",
        skills=[
            make_skill(
                delegation=DelegationPolicy.ALLOWLIST,
                allowed_delegates=["allowed-agent"],
            )
        ],
    )
    registry.register(caller)
    verifier = SAGAVerifier(registry)

    result = verifier.verify_delegation(
        "caller-agent", "not-allowed-agent", "freeze_account"
    )
    assert result.status == AttestationStatus.OUT_OF_SCOPE


def test_delegation_any_allows_any_attested_agent(registry):
    caller = make_agent(
        agent_id="caller-agent",
        skills=[make_skill(delegation=DelegationPolicy.ANY)],
    )
    called = make_agent(agent_id="called-agent")
    registry.register(caller)
    registry.register(called)
    verifier = SAGAVerifier(registry)

    result = verifier.verify_delegation(
        "caller-agent", "called-agent", "freeze_account"
    )
    assert result.is_authorized


# ---------------------------------------------------------------------------
# AttestationRegistry
# ---------------------------------------------------------------------------


def test_registry_loads_from_file():
    attestations_dir = Path("attestations")
    if not attestations_dir.exists():
        pytest.skip("No attestations directory found")
    reg = AttestationRegistry(attestations_dir=attestations_dir)
    agents = reg.list_agents()
    assert len(agents) > 0


def test_registry_get_known_agent(registry):
    agent = registry.get("fraud-investigator-v2")
    assert agent is not None
    assert agent.agent_id == "fraud-investigator-v2"


def test_registry_get_unknown_returns_none(registry):
    assert registry.get("does-not-exist") is None


def test_registry_save_and_reload(tmp_path):
    reg = AttestationRegistry(attestations_dir=tmp_path / "att")
    agent = make_agent(agent_id="test-save-agent")
    reg.save(agent)

    # New registry instance picks it up from disk
    reg2 = AttestationRegistry(attestations_dir=tmp_path / "att")
    loaded = reg2.get("test-save-agent")
    assert loaded is not None
    assert loaded.tenant == "acme-prod"


def test_registry_list_agents(registry):
    agents = registry.list_agents()
    assert "fraud-investigator-v2" in agents


# ---------------------------------------------------------------------------
# Real attestation file — fraud-investigator-v2
# ---------------------------------------------------------------------------


def test_real_attestation_loads():
    attestations_dir = Path("attestations")
    if not attestations_dir.exists():
        pytest.skip("No attestations directory found")
    reg = AttestationRegistry(attestations_dir=attestations_dir)
    agent = reg.get("fraud-investigator-v2")
    assert agent is not None
    assert "freeze_account" in agent.skill_names()
    assert "summarize_transaction" in agent.skill_names()


def test_real_attestation_eu_freeze_denied():
    """The real attestation denies freeze_account in EU — our demo scenario."""
    attestations_dir = Path("attestations")
    if not attestations_dir.exists():
        pytest.skip("No attestations directory found")
    reg = AttestationRegistry(attestations_dir=attestations_dir)
    verifier = SAGAVerifier(reg)

    result = verifier.verify(
        "fraud-investigator-v2",
        "freeze_account",
        {"jurisdiction": "EU", "model": "gpt-4o-validated-v2", "risk_level": "high"},
    )
    assert not result.is_authorized
    assert result.status == AttestationStatus.OUT_OF_SCOPE


def test_real_attestation_us_freeze_allowed():
    """The real attestation allows freeze_account in US at low risk."""
    attestations_dir = Path("attestations")
    if not attestations_dir.exists():
        pytest.skip("No attestations directory found")
    reg = AttestationRegistry(attestations_dir=attestations_dir)
    verifier = SAGAVerifier(reg)

    result = verifier.verify(
        "fraud-investigator-v2",
        "freeze_account",
        {
            "jurisdiction": "US",
            "risk_level": "low",
            "data_type": "financial",
            "environment": "production",
            "model": "gpt-4o-validated-v2",
        },
    )
    assert result.is_authorized


def test_real_attestation_summarize_is_global():
    """summarize_transaction has no scope restrictions — valid everywhere."""
    attestations_dir = Path("attestations")
    if not attestations_dir.exists():
        pytest.skip("No attestations directory found")
    reg = AttestationRegistry(attestations_dir=attestations_dir)
    verifier = SAGAVerifier(reg)

    result = verifier.verify(
        "fraud-investigator-v2",
        "summarize_transaction",
        {"jurisdiction": "EU", "risk_level": "high", "environment": "production"},
    )
    assert result.is_authorized
