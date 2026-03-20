# api.py — FastAPI application exposing the marketplace as a REST service.
# Endpoints: GET /policies, GET /policies/{id}, POST /validate, POST /evaluate,
#            POST /evaluate/domain, POST /evaluate/jurisdiction, GET /health

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from biasops.engine import PolicyEngine
from biasops.loader import PolicyLoadError, load_policy_from_dict
from biasops.models import Policy, PolicyReport
from biasops.registry import PolicyRegistry
from biasops.validator import validate_policy_schema

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BiasOps Policy Marketplace API",
    version="0.1.0",
    description=(
        "Policy-as-code infrastructure for AI governance. "
        "Validate, list, and evaluate bias-detection policies via REST."
    ),
)

_POLICIES_DIR = Path(os.getenv("BIASOPS_POLICIES_DIR", "policies/"))


def _get_registry() -> PolicyRegistry:
    """Return a PolicyRegistry pointed at the configured policies directory."""
    return PolicyRegistry(policies_dir=_POLICIES_DIR)


def _get_engine() -> PolicyEngine:
    """Return a PolicyEngine loaded from the configured policies directory."""
    return PolicyEngine(policies_dir=_POLICIES_DIR)


# ---------------------------------------------------------------------------
# Registry routes
# ---------------------------------------------------------------------------


@app.get("/registry", response_model=list[dict], tags=["registry"])
async def registry_list(
    domain: str | None = None,
    jurisdiction: str | None = None,
    risk_level: str | None = None,
    enforcement_mode: str | None = None,
) -> list[dict]:
    """Browse the policy marketplace with optional filters.

    All query parameters are optional and combine with AND logic.

    - ``domain`` — e.g. ``hiring``, ``financial-services``, ``healthcare``
    - ``jurisdiction`` — e.g. ``EU``, ``US``, ``Global``
    - ``risk_level`` — ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``
    - ``enforcement_mode`` — ``block``, ``warn``, ``audit``
    """
    registry = _get_registry()
    return registry.list_policies(
        domain=domain,
        jurisdiction=jurisdiction,
        risk_level=risk_level,
        enforcement_mode=enforcement_mode,
    )


@app.get("/registry/stats", response_model=dict, tags=["registry"])
async def registry_stats() -> dict:
    """Return aggregate statistics about the policy marketplace.

    Includes total policy count and breakdowns by domain, jurisdiction,
    risk level, and enforcement mode.
    """
    return _get_registry().stats()


@app.get("/registry/search", response_model=list[dict], tags=["registry"])
async def registry_search(q: str) -> list[dict]:
    """Full-text search across policy IDs, names, domains, and regulation refs.

    Args:
        q: Case-insensitive search string (e.g. ``GDPR``, ``hiring``, ``EU``).
    """
    if not q or len(q.strip()) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Search query must be at least 2 characters.",
        )
    return _get_registry().search(q.strip())
    """Return a PolicyEngine loaded from the configured policies directory."""
    return PolicyEngine(policies_dir=_POLICIES_DIR)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class ValidateRequest(BaseModel):
    """Request body for POST /validate."""

    policy: dict = Field(..., description="Raw policy document to validate.")


class ValidateResponse(BaseModel):
    """Response for POST /validate."""

    is_valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EvaluateRequest(BaseModel):
    """Request body for POST /evaluate."""

    model_metadata: dict[str, Any] = Field(
        ...,
        description="Key/value pairs describing the model under evaluation.",
        examples=[{"demographic_parity": 0.12, "has_bias_audit": True}],
    )


class EvaluateDomainRequest(EvaluateRequest):
    """Request body for POST /evaluate/domain."""

    domain: str = Field(..., description="Domain to filter policies by.", examples=["hiring"])


class EvaluateJurisdictionRequest(EvaluateRequest):
    """Request body for POST /evaluate/jurisdiction."""

    jurisdiction: str = Field(
        ..., description="Jurisdiction to filter policies by.", examples=["EU"]
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Liveness probe — returns OK when the service is running."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/policies", response_model=list[dict], tags=["policies"])
async def list_policies() -> list[dict]:
    """Return summary metadata for every loaded policy.

    Each entry includes ``id``, ``name``, ``version``, ``domain``,
    ``jurisdiction``, ``risk_level``, and ``enforcement_mode``.
    """
    engine = _get_engine()
    return [
        {
            "id": p.id,
            "name": p.name,
            "version": p.version,
            "domain": p.domain,
            "jurisdiction": p.jurisdiction,
            "risk_level": p.risk_level,
            "enforcement_mode": p.enforcement_mode,
            "maintained_by": p.maintained_by,
        }
        for p in engine.get_loaded_policies()
    ]


@app.get("/policies/{policy_id}", response_model=dict, tags=["policies"])
async def get_policy(policy_id: str) -> dict:
    """Return the full document for a single policy by its ID.

    Raises 404 if no policy with that ID is loaded.
    """
    engine = _get_engine()
    policy = engine.get_policy_by_id(policy_id)
    if policy is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found.",
        )
    return policy.model_dump(mode="json")


@app.post("/validate", response_model=ValidateResponse, tags=["policies"])
async def validate_policy(body: ValidateRequest) -> ValidateResponse:
    """Validate a raw policy document against the BiasOps JSON Schema.

    Returns ``is_valid=true`` and an empty ``errors`` list on success.
    On failure, ``errors`` contains one entry per schema violation.
    """
    result = validate_policy_schema(body.policy)
    return ValidateResponse(
        is_valid=result.is_valid,
        errors=result.errors,
        warnings=result.warnings,
    )


@app.post("/evaluate", response_model=dict, tags=["evaluation"])
async def evaluate(body: EvaluateRequest) -> dict:
    """Evaluate model metadata against **all** loaded policies.

    Returns a :class:`PolicyReport` serialised as JSON. The top-level
    ``status`` field is ``"FAIL"`` when at least one blocking violation
    is found, otherwise ``"PASS"``.
    """
    engine = _get_engine()
    if not engine.get_loaded_policies():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No policies loaded. Check BIASOPS_POLICIES_DIR.",
        )
    report: PolicyReport = engine.evaluate(body.model_metadata)
    return report.model_dump(mode="json")


@app.post("/evaluate/domain", response_model=dict, tags=["evaluation"])
async def evaluate_by_domain(body: EvaluateDomainRequest) -> dict:
    """Evaluate model metadata against policies filtered by **domain**.

    Useful when you want to run only hiring, financial-services, or
    healthcare policies against a specific model.
    """
    engine = _get_engine()
    report: PolicyReport = engine.evaluate_by_domain(body.model_metadata, body.domain)
    if not report.policies_evaluated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No policies found for domain '{body.domain}'.",
        )
    return report.model_dump(mode="json")


@app.post("/evaluate/jurisdiction", response_model=dict, tags=["evaluation"])
async def evaluate_by_jurisdiction(body: EvaluateJurisdictionRequest) -> dict:
    """Evaluate model metadata against policies filtered by **jurisdiction**.

    Useful when you want to run only EU, US, or US-CA policies against
    a specific model.
    """
    engine = _get_engine()
    report: PolicyReport = engine.evaluate_by_jurisdiction(
        body.model_metadata, body.jurisdiction
    )
    if not report.policies_evaluated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No policies found for jurisdiction '{body.jurisdiction}'.",
        )
    return report.model_dump(mode="json")
