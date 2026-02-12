# api.py — FastAPI application exposing the marketplace as a REST service.
# Endpoints: POST /validate, POST /evaluate, GET /policies, POST /policies.

from fastapi import FastAPI

app = FastAPI(title="BiasOps Policy Marketplace API", version="0.1.0")


@app.get("/policies")
async def list_policies():
    """Return all available policies."""
    raise NotImplementedError


@app.post("/validate")
async def validate_policy():
    """Validate a submitted policy document."""
    raise NotImplementedError


@app.post("/evaluate")
async def evaluate_policy():
    """Evaluate a policy against submitted data."""
    raise NotImplementedError
