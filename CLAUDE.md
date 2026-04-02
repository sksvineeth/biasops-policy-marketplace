# BiasOps Policy Marketplace — Agent Instructions

## What Is This Repo?

Open-source policy-as-code marketplace for AI governance. Contains YAML policy files, a Python policy engine (evaluator, adapter, registry, SAGA framework, runtime enforcer), an MCP server, and CI/CD validation. Policies are versioned, composable, and machine-readable — the engine evaluates ML models against regulatory thresholds and produces signed audit artifacts.

GitHub: github.com/sksvineeth/biasops-policy-marketplace

## Architecture

```
biasops-policy-marketplace/
├── biasops/                    # Python policy engine
│   ├── api.py                  # FastAPI routes
│   ├── engine.py               # Core evaluation engine
│   ├── registry.py             # Policy registry (load, validate, search)
│   ├── saga/                   # SAGA framework (Skill Attestation & Governance Architecture)
│   ├── runtime/                # Runtime enforcer
│   └── __init__.py
├── policies/                   # YAML policy files (the marketplace content)
│   ├── enterprise-compliance/
│   │   └── eu-ai-act/          # 5 EU AI Act policies
│   └── hr-employment/
│       └── hiring-bias/        # 4 US hiring policies (EEOC, NYC LL144, IL, CO)
├── schemas/
│   └── policy_schema.json      # JSON Schema for policy YAML validation
├── templates/                  # Policy authoring templates
├── examples/
│   └── eu_ai_act_demo/         # Demo scanner with model metadata
├── tests/                      # pytest test suite
├── mcp_server/                 # MCP server for Claude Desktop integration
├── docs/                       # Documentation
├── .github/workflows/ci.yml    # CI: ruff + pytest on Python 3.10/3.11/3.12
└── run_mcp.sh                  # MCP server launcher
```

## Policy Schema (v2.0.0)

Every policy YAML follows the structured rules-array schema:

```yaml
id: POLICY-ID-001
name: Human-Readable Name
version: 2.0.0
domain: hr-employment | enterprise-compliance
jurisdiction: US | EU | US-NY-NYC | US-CO
risk_level: CRITICAL | HIGH | MEDIUM
enforcement_mode: block | warn

rules:
  - id: RULE-001
    name: Rule Name
    type: numeric | attestation | conditional_numeric
    metric_id: adverse_impact_ratio    # maps to adapter.py output key
    stage: pre_training | post_training | pre_deployment
    severity: BLOCK | WARN
    threshold: 0.80
    operator: ">=" | "<=" | ">" | "<" | "=="
    threshold_provenance:
      source: "Citation"
      confidence: HIGH | MEDIUM | LOW
```

Key design: `metric_id` is the binding between policy YAML and computation. If `metric_id` doesn't match an adapter output key, the rule is SKIPPED with a warning.

For rules binding multiple metrics, use `metric_ids` array:
```yaml
    metric_ids:
      - id: air
        metric_id: adverse_impact_ratio
      - id: acc
        metric_id: overall_accuracy
```

## Active Policies

### EU AI Act (5 policies)
| ID | File | Version |
|----|------|---------|
| EU-AI-ACT-001 | eu_ai_act_high_risk_system.yaml | 1.2.0 |
| EU-AI-ACT-002 | eu_ai_act_prohibited_practices.yaml | 1.2.0 |
| EU-AI-ACT-003 | eu_ai_act_high_risk_llm_application.yaml | 1.2.0 |
| EU-AI-ACT-004 | eu_ai_act_gpai.yaml | 1.0.0 |
| EU-AI-ACT-005 | eu_ai_act_environmental.yaml | 1.0.0 |

### US Hiring (4 policies)
| ID | File | Version |
|----|------|---------|
| EEOC-TITLE7-001 | eeoc_title7_hiring_disparate_impact.yaml | 2.0.0 |
| NYC-LL144-001 | nyc_local_law_144.yaml | 1.0.0 |
| IL-HB3773-001 | illinois_hb3773.yaml | 1.0.0 |
| CO-SB24205-001 | colorado_ai_act_hiring.yaml | 1.0.0 |

### Financial Services (5 policies)
| ID | File |
|----|------|
| ECOA-001 | ecoa_fair_lending.yaml |
| HMDA-001 | hmda_reporting.yaml |
| CFPB-001 | cfpb_adverse_action.yaml |
| SR11-7-001 | sr11_7_model_risk.yaml |
| FHA-001 | fha_fair_housing.yaml |

## Tech Stack

- Python 3.10+ (strict: no 3.9 features relied upon, but >=3.10 required)
- FastAPI (API server)
- Pydantic (policy model validation)
- PyYAML (policy parsing)
- fairlearn (bias metrics computation)
- scikit-learn (model evaluation)
- FastMCP 3.1+ (MCP server, requires Python 3.12)
- pytest + pytest-cov (testing)
- ruff (linting)

## Code Conventions

### Python Style
- `from __future__ import annotations` in every file
- Snake case for functions/variables, PascalCase for classes
- Type hints on all function signatures
- Frozen dataclasses for immutable value objects where applicable
- No unused imports (ruff F401 enforced in CI)
- No multi-statement lines (ruff E701/E702 enforced)
- `bool()` cast on all numpy comparison results to avoid `numpy.bool_` identity issues
- Prefer `==` over `is` for value comparisons (except `None` checks)

### Policy YAML Style
- Comments with `# ===` section headers for visual structure
- Every numeric rule must have `metric_id` matching an adapter.py output key
- `threshold_provenance` with `source` and `confidence` on every threshold
- `remediation` field on every rule describing the fix
- Version in `version` field, track changes in `changelog` array

### Testing
- pytest with `--cov=biasops` in CI
- Test files: `test_*.py` in `tests/`
- Every policy file must parse without error (tested in `test_policies.py`)
- Version assertions in tests must match policy YAML versions

### Git Rules
- NEVER add Co-authored-by trailers to any commits
- NEVER modify git config
- Conventional commits: `feat:`, `fix:`, `docs:`, `ci:`, `test:`, `style:`, `chore:`
- Push to `main` branch directly (no PR workflow for solo dev)

## CI Pipeline

GitHub Actions on push/PR to `main`:
1. Matrix: Python 3.10, 3.11, 3.12
2. `pip install -e ".[dev]"`
3. `ruff check .`
4. `pytest --cov=biasops`

## Related Repos

- **biasops-sdk** (`~/biasops-sdk/`) — pip-installable SDK with bundled policies, `biasops.eval()` API
- **biasops-saas** (`~/biasops-saas/`) — SaaS platform (Next.js + FastAPI)
- **biasOps-site** (`~/biasOps-site/`) — Landing page at biasops.ai

## Common Operations

### Add a new policy
1. Create YAML in appropriate `policies/` subdirectory
2. Follow v2.0.0 rules-array schema
3. Add to `test_policies.py` if needed
4. Update README.md policy table
5. Commit, push, verify CI passes

### Update policy version
1. Bump `version` field in YAML
2. Add changelog entry
3. Update `test_policies.py` version assertion
4. Update README table

### Run tests locally
```bash
pip install -e ".[dev]"
ruff check .
pytest --cov=biasops
```

## Important Warnings

- The `biasops/` package in this repo shadows the pip-installed `biasops` SDK. When running SDK tests, do NOT run from this directory.
- MCP server requires Python 3.12+ (fastmcp dependency). Use `/opt/homebrew/bin/python3.12`.
- The `run_mcp.sh` wrapper exists because Claude Desktop doesn't respect `cwd` in its config.
