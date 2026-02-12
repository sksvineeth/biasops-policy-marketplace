# BiasOps Policy Marketplace

> Policy-as-code infrastructure for AI governance. Version-controlled, testable, and executable compliance policies for ML engineers, compliance officers, and audit teams.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-94%20passing-brightgreen.svg)]()
[![Policies](https://img.shields.io/badge/policies-3%20active-orange.svg)]()

---

## What is BiasOps?

BiasOps is an open-source policy marketplace for AI governance. It lets you express compliance requirements — GDPR, EEOC, FCPA, EU AI Act, and more — as structured YAML files that can be version-controlled, tested, and executed automatically in your CI/CD pipeline.

Think of it like this: Terraform does for infrastructure what BiasOps does for AI compliance. Instead of manually reviewing PDFs and hoping engineers interpreted them correctly, you write a policy file once, check it into git, and it runs automatically against every model you deploy.

---

## The Problem BiasOps Solves

**Compliance lives in PDFs, not pipelines**

GDPR Article 22, the EU AI Act, EEOC Title VII — these are documents. They have no way to enforce themselves. The gap between "we have a compliance policy" and "we enforce a compliance policy" is where every AI governance failure happens.

**Every company rebuilds the same policies from scratch**

Right now, every bank, every insurer, every enterprise building AI is independently writing their own fair lending checks, their own GDPR transparency gates, their own SOX model controls. That is massively duplicated effort across the industry. BiasOps is the shared library the industry is missing.

**Governance and engineering teams speak different languages**

Legal says "ensure equalized odds across protected classes." Engineering says "what does that mean in code?" There is no translation layer. Policies get lost between the two teams and models ship without proper checks. BiasOps is the translation layer.

**Audit trails are an afterthought**

When regulators come asking, companies scramble to reconstruct what their models were doing. A policy-as-code repo with git history, test results, and deployment logs is a native audit trail — not something you build after the fact.

---

## How BiasOps Works
Step 1 — Write or import a policy YAML file
policies/gdpr/gdpr_article22_automated_decision.yaml

Step 2 — Point BiasOps at your model metadata
biasops scan policies/ my_model_metadata.json

Step 3 — Policies run automatically against the model
Engine checks every threshold and requirement

Step 4 — Violations surface with citations and fix instructions
[CRITICAL] GDPR-ART22-001 — Human oversight not documented
Regulation: GDPR Article 22
Fix: Document human oversight process in model card

Step 5 — Git history becomes your compliance audit trail
Every policy version, scan result, and violation
is timestamped and traceable


---

## Quickstart

### Install
```bash
pip install biasops
```

### Validate a policy file

Check that a policy file is correctly structured before committing it:
```bash
biasops validate policies/enterprise-compliance/gdpr/gdpr_article22_automated_decision.yaml
```

Output:
✓ VALID: gdpr_article22_automated_decision.yaml


### Create your model metadata file

Create a JSON file describing your model and its compliance properties:
```json
{
  "model_id": "credit-scoring-v2",
  "model_type": "XGBoost classifier",
  "decision_impact": "significant",
  "human_oversight_present": false,
  "explainability_score": 0.45,
  "right_to_contest_documented": false,
  "data_minimization_compliant": true,
  "transparency_notice_provided": false,
  "selection_rate_disparity": 0.65,
  "demographic_proxy_variables": false,
  "adverse_action_documented": true,
  "bias_audit_completed": false,
  "protected_class_analysis_completed": false
}
```

### Scan your model against all policies
```bash
biasops scan policies/ my_model_metadata.json
```

Output:
Status: FAIL ✗
Policies evaluated: 2
Violations found: 4

[CRITICAL] GDPR-ART22-001 — human_oversight_present must be true
Regulation: GDPR Article 22 - Automated individual decision-making
Fix: Document human oversight process in model card

[CRITICAL] GDPR-ART22-001 — explainability_score below minimum threshold 0.65
Regulation: GDPR Article 22 - Automated individual decision-making
Fix: Implement explainability layer (SHAP or LIME) and ensure score >= 0.65

[CRITICAL] GDPR-ART22-001 — right_to_contest_documented must be true
Regulation: GDPR Article 22 - Automated individual decision-making
Fix: Add right-to-contest mechanism in the user-facing application

[CRITICAL] EEOC-TITLE7-001 — selection_rate_disparity below 80% rule threshold
Regulation: Title VII Civil Rights Act 1964
Fix: Conduct adverse impact analysis across all protected classes


### List all available policies
```bash
biasops list policies/
```

Output:
ID                  Name                              Domain            Risk      Enforcement
GDPR-ART22-001      GDPR Article 22 Automated         enterprise        CRITICAL  block
EEOC-TITLE7-001     EEOC Title VII Hiring 80% Rule    hr-employment     CRITICAL  block
FCPA-GIFTS-001      FCPA Gifts & Hospitality          enterprise        HIGH      warn

Total: 3 policies


### Check for policy conflicts
```bash
biasops check-conflicts policies/
```

Output:
✓ No conflicts detected across 3 policies


---

## Who Uses BiasOps

**ML Engineers**

Drop BiasOps into your CI/CD pipeline as a deployment gate. Models that violate compliance policies never reach production. One GitHub Action covers every model in your organization. You stop writing one-off compliance scripts and start using shared, community-maintained rules.

**Compliance Officers**

Write policy intent in structured YAML without writing a single line of Python. Your compliance requirements run automatically across every model in the organization. When a model violates a rule you wrote, you get a report with the exact violation, the regulation it breaches, and the steps to fix it.

**Audit and Legal Teams**

When a regulator asks how you ensure your credit model does not discriminate, you hand them a versioned policy repository with a git history showing when each policy was added, who approved it, what tests it passed, and which models it was applied to. That is audit-ready evidence, not a PowerPoint deck.

**Consultants and System Integrators**

Start client engagements with pre-built, regulation-specific policies instead of building from scratch. The policy marketplace is your catalog. Pick the policies relevant to your client's jurisdiction and industry and deploy in minutes rather than weeks.

---

## Policy Library

BiasOps is a central, growing library of executable compliance policies organized by domain. Each policy is version-controlled, citable, and ready to run against any AI model.

### Enterprise Compliance

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| GDPR-ART22-001 | Automated Decision-Making | GDPR Article 22 | EU | CRITICAL | ✅ Active |
| FCPA-GIFTS-001 | Gifts & Hospitality Thresholds | FCPA / French AFA | US + FR | HIGH | ✅ Active |
| EU-AI-ACT-001 | High Risk System Obligations | EU AI Act Annex III | EU | CRITICAL | 🔜 Coming |
| EU-AI-ACT-002 | Prohibited Practices | EU AI Act Article 5 | EU | CRITICAL | 🔜 Coming |
| SOX-404-001 | ML Model Risk Controls | SOX Section 404 | US | HIGH | 🔜 Coming |
| ISO-42001-001 | AI Management System | ISO/IEC 42001:2023 | Global | MEDIUM | 🔜 Coming |

### HR & Employment

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| EEOC-TITLE7-001 | Hiring Disparate Impact 80% Rule | EEOC Title VII | US | CRITICAL | ✅ Active |
| NYC-LL144-001 | Automated Employment Decisions | NYC Local Law 144 | US-NYC | HIGH | 🔜 Coming |
| IL-AEDT-001 | Bias Audit Requirements | Illinois AEDT | US-IL | HIGH | 🔜 Coming |
| CO-AI-ACT-001 | Employment AI Provisions | Colorado AI Act | US-CO | HIGH | 🔜 Coming |
| ADA-001 | Disability Discrimination in Hiring | ADA Title I | US | CRITICAL | 🔜 Coming |
| ADEA-001 | Age Discrimination 40 Plus | ADEA | US | HIGH | 🔜 Coming |

### Financial Services

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| ECOA-001 | Fair Lending Disparate Impact | ECOA / Reg B | US | CRITICAL | 🔜 Coming |
| FHA-001 | Credit Scoring Fairness | Fair Housing Act | US | CRITICAL | 🔜 Coming |
| CFPB-001 | Adverse Action Notice Requirements | CFPB Guidelines | US | HIGH | 🔜 Coming |
| SEC-AI-001 | Investment Model Risk | SEC AI Guidance | US | HIGH | 🔜 Coming |
| AML-001 | Transaction Monitoring Bias | BSA / FinCEN | US | HIGH | 🔜 Coming |
| BASEL-001 | Model Risk Management | Basel III SR 11-7 | Global | HIGH | 🔜 Coming |

### Healthcare

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| HIPAA-ML-001 | ML Model Data Minimization | HIPAA Privacy Rule | US | CRITICAL | 🔜 Coming |
| CA-AB3030-001 | GenAI Patient Communications | California AB 3030 | US-CA | HIGH | 🔜 Coming |
| FDA-SAMD-001 | AI/ML Medical Device Software | FDA SaMD Guidance | US | CRITICAL | 🔜 Coming |
| DIAG-FAIR-001 | Diagnostic Model Fairness | HHS Equity Guidelines | US | HIGH | 🔜 Coming |

### Climate & ESG

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| J40-001 | Benefit Equity 40% Rule | Justice40 Initiative | US Federal | HIGH | 🔜 Coming |
| TCFD-001 | Climate Risk Model Disclosure | TCFD Framework | Global | MEDIUM | 🔜 Coming |
| EU-TAX-001 | Green Claims Validation | EU Taxonomy | EU | HIGH | 🔜 Coming |
| CARBON-001 | Carbon Credit Verification Bias | Voluntary Carbon Markets | Global | MEDIUM | 🔜 Coming |

### Space & Emerging Technology

| ID | Policy | Regulation | Jurisdiction | Risk | Status |
|---|---|---|---|---|---|
| ITAR-001 | Export Control AI Restrictions | ITAR / EAR | US | CRITICAL | 🔜 Coming |
| FAA-AUTO-001 | Autonomous Systems Safety | FAA Guidance | US | CRITICAL | 🔜 Coming |
| SPACE-LIC-001 | Space Licensing Equity | FCC / FAA | US | MEDIUM | 🔜 Coming |
| SCSP-001 | National Security AI Governance | SCSP AI Guidelines | US | CRITICAL | 🔜 Coming |

> Want a policy that is not listed? Open an issue or submit a pull request. See CONTRIBUTING.md for the full submission guide.

---

## Writing a Policy

Every policy follows the same schema. Copy templates/policy_template.yaml and fill in your regulation:
```yaml
# ─────────────────────────────────────────────
# BiasOps Policy File
# ─────────────────────────────────────────────

# Unique identifier — Format: DOMAIN-REGULATION-NUMBER
id: MY-POLICY-001

# Human readable name
name: My Compliance Policy

# Semantic version — increment when thresholds or logic change
version: 1.0.0

# Domain: enterprise-compliance | hr-employment | financial-services
#         healthcare | climate | space-policy
domain: financial-services

# Geographic jurisdiction: EU | US | US-CA | US-NYC | Global
jurisdiction: US

# Risk level: LOW | MEDIUM | HIGH | CRITICAL
risk_level: HIGH

# Enforcement: warn | block | audit
# warn  — log violation, allow model to proceed
# block — fail scan, block deployment
# audit — log for review, do not block
enforcement_mode: block

maintained_by: Your Name or Team

applies_to:
  - credit scoring models
  - loan approval systems

bias_types_addressed:
  - disparate-impact
  - demographic-proxy

regulation_references:
  - article: "Regulation Name and Section"
    url: "https://link-to-official-regulation"
    jurisdiction: US

# Threshold types supported:
# _max_threshold    model value must be BELOW this number
# _min_threshold    model value must be ABOVE this number
# _must_be_true     metadata field must equal true
# _must_be_false    metadata field must equal false
# _block_threshold  value above this triggers CRITICAL block
# _warn_threshold   value above this triggers HIGH warning
policy_logic:
  my_metric_max_threshold: 0.80
  my_flag_must_be_true: true
  my_risk_score_block_threshold: 0.95
  my_risk_score_warn_threshold: 0.75

remediation_steps:
  - "Step 1: What to do first to fix this violation"
  - "Step 2: What to do next"
  - "Step 3: How to verify the fix worked"

created_at: "2026-01-01T00:00:00Z"
```

---

## CI/CD Integration

Add BiasOps as a deployment gate in your GitHub Actions pipeline. Any model that violates a CRITICAL policy is blocked from deploying automatically.
```yaml
name: BiasOps Policy Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  biasops-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install BiasOps
        run: pip install biasops

      - name: Validate all policies
        run: biasops validate policies/

      - name: Scan model against policies
        run: biasops scan policies/ model_metadata.json
```

---

## Architecture
biasops-policy-marketplace/
│
├── biasops/                    Core Python package
│   ├── models.py               Pydantic data models
│   │                           Policy, Violation, PolicyReport
│   ├── loader.py               YAML policy file parser
│   │                           Converts files into Policy objects
│   ├── validator.py            JSON Schema validation
│   │                           Checks policy files are well-formed
│   │                           Detects conflicts between policies
│   ├── engine.py               Policy evaluation engine
│   │                           Runs policies against model metadata
│   │                           Generates violations and reports
│   ├── cli.py                  Terminal interface
│   │                           validate, scan, list, check-conflicts
│   └── api.py                  FastAPI REST service
│                               HTTP endpoints for remote scanning
│
├── policies/                   The policy library
│   ├── enterprise-compliance/  GDPR, EU AI Act, FCPA, SOX
│   ├── hr-employment/          EEOC, NYC LL144, Colorado AI Act
│   ├── financial-services/     ECOA, Fair Housing, CFPB
│   ├── healthcare/             HIPAA, FDA SaMD, AB 3030
│   ├── climate/                Justice40, TCFD, EU Taxonomy
│   └── space-policy/           ITAR, FAA, FCC, SCSP
│
├── schemas/                    JSON Schemas
│   ├── policy_schema.json      Validates policy YAML structure
│   ├── rule_schema.json        Validates individual rules
│   └── evaluation_schema.json  Validates scan output
│
├── templates/                  Starter templates
│   └── policy_template.yaml    Copy this to write a new policy
│
├── tests/                      94 passing tests
│   ├── test_models.py
│   ├── test_loader.py
│   ├── test_validator.py
│   ├── test_engine.py
│   └── test_cli.py
│
└── examples/                   Runnable demos
├── quickstart.py
└── custom_policy.yaml


---

## Contributing

BiasOps grows through community contributions. The most valuable contribution you can make is adding a new policy for a regulation you know well.

**How to contribute a policy**

1. Fork the repository
2. Copy templates/policy_template.yaml to the correct domain folder
3. Fill in all required fields following the schema
4. Run biasops validate on your file locally to check it passes
5. Open a pull request with a description of the regulation covered and why it matters

**What makes a good policy**

A good BiasOps policy must cite a real, publicly available regulation with a direct URL to the official text. It must have clear, actionable remediation steps that tell engineers exactly what to fix and how. It must pass schema validation without errors. Thresholds must be grounded in the actual regulation text, not arbitrary numbers.

**Most needed right now**

- EU AI Act High Risk System Obligations
- Fair Lending Disparate Impact under ECOA
- NYC Local Law 144 Automated Employment Decisions
- Justice40 Benefit Equity for climate programs
- SOX Section 404 Model Risk Controls

See CONTRIBUTING.md for the full submission guide, schema requirements, and review process.

---

## Roadmap

- [x] Core policy evaluation engine with threshold logic
- [x] CLI with validate, scan, list, check-conflicts commands
- [x] Pydantic data models for Policy, Violation, PolicyReport
- [x] JSON Schema validation for policy files
- [x] Conflict detection between loaded policies
- [x] GDPR Article 22 seed policy
- [x] EEOC Title VII hiring disparate impact seed policy
- [x] 94 passing unit and integration tests
- [ ] FCPA Gifts and Hospitality policy
- [ ] EU AI Act High Risk System Obligations policy
- [ ] FastAPI REST service with scan and validate endpoints
- [ ] PyPI package publish
- [ ] GitHub Actions policy validation workflow
- [ ] Policy versioning and deprecation system
- [ ] Web UI policy browser
- [ ] Policy search and filtering API
- [ ] Community policy submission portal

---

## License

Apache 2.0 — free to use, modify, and distribute in both commercial and open-source projects.

---

## Built By

**Vineeth Reddy** — Principal ML Engineer, AI Governance Researcher

7+ years building enterprise AI systems. Led anomaly detection platforms documenting $50M+ in risk avoidance. IEEE Senior Member Candidate. Speaker at MLWeek 2026 on AI governance topics. Accepted into SCSP AI+Space program. AI advisor to educational institutions.

BiasOps is the open-source foundation of a larger AI governance platform focused on making compliance infrastructure as robust and community-driven as software infrastructure.

If you are building compliance infrastructure for regulated industries and want to collaborate, open an issue or reach out directly.

[GitHub](https://github.com/sksvineeth) · [LinkedIn](https://linkedin.com/in/sksvineeth)
