# EU AI Act Compliance Demo

This demo simulates a real-world scenario: a European bank deploying
an AI-powered loan approval system. Under EU AI Act Annex III, credit
scoring and loan decisioning are classified as HIGH RISK AI systems,
meaning strict compliance obligations apply before deployment.

## The Scenario

**Company:** NordBank AG (fictional European retail bank)
**System:** AutoLend AI — automated loan approval model
**Deployment:** Consumer loan decisions across Germany, France, Netherlands
**Risk Classification:** HIGH RISK under EU AI Act Annex III Article 6

NordBank's ML team built AutoLend AI using XGBoost trained on 3 years
of historical loan data. The model approves or rejects loan applications
in under 2 seconds. Before deploying to production, their compliance
team runs BiasOps to check if the system meets EU AI Act obligations.

## Run the Demo

Step 1 — Install BiasOps:
pip install -e "../.."

Step 2 — Run the compliant scenario (PASS):
python run_scan.py --scenario compliant

Step 3 — Run the non-compliant scenario (FAIL):
python run_scan.py --scenario non_compliant

Step 4 — Run the partial scenario (mixed violations):
python run_scan.py --scenario partial

## What You Will See

The non-compliant scenario shows a model that:
- Has no human oversight mechanism defined
- Has no technical documentation
- Has no conformity assessment completed
- Has accuracy score below the minimum threshold
- Has no post-market monitoring plan

BiasOps catches all of these and blocks deployment with specific
remediation steps citing the exact EU AI Act articles.
