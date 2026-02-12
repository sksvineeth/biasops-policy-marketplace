# quickstart.py — Minimal example showing how to load and evaluate a policy.
# Usage: python examples/quickstart.py

"""
from biasops.loader import load_policy
from biasops.engine import evaluate

policy = load_policy("policies/builtin/fairness_basic.yaml")
result = evaluate(policy, data={"predictions": [], "labels": [], "groups": []})
print(result)
"""
