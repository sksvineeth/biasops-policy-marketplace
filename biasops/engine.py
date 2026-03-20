# engine.py — Core policy evaluation engine for the BiasOps Policy Marketplace.
# Loads policies, evaluates model metadata against threshold rules, and
# produces PolicyReport objects aggregating all violations.

from __future__ import annotations

import logging
from pathlib import Path

from biasops.loader import load_policies_from_directory, load_policy
from biasops.models import (
    EnforcementMode,
    Policy,
    PolicyReport,
    ReportStatus,
    RiskLevel,
    ThresholdType,
    Violation,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Suffix → evaluation behaviour mapping
# ---------------------------------------------------------------------------

# Each recognised suffix maps to:
#   (comparison_label, severity_override_or_None)
# When severity_override is ``None`` the policy's own ``risk_level`` is used.
_THRESHOLD_SUFFIXES: dict[str, tuple[str, RiskLevel | None]] = {
    "_max_threshold": ("at or below", None),
    "_min_threshold": ("at or above", None),
    "_must_be_true": ("true", None),
    "_must_be_false": ("false", None),
    "_block_threshold": ("at or below", RiskLevel.CRITICAL),
    "_warn_threshold": ("at or below", RiskLevel.HIGH),
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Loads policies and evaluates model metadata against their rules.

    The engine maintains an internal registry of :class:`Policy` objects
    keyed by ``policy.id``.  Evaluation methods run each applicable policy
    against a ``model_metadata`` dict and return a :class:`PolicyReport`.

    Args:
        policies_dir: Directory to scan for ``.yaml`` policy files at
            construction time.  If the directory does not exist the engine
            starts with an empty registry.
    """

    def __init__(self, policies_dir: str | Path = "policies/") -> None:
        self._registry: dict[str, Policy] = {}

        dirpath = Path(policies_dir)
        if dirpath.exists():
            for policy in load_policies_from_directory(dirpath):
                self._registry[policy.id] = policy
        else:
            logger.warning(
                "Policies directory %s does not exist — starting with an empty registry.",
                dirpath,
            )

    # ------------------------------------------------------------------
    # Registry helpers
    # ------------------------------------------------------------------

    def load_policy(self, path: str | Path) -> Policy:
        """Load a single policy file and add it to the registry.

        Args:
            path: Filesystem path to a ``.yaml`` policy file.

        Returns:
            The validated :class:`Policy` that was added.

        Raises:
            FileNotFoundError: If *path* does not exist.
            PolicyLoadError: If the file is malformed or invalid.
        """
        policy = load_policy(path)
        self._registry[policy.id] = policy
        return policy

    def get_loaded_policies(self) -> list[Policy]:
        """Return all currently loaded policies.

        Returns:
            A list of :class:`Policy` instances in insertion order.
        """
        return list(self._registry.values())

    def get_policy_by_id(self, policy_id: str) -> Policy | None:
        """Look up a specific policy by its identifier.

        Args:
            policy_id: The ``Policy.id`` to search for.

        Returns:
            The matching :class:`Policy`, or ``None`` if not found.
        """
        return self._registry.get(policy_id)

    # ------------------------------------------------------------------
    # Evaluation entry points
    # ------------------------------------------------------------------

    def evaluate(self, model_metadata: dict) -> PolicyReport:
        """Evaluate **all** loaded policies against *model_metadata*.

        Args:
            model_metadata: Key/value pairs describing the model under test
                (e.g. ``{"demographic_parity": 0.12, "has_bias_audit": True}``).

        Returns:
            A :class:`PolicyReport` aggregating every violation found.  The
            report ``status`` is ``FAIL`` when at least one violation comes
            from a policy whose ``enforcement_mode`` is ``block``; otherwise
            ``PASS``.
        """
        return self._run_evaluation(model_metadata, list(self._registry.values()))

    def evaluate_by_domain(self, model_metadata: dict, domain: str) -> PolicyReport:
        """Evaluate only policies matching *domain*.

        Args:
            model_metadata: Model metadata dict.
            domain: The domain string to filter on (e.g. ``"hiring"``).

        Returns:
            A :class:`PolicyReport` for the matching policy subset.
        """
        matching = [p for p in self._registry.values() if p.domain == domain]
        return self._run_evaluation(model_metadata, matching)

    def evaluate_by_jurisdiction(
        self, model_metadata: dict, jurisdiction: str
    ) -> PolicyReport:
        """Evaluate only policies matching *jurisdiction*.

        Args:
            model_metadata: Model metadata dict.
            jurisdiction: The jurisdiction string to filter on (e.g. ``"EU"``).

        Returns:
            A :class:`PolicyReport` for the matching policy subset.
        """
        matching = [p for p in self._registry.values() if p.jurisdiction == jurisdiction]
        return self._run_evaluation(model_metadata, matching)

    # ------------------------------------------------------------------
    # Internal evaluation logic
    # ------------------------------------------------------------------

    def _run_evaluation(
        self, model_metadata: dict, policies: list[Policy]
    ) -> PolicyReport:
        """Shared driver that evaluates a list of policies and builds the report.

        Args:
            model_metadata: Model metadata dict.
            policies: The subset of policies to evaluate.

        Returns:
            A fully populated :class:`PolicyReport`.
        """
        all_violations: list[Violation] = []
        has_block = False

        for policy in policies:
            violations = self._evaluate_single_policy(policy, model_metadata)
            if violations and policy.enforcement_mode == EnforcementMode.BLOCK:
                has_block = True
            all_violations.extend(violations)

        summary: dict[str, int] = {level.value: 0 for level in RiskLevel}
        for v in all_violations:
            summary[v.severity.value] += 1

        return PolicyReport(
            status=ReportStatus.FAIL if has_block else ReportStatus.PASS,
            violations=all_violations,
            summary=summary,
            model_metadata_snapshot=dict(model_metadata),
            policies_evaluated=[p.id for p in policies],
        )

    def _evaluate_single_policy(
        self, policy: Policy, model_metadata: dict
    ) -> list[Violation]:
        """Evaluate one policy against model metadata — handles both formats.

        Evaluates structured ``policy.checks`` first (preferred format), then
        falls back to flat ``policy_logic`` suffix rules (legacy format).

        Args:
            policy: The policy to evaluate.
            model_metadata: Key/value pairs for the model under test.

        Returns:
            A list of :class:`Violation` objects (empty if the policy passes).
        """
        citation = ", ".join(
            f"{ref.jurisdiction} {ref.article}" for ref in policy.regulation_references
        )
        violations: list[Violation] = []
        violations.extend(self._evaluate_checks(policy, model_metadata, citation))
        violations.extend(self._evaluate_policy_logic(policy, model_metadata, citation))
        return violations

    def _evaluate_checks(
        self, policy: Policy, model_metadata: dict, citation: str
    ) -> list[Violation]:
        """Evaluate the structured ``policy.checks`` list.

        Each check explicitly names its metric, comparison type, and threshold.
        Missing metadata keys are logged and skipped.
        """
        violations: list[Violation] = []

        for check in policy.checks:
            if check.metric not in model_metadata:
                logger.warning(
                    "Policy '%s' check '%s': metadata key '%s' not found — skipping.",
                    policy.id, check.name, check.metric,
                )
                continue

            value = model_metadata[check.metric]
            violated = False
            message = ""

            if check.threshold_type == ThresholdType.MIN:
                if value < check.threshold_value:
                    violated = True
                    message = (
                        f"[{check.name}] '{check.metric}' is {value}, "
                        f"below minimum {check.threshold_value}"
                    )
            elif check.threshold_type == ThresholdType.MAX:
                if value > check.threshold_value:
                    violated = True
                    message = (
                        f"[{check.name}] '{check.metric}' is {value}, "
                        f"exceeds maximum {check.threshold_value}"
                    )
            elif check.threshold_type == ThresholdType.MUST_BE_TRUE:
                if value is not True:
                    violated = True
                    message = f"[{check.name}] '{check.metric}' must be true but is {value}"
            elif check.threshold_type == ThresholdType.MUST_BE_FALSE:
                if value is not False:
                    violated = True
                    message = f"[{check.name}] '{check.metric}' must be false but is {value}"
            elif check.threshold_type == ThresholdType.SIGNIFICANCE:
                if value > check.threshold_value:
                    violated = True
                    message = (
                        f"[{check.name}] '{check.metric}' p-value {value} "
                        f"exceeds significance threshold {check.threshold_value}"
                    )

            if violated:
                violations.append(
                    Violation(
                        policy_id=policy.id,
                        severity=check.failure_severity,
                        message=message,
                        regulation_citation=citation,
                        remediation_steps=policy.remediation_steps,
                    )
                )

        return violations

    def _evaluate_policy_logic(
        self, policy: Policy, model_metadata: dict, citation: str
    ) -> list[Violation]:
        """Evaluate flat ``policy_logic`` suffix rules (legacy format).

        Retained for backwards compatibility with policies that do not use
        the structured ``checks`` list.  Iterates over ``policy.policy_logic``
        keys and matches recognised suffixes.
        """
        violations: list[Violation] = []

        for key, threshold in policy.policy_logic.items():
            for suffix, (expectation, severity_override) in _THRESHOLD_SUFFIXES.items():
                if not key.endswith(suffix):
                    continue

                metric = key[: -len(suffix)]
                severity = severity_override if severity_override is not None else policy.risk_level

                if metric not in model_metadata:
                    logger.warning(
                        "Policy '%s': metadata key '%s' not found — skipping check.",
                        policy.id,
                        metric,
                    )
                    break

                value = model_metadata[metric]
                violated = False
                message = ""

                if suffix == "_max_threshold":
                    if value > threshold:
                        violated = True
                        message = (
                            f"'{metric}' is {value}, exceeds max threshold {threshold}"
                        )

                elif suffix == "_min_threshold":
                    if value < threshold:
                        violated = True
                        message = (
                            f"'{metric}' is {value}, below min threshold {threshold}"
                        )

                elif suffix == "_must_be_true":
                    if value is not True:
                        violated = True
                        message = f"'{metric}' must be true but is {value}"

                elif suffix == "_must_be_false":
                    if value is not False:
                        violated = True
                        message = f"'{metric}' must be false but is {value}"

                elif suffix == "_block_threshold":
                    if value > threshold:
                        violated = True
                        message = (
                            f"'{metric}' is {value}, exceeds block threshold {threshold}"
                        )

                elif suffix == "_warn_threshold":
                    if value > threshold:
                        violated = True
                        message = (
                            f"'{metric}' is {value}, exceeds warn threshold {threshold}"
                        )

                if violated:
                    violations.append(
                        Violation(
                            policy_id=policy.id,
                            severity=severity,
                            message=message,
                            regulation_citation=citation,
                            remediation_steps=policy.remediation_steps,
                        )
                    )

                # A key matches at most one suffix — stop checking others.
                break

        return violations
