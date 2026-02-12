# validator.py — Schema and semantic validation for BiasOps policy documents.
# Combines JSON Schema structural checks with cross-policy conflict detection.

from __future__ import annotations

import json
import logging
from itertools import combinations
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, Field

from biasops.models import Policy

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resolve the default schema path once at import time.
# ---------------------------------------------------------------------------

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_DEFAULT_SCHEMA_PATH = _SCHEMA_DIR / "policy_schema.json"


# ---------------------------------------------------------------------------
# Result / warning models
# ---------------------------------------------------------------------------


class ValidationResult(BaseModel):
    """Outcome of validating a single policy document.

    Attributes:
        is_valid: ``True`` when no errors were found.
        errors:   Human-readable, field-level error messages.
        warnings: Non-fatal observations (e.g. deprecated fields).
        filename: The originating file path, if applicable.
    """

    is_valid: bool = Field(
        ...,
        description="True when no errors were found.",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Human-readable field-level error messages.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal observations about the policy.",
    )
    filename: str = Field(
        default="",
        description="Originating file path, if applicable.",
    )


class ConflictWarning(BaseModel):
    """A detected conflict between two policies.

    Attributes:
        policy_id_1:          First policy involved in the conflict.
        policy_id_2:          Second policy involved in the conflict.
        conflict_description: What exactly conflicts (metric, thresholds).
        recommendation:       Suggested resolution.
    """

    policy_id_1: str = Field(
        ...,
        description="First policy involved in the conflict.",
    )
    policy_id_2: str = Field(
        ...,
        description="Second policy involved in the conflict.",
    )
    conflict_description: str = Field(
        ...,
        description="What exactly conflicts between the two policies.",
    )
    recommendation: str = Field(
        ...,
        description="Suggested resolution for the conflict.",
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_json_schema(schema_path: Path) -> dict:
    """Read and parse a JSON Schema file from disk.

    Args:
        schema_path: Absolute or relative path to a ``.json`` schema file.

    Returns:
        The parsed schema as a dict.

    Raises:
        FileNotFoundError: If the schema file does not exist.
    """
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _format_jsonschema_error(error) -> str:
    """Turn a ``jsonschema.ValidationError`` into a one-line human message.

    Args:
        error: A single ``jsonschema`` validation error.

    Returns:
        A string like ``"$.field: 'x' is not valid under ..."``
    """
    path = "$." + ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "$"
    return f"{path}: {error.message}"


def _extract_rules(logic: Any) -> list[dict]:
    """Recursively extract rule dicts that have both 'metric' and 'threshold'.

    Walks the ``policy_logic`` tree — which may nest rules under an
    ``"operator"`` / ``"rules"`` structure — and returns every leaf node
    that looks like a concrete rule (has *metric* and *threshold* keys).

    Args:
        logic: The ``policy_logic`` value (usually a dict or list).

    Returns:
        A flat list of rule dicts containing at least *metric* and *threshold*.
    """
    found: list[dict] = []
    if isinstance(logic, dict):
        if "metric" in logic and "threshold" in logic:
            found.append(logic)
        for value in logic.values():
            found.extend(_extract_rules(value))
    elif isinstance(logic, list):
        for item in logic:
            found.extend(_extract_rules(item))
    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_policy_schema(
    policy_dict: dict,
    schema_path: str | Path | None = None,
) -> ValidationResult:
    """Validate a raw policy dict against the BiasOps JSON Schema.

    Args:
        policy_dict:  The policy data as a plain dictionary.
        schema_path:  Optional override for the JSON Schema file.  Defaults
                      to ``schemas/policy_schema.json`` in the project root.

    Returns:
        A :class:`ValidationResult` summarising errors and warnings.
    """
    resolved = Path(schema_path) if schema_path else _DEFAULT_SCHEMA_PATH
    schema = _load_json_schema(resolved)
    validator = Draft202012Validator(schema)

    errors: list[str] = []
    warnings: list[str] = []

    for error in sorted(validator.iter_errors(policy_dict), key=lambda e: list(e.absolute_path)):
        errors.append(_format_jsonschema_error(error))

    # Non-fatal heuristic checks
    if not errors:
        if not policy_dict.get("applies_to"):
            warnings.append(
                "'applies_to' is empty — this policy will apply to all models."
            )

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def validate_policy_file(path: str | Path) -> ValidationResult:
    """Read a YAML policy file and validate it against the JSON Schema.

    Args:
        path: Filesystem path to a ``.yaml`` policy file.

    Returns:
        A :class:`ValidationResult` with ``filename`` populated.  If the
        file cannot be read or parsed, the result will contain a single
        error describing the problem.
    """
    filepath = Path(path)
    filename = str(filepath)

    if not filepath.exists():
        return ValidationResult(
            is_valid=False,
            errors=[f"{filename}: file not found"],
            filename=filename,
        )

    try:
        data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return ValidationResult(
            is_valid=False,
            errors=[f"{filename}: malformed YAML — {exc}"],
            filename=filename,
        )

    if not isinstance(data, dict):
        return ValidationResult(
            is_valid=False,
            errors=[f"{filename}: expected a YAML mapping at root, got {type(data).__name__}"],
            filename=filename,
        )

    result = validate_policy_schema(data)
    return ValidationResult(
        is_valid=result.is_valid,
        errors=[f"{filename}: {e}" for e in result.errors],
        warnings=[f"{filename}: {e}" for e in result.warnings],
        filename=filename,
    )


def validate_all_policies(directory: str | Path) -> dict[str, ValidationResult]:
    """Validate every ``.yaml`` file in a directory tree.

    Args:
        directory: Root directory to scan recursively.

    Returns:
        A mapping of ``filename -> ValidationResult``.  Every discovered
        ``.yaml`` file gets an entry — none are silently skipped.
    """
    dirpath = Path(directory)
    results: dict[str, ValidationResult] = {}

    if not dirpath.exists():
        return results

    for yaml_file in sorted(dirpath.rglob("*.yaml")):
        if yaml_file.name == ".gitkeep":
            continue
        try:
            results[str(yaml_file)] = validate_policy_file(yaml_file)
        except Exception as exc:
            results[str(yaml_file)] = ValidationResult(
                is_valid=False,
                errors=[f"{yaml_file}: unexpected error — {exc}"],
                filename=str(yaml_file),
            )

    return results


def detect_conflicts(policies: list[Policy]) -> list[ConflictWarning]:
    """Detect contradicting thresholds across policies in the same jurisdiction.

    Two policies conflict when they share the same ``jurisdiction`` **and**
    define rules for the same ``metric`` inside ``policy_logic``, but
    specify different ``threshold`` values.

    Args:
        policies: A list of already-validated :class:`~biasops.models.Policy`
                  instances.

    Returns:
        A list of :class:`ConflictWarning` objects, one per detected conflict.
    """
    # Build an index: (jurisdiction, metric) -> list[(policy_id, threshold, rule)]
    index: dict[tuple[str, str], list[tuple[str, float]]] = {}

    for policy in policies:
        for rule in _extract_rules(policy.policy_logic):
            key = (policy.jurisdiction, rule["metric"])
            index.setdefault(key, []).append((policy.id, rule["threshold"]))

    conflicts: list[ConflictWarning] = []

    for (jurisdiction, metric), entries in index.items():
        for (id_a, thresh_a), (id_b, thresh_b) in combinations(entries, 2):
            if id_a == id_b:
                continue
            if thresh_a != thresh_b:
                conflicts.append(
                    ConflictWarning(
                        policy_id_1=id_a,
                        policy_id_2=id_b,
                        conflict_description=(
                            f"Metric '{metric}' in jurisdiction '{jurisdiction}': "
                            f"policy '{id_a}' sets threshold {thresh_a} "
                            f"but policy '{id_b}' sets threshold {thresh_b}"
                        ),
                        recommendation=(
                            f"Align the '{metric}' threshold between policies "
                            f"'{id_a}' and '{id_b}', or scope them to different "
                            f"jurisdictions / domains."
                        ),
                    )
                )

    return conflicts
