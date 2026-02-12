# loader.py — Reads and parses policy YAML files into validated Pydantic models.
# Provides single-file loading, directory scanning, and raw-dict ingestion.

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from biasops.models import Policy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded or validated.

    Covers YAML syntax problems (malformed YAML, non-mapping root) **and**
    Pydantic schema validation failures.  When the cause is a
    ``ValidationError``, the original exception is chained via ``__cause__``
    and the message includes the originating filename.
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_policy(path: str | Path) -> Policy:
    """Load a single YAML policy file and return a validated ``Policy`` object.

    Args:
        path: Filesystem path to a ``.yaml`` policy file.

    Returns:
        A fully validated :class:`~biasops.models.Policy` instance.

    Raises:
        FileNotFoundError: If *path* does not exist on disk.
        PolicyLoadError: If the file contains malformed YAML, the YAML
            root is not a mapping, or the parsed data fails Pydantic
            validation.  In the validation case the original
            ``ValidationError`` is chained as ``__cause__`` and the
            message includes the filename for easier debugging.
    """
    filepath = Path(path)

    if not filepath.exists():
        raise FileNotFoundError(f"Policy file not found: {filepath}")

    raw_text = filepath.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(
            f"Malformed YAML in {filepath}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise PolicyLoadError(
            f"Expected a YAML mapping at the root of {filepath}, "
            f"got {type(data).__name__}"
        )

    try:
        # strict=False so YAML-native strings are coerced to datetimes /
        # enums even though the Policy model sets strict=True by default.
        return Policy.model_validate(data, strict=False)
    except ValidationError as exc:
        raise PolicyLoadError(
            f"Validation failed for {filepath}:\n{exc}"
        ) from exc


def load_policies_from_directory(directory: str | Path) -> list[Policy]:
    """Recursively discover and load all ``.yaml`` policy files in a directory.

    Files named ``.gitkeep`` are silently skipped.  Any file that fails
    validation is logged as a warning and omitted from the returned list
    rather than aborting the entire scan.

    Args:
        directory: Root directory to scan.

    Returns:
        A list of validated :class:`~biasops.models.Policy` instances for
        every file that loaded successfully.

    Raises:
        FileNotFoundError: If *directory* does not exist.
    """
    dirpath = Path(directory)

    if not dirpath.exists():
        raise FileNotFoundError(f"Policy directory not found: {dirpath}")

    policies: list[Policy] = []

    for yaml_file in sorted(dirpath.rglob("*.yaml")):
        if yaml_file.name == ".gitkeep":
            continue

        try:
            policies.append(load_policy(yaml_file))
        except (PolicyLoadError, FileNotFoundError) as exc:
            logger.warning("Skipping %s: %s", yaml_file, exc)

    return policies


def load_policy_from_dict(data: dict) -> Policy:
    """Convert a raw dictionary directly into a validated ``Policy`` object.

    Useful for testing and for API request bodies that have already been
    deserialised from JSON.

    Args:
        data: A dictionary whose keys match the :class:`~biasops.models.Policy`
              field names.

    Returns:
        A fully validated :class:`~biasops.models.Policy` instance.

    Raises:
        ValidationError: If *data* does not conform to the Policy schema.
    """
    return Policy.model_validate(data, strict=False)
