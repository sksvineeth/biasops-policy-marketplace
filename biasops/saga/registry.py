# saga/registry.py — Attestation registry.
# Loads AgentAttestation records from YAML files in the attestations/ directory.
# File-backed now, swappable for a remote registry later.

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from biasops.saga.attestation import AgentAttestation

logger = logging.getLogger(__name__)

_DEFAULT_ATTESTATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "attestations"


class AttestationLoadError(Exception):
    """Raised when an attestation file cannot be loaded or validated."""


class AttestationRegistry:
    """File-backed registry of agent attestations.

    Scans a directory for ``*.yaml`` attestation files and indexes them
    by ``agent_id`` for O(1) lookup at runtime.

    Args:
        attestations_dir: Directory containing attestation YAML files.
                          Defaults to ``attestations/`` in the project root.
    """

    def __init__(self, attestations_dir: str | Path | None = None) -> None:
        self._root = (
            Path(attestations_dir) if attestations_dir else _DEFAULT_ATTESTATIONS_DIR
        )
        self._root.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, AgentAttestation] = {}
        self._load_all()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get(self, agent_id: str) -> AgentAttestation | None:
        """Return the AgentAttestation for a given agent ID, or None.

        Args:
            agent_id: The agent identifier to look up.

        Returns:
            The :class:`AgentAttestation` if found, otherwise ``None``.
        """
        return self._index.get(agent_id)

    def register(self, attestation: AgentAttestation) -> None:
        """Add or replace an attestation in the in-memory registry.

        Does not persist to disk — use :meth:`save` for that.

        Args:
            attestation: The :class:`AgentAttestation` to register.
        """
        self._index[attestation.agent_id] = attestation
        logger.info("Registered attestation for agent '%s'", attestation.agent_id)

    def save(self, attestation: AgentAttestation) -> Path:
        """Persist an attestation to disk as a YAML file.

        Writes to ``{attestations_dir}/{agent_id}.yaml``. Registers
        the attestation in-memory after writing.

        Args:
            attestation: The :class:`AgentAttestation` to save.

        Returns:
            The :class:`Path` where the file was written.
        """
        dest = self._root / f"{attestation.agent_id}.yaml"
        dest.write_text(
            yaml.dump(
                attestation.model_dump(mode="json"),
                default_flow_style=False,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        self.register(attestation)
        logger.info("Saved attestation for agent '%s' → %s", attestation.agent_id, dest)
        return dest

    def list_agents(self) -> list[str]:
        """Return all registered agent IDs."""
        return sorted(self._index.keys())

    def all_attestations(self) -> list[AgentAttestation]:
        """Return all loaded attestations."""
        return list(self._index.values())

    def reload(self) -> None:
        """Re-scan the attestations directory and refresh the index."""
        self._index.clear()
        self._load_all()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_all(self) -> None:
        """Scan the root directory and load all valid attestation files."""
        for yaml_file in sorted(self._root.glob("*.yaml")):
            try:
                self._load_file(yaml_file)
            except AttestationLoadError as exc:
                logger.warning("Skipping %s: %s", yaml_file, exc)

    def _load_file(self, path: Path) -> AgentAttestation:
        """Load a single attestation YAML file into the index.

        Args:
            path: Path to the YAML file.

        Returns:
            The loaded :class:`AgentAttestation`.

        Raises:
            AttestationLoadError: If the file is malformed or invalid.
        """
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise AttestationLoadError(f"Malformed YAML in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise AttestationLoadError(
                f"Expected a YAML mapping at root of {path}, got {type(data).__name__}"
            )

        try:
            attestation = AgentAttestation.model_validate(data, strict=False)
        except ValidationError as exc:
            raise AttestationLoadError(
                f"Validation failed for {path}:\n{exc}"
            ) from exc

        self._index[attestation.agent_id] = attestation
        logger.debug("Loaded attestation for agent '%s'", attestation.agent_id)
        return attestation
