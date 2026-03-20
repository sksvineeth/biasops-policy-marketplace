# registry.py — Policy marketplace registry.
# File-backed implementation: lists, publishes, fetches, and searches
# policies stored in the local policies/ directory tree.
# Designed to be swapped for a remote registry backend later with no
# interface changes.

from __future__ import annotations

import logging
import shutil
from pathlib import Path


from biasops.loader import PolicyLoadError, load_policy
from biasops.models import Policy

logger = logging.getLogger(__name__)

_DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


# ---------------------------------------------------------------------------
# Registry class
# ---------------------------------------------------------------------------


class PolicyRegistry:
    """File-backed policy registry.

    Scans a directory tree for ``.yaml`` policy files and exposes them
    through a consistent interface that can be replaced with a remote
    registry backend without changing call sites.

    Args:
        policies_dir: Root directory to scan. Defaults to the ``policies/``
                      folder in the project root.
    """

    def __init__(self, policies_dir: str | Path | None = None) -> None:
        self._root = Path(policies_dir) if policies_dir else _DEFAULT_POLICIES_DIR
        self._root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Core interface
    # ------------------------------------------------------------------

    def list_policies(
        self,
        domain: str | None = None,
        jurisdiction: str | None = None,
        risk_level: str | None = None,
        enforcement_mode: str | None = None,
    ) -> list[dict]:
        """Return summary metadata for every policy in the registry.

        All filter arguments are optional and additive (AND logic).

        Args:
            domain:           Filter by policy domain (e.g. ``"hiring"``).
            jurisdiction:     Filter by jurisdiction (e.g. ``"EU"``).
            risk_level:       Filter by risk level (``"LOW"`` … ``"CRITICAL"``).
            enforcement_mode: Filter by enforcement mode (``"block"`` / ``"warn"``
                              / ``"audit"``).

        Returns:
            List of summary dicts — one per matching policy — sorted by
            ``domain`` then ``id``.  Each dict contains the fields most
            useful for browsing: ``id``, ``name``, ``version``, ``domain``,
            ``jurisdiction``, ``risk_level``, ``enforcement_mode``,
            ``maintained_by``, and ``applies_to``.
        """
        results = []
        for policy in self._load_all():
            if domain and policy.domain != domain:
                continue
            if jurisdiction and policy.jurisdiction != jurisdiction:
                continue
            if risk_level and policy.risk_level.value != risk_level.upper():
                continue
            if enforcement_mode and policy.enforcement_mode.value != enforcement_mode.lower():
                continue
            results.append(self._summary(policy))

        return sorted(results, key=lambda p: (p["domain"], p["id"]))

    def fetch_policy(self, policy_id: str, version: str | None = None) -> Policy:
        """Return a fully validated :class:`Policy` object by its ID.

        If ``version`` is supplied, the returned policy must match it exactly.

        Args:
            policy_id: The ``Policy.id`` to look up.
            version:   Optional semantic version string (e.g. ``"1.0.0"``).

        Returns:
            The matching :class:`Policy`.

        Raises:
            KeyError: If no policy with the given ID (and version) is found.
        """
        for policy in self._load_all():
            if policy.id != policy_id:
                continue
            if version and policy.version != version:
                continue
            return policy
        version_hint = f" v{version}" if version else ""
        raise KeyError(f"Policy '{policy_id}{version_hint}' not found in registry.")

    def publish_policy(
        self,
        policy_path: str | Path,
        domain_subfolder: str | None = None,
        overwrite: bool = False,
    ) -> Path:
        """Copy a local policy YAML file into the registry directory tree.

        Validates the policy before copying — malformed or schema-invalid
        files are rejected before touching the registry.

        Args:
            policy_path:     Path to the source ``.yaml`` policy file.
            domain_subfolder: Optional subdirectory under ``policies/`` to
                              place the file in (e.g. ``"financial-services"``).
                              Defaults to the policy's ``domain`` value.
            overwrite:       If ``True``, replace an existing file with the
                             same name. Raises ``FileExistsError`` otherwise.

        Returns:
            The destination :class:`Path` where the policy was written.

        Raises:
            FileNotFoundError:  If ``policy_path`` does not exist.
            PolicyLoadError:    If the file fails schema validation.
            FileExistsError:    If a file with the same name already exists
                                and ``overwrite=False``.
        """
        src = Path(policy_path)
        if not src.exists():
            raise FileNotFoundError(f"Source policy file not found: {src}")

        # Validate before touching the registry
        policy = load_policy(src)

        subfolder = domain_subfolder or policy.domain
        dest_dir = self._root / subfolder
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name

        if dest.exists() and not overwrite:
            raise FileExistsError(
                f"Policy already exists at {dest}. "
                "Pass overwrite=True to replace it."
            )

        shutil.copy2(src, dest)
        logger.info("Published policy '%s' → %s", policy.id, dest)
        return dest

    def search(self, query: str) -> list[dict]:
        """Full-text search across policy id, name, domain, and regulation refs.

        Case-insensitive substring match. Useful for CLI and API discovery.

        Args:
            query: Search string (e.g. ``"GDPR"``, ``"hiring"``, ``"EU"``).

        Returns:
            List of summary dicts for matching policies.
        """
        q = query.lower()
        results = []
        for policy in self._load_all():
            haystack = " ".join([
                policy.id,
                policy.name,
                policy.domain,
                policy.jurisdiction,
                " ".join(r.article for r in policy.regulation_references),
                " ".join(policy.bias_types_addressed),
            ]).lower()
            if q in haystack:
                results.append(self._summary(policy))
        return sorted(results, key=lambda p: (p["domain"], p["id"]))

    def stats(self) -> dict:
        """Return aggregate statistics about the registry.

        Returns:
            Dict with ``total``, ``by_domain``, ``by_jurisdiction``,
            ``by_risk_level``, and ``by_enforcement_mode`` counts.
        """
        policies = self._load_all()
        by_domain: dict[str, int] = {}
        by_jurisdiction: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_enforcement: dict[str, int] = {}

        for p in policies:
            by_domain[p.domain] = by_domain.get(p.domain, 0) + 1
            by_jurisdiction[p.jurisdiction] = by_jurisdiction.get(p.jurisdiction, 0) + 1
            by_risk[p.risk_level.value] = by_risk.get(p.risk_level.value, 0) + 1
            by_enforcement[p.enforcement_mode.value] = (
                by_enforcement.get(p.enforcement_mode.value, 0) + 1
            )

        return {
            "total": len(policies),
            "by_domain": by_domain,
            "by_jurisdiction": by_jurisdiction,
            "by_risk_level": by_risk,
            "by_enforcement_mode": by_enforcement,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_all(self) -> list[Policy]:
        """Scan the registry root and return all valid policies."""
        policies: list[Policy] = []
        for yaml_file in sorted(self._root.rglob("*.yaml")):
            if yaml_file.name in (".gitkeep",):
                continue
            try:
                policies.append(load_policy(yaml_file))
            except (PolicyLoadError, FileNotFoundError) as exc:
                logger.warning("Skipping %s: %s", yaml_file, exc)
        return policies

    @staticmethod
    def _summary(policy: Policy) -> dict:
        """Return a compact summary dict for listing/search results."""
        return {
            "id": policy.id,
            "name": policy.name,
            "version": policy.version,
            "domain": policy.domain,
            "jurisdiction": policy.jurisdiction,
            "risk_level": policy.risk_level.value,
            "enforcement_mode": policy.enforcement_mode.value,
            "maintained_by": policy.maintained_by,
            "applies_to": policy.applies_to,
            "bias_types_addressed": policy.bias_types_addressed,
            "regulation_count": len(policy.regulation_references),
        }


# ---------------------------------------------------------------------------
# Module-level convenience functions (backwards-compatible interface)
# ---------------------------------------------------------------------------

_default_registry: PolicyRegistry | None = None


def _get_default_registry() -> PolicyRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = PolicyRegistry()
    return _default_registry


def list_policies(
    domain: str | None = None,
    jurisdiction: str | None = None,
    risk_level: str | None = None,
    enforcement_mode: str | None = None,
) -> list[dict]:
    """List policies from the default registry with optional filters.

    Convenience wrapper around :meth:`PolicyRegistry.list_policies`.
    """
    return _get_default_registry().list_policies(
        domain=domain,
        jurisdiction=jurisdiction,
        risk_level=risk_level,
        enforcement_mode=enforcement_mode,
    )


def publish_policy(
    policy_path: str,
    domain_subfolder: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Publish a policy file to the default registry.

    Convenience wrapper around :meth:`PolicyRegistry.publish_policy`.
    """
    return _get_default_registry().publish_policy(
        policy_path=policy_path,
        domain_subfolder=domain_subfolder,
        overwrite=overwrite,
    )


def fetch_policy(policy_id: str, version: str | None = None) -> Policy:
    """Fetch a policy from the default registry by ID.

    Convenience wrapper around :meth:`PolicyRegistry.fetch_policy`.
    """
    return _get_default_registry().fetch_policy(policy_id=policy_id, version=version)
