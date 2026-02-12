# registry.py — Policy marketplace registry.
# Handles listing, publishing, and fetching policies from the marketplace index.


def list_policies(tags: list[str] | None = None) -> list[dict]:
    """List available policies, optionally filtered by tags."""
    raise NotImplementedError


def publish_policy(policy_path: str, registry_url: str | None = None):
    """Publish a local policy to the marketplace registry."""
    raise NotImplementedError


def fetch_policy(name: str, version: str | None = None):
    """Download a policy from the registry by name and optional version."""
    raise NotImplementedError
