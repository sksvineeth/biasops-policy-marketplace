# cli.py — Typer-based command-line interface for BiasOps.
# Provides commands: validate, scan, list, check-conflicts.

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from biasops.engine import PolicyEngine
from biasops.loader import load_policies_from_directory
from biasops.validator import detect_conflicts, validate_policy_file

__version__ = "0.1.0"

app = typer.Typer(
    name="biasops",
    help="BiasOps Policy Marketplace — validate, scan, and manage bias-detection policies.",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    """Print version and exit when ``--version`` is passed."""
    if value:
        console.print(f"biasops {__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Global options
# ---------------------------------------------------------------------------


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show the BiasOps version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """BiasOps Policy Marketplace CLI."""


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@app.command()
def validate(
    policy_path: Path = typer.Argument(
        ...,
        help="Path to a single .yaml policy file to validate.",
        exists=False,  # we do our own existence check for a friendlier message
    ),
) -> None:
    """Validate a policy file against the BiasOps JSON Schema.

    Prints a green check if the policy is valid, or a red cross followed by
    each error if invalid.  Exit code is 0 for valid, 1 for invalid.
    """
    try:
        result = validate_policy_file(policy_path)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    if result.is_valid:
        console.print(f"[green]✓ VALID:[/green] {policy_path}")
        for warning in result.warnings:
            console.print(f"  [yellow]⚠ {warning}[/yellow]")
        raise typer.Exit(code=0)
    else:
        console.print(f"[red]✗ INVALID:[/red] {policy_path}")
        for error in result.errors:
            console.print(f"  {error}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    policies_dir: Path = typer.Argument(
        ...,
        help="Directory containing .yaml policy files.",
    ),
    model_metadata_json: Path = typer.Argument(
        ...,
        help="Path to a JSON file containing model metadata key/value pairs.",
    ),
) -> None:
    """Evaluate all policies against model metadata and produce a report.

    Loads every policy from the directory, evaluates them against the
    metadata JSON file, and prints a summary.  Exit code is 0 for PASS,
    1 for FAIL.
    """
    # --- read metadata JSON ---
    if not model_metadata_json.exists():
        err_console.print(
            f"[red]Error:[/red] metadata file not found: {model_metadata_json}"
        )
        raise typer.Exit(code=1)

    try:
        metadata = json.loads(model_metadata_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        err_console.print(f"[red]Error:[/red] cannot read metadata file — {exc}")
        raise typer.Exit(code=1)

    # --- run engine ---
    try:
        engine = PolicyEngine(policies_dir=policies_dir)
        report = engine.evaluate(metadata)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    # --- print report ---
    if report.status.value == "PASS":
        console.print(f"\n[bold green]Status: PASS ✓[/bold green]")
    else:
        console.print(f"\n[bold red]Status: FAIL ✗[/bold red]")

    console.print(f"Policies evaluated: {len(report.policies_evaluated)}")
    console.print(f"Violations found: {len(report.violations)}")

    for v in report.violations:
        console.print(
            f"\n  [bold][{v.severity.value}][/bold] {v.policy_id} — {v.message}"
        )
        console.print(f"  Regulation: {v.regulation_citation}")
        if v.remediation_steps:
            console.print(f"  Fix: {v.remediation_steps[0]}")

    console.print()

    if report.status.value == "FAIL":
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@app.command("list")
def list_policies(
    policies_dir: Path = typer.Argument(
        ...,
        help="Directory containing .yaml policy files.",
    ),
) -> None:
    """List all policies found in a directory.

    Prints a formatted table with ID, Name, Domain, Jurisdiction,
    Risk Level, and Enforcement Mode columns.
    """
    if not policies_dir.exists():
        err_console.print(
            f"[red]Error:[/red] directory not found: {policies_dir}"
        )
        raise typer.Exit(code=1)

    try:
        policies = load_policies_from_directory(policies_dir)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    if not policies:
        console.print("[yellow]No policies found.[/yellow]")
        raise typer.Exit(code=0)

    table = Table(title="BiasOps Policies")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Domain")
    table.add_column("Jurisdiction")
    table.add_column("Risk Level")
    table.add_column("Enforcement")

    for p in policies:
        table.add_row(
            p.id,
            p.name,
            p.domain,
            p.jurisdiction,
            p.risk_level.value,
            p.enforcement_mode.value,
        )

    console.print(table)
    console.print(f"\nTotal: {len(policies)} policies")


# ---------------------------------------------------------------------------
# check-conflicts
# ---------------------------------------------------------------------------


@app.command("check-conflicts")
def check_conflicts(
    policies_dir: Path = typer.Argument(
        ...,
        help="Directory containing .yaml policy files to check for conflicts.",
    ),
) -> None:
    """Detect conflicting thresholds across policies in the same jurisdiction.

    Loads all policies, compares their threshold rules, and reports any
    conflicts found.  Exit code is 0 for clean, 1 for conflicts found.
    """
    if not policies_dir.exists():
        err_console.print(
            f"[red]Error:[/red] directory not found: {policies_dir}"
        )
        raise typer.Exit(code=1)

    try:
        policies = load_policies_from_directory(policies_dir)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    conflicts = detect_conflicts(policies)

    if not conflicts:
        console.print("[green]✓ No conflicts detected[/green]")
        raise typer.Exit(code=0)

    console.print(f"[red]✗ {len(conflicts)} conflict(s) detected:[/red]\n")
    for c in conflicts:
        console.print(f"  [bold]{c.policy_id_1}[/bold] ↔ [bold]{c.policy_id_2}[/bold]")
        console.print(f"    {c.conflict_description}")
        console.print(f"    [yellow]Recommendation:[/yellow] {c.recommendation}")
        console.print()

    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
