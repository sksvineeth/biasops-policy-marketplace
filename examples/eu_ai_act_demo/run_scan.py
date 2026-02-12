"""
EU AI Act Compliance Demo — NordBank AutoLend AI Scenario

This script simulates BiasOps scanning a loan approval AI system
against EU AI Act High Risk System Obligations.

Usage:
    python run_scan.py --scenario compliant
    python run_scan.py --scenario non_compliant
    python run_scan.py --scenario partial
"""

import json
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SCENARIOS = {
    "compliant": {
        "file": "compliant_model.json",
        "description": "AutoLend AI v3.2 — Full EU AI Act compliance package complete"
    },
    "non_compliant": {
        "file": "non_compliant_model.json",
        "description": "AutoLend AI v1.0 — Rushed to production with no compliance documentation"
    },
    "partial": {
        "file": "partial_compliant_model.json",
        "description": "AutoLend AI v2.1 — Partial compliance, missing human oversight and conformity assessment"
    }
}

EU_AI_ACT_CHECKS = [
    {
        "field": "risk_management_system_documented",
        "article": "Article 9",
        "requirement": "Risk management system documented",
        "remediation": "Establish risk management system covering full AI lifecycle"
    },
    {
        "field": "technical_documentation_complete",
        "article": "Article 11",
        "requirement": "Technical documentation complete",
        "remediation": "Complete Annex IV technical documentation package"
    },
    {
        "field": "data_governance_policy_present",
        "article": "Article 10",
        "requirement": "Data governance policy present",
        "remediation": "Implement data governance covering training data quality and bias examination"
    },
    {
        "field": "human_oversight_mechanism_defined",
        "article": "Article 14",
        "requirement": "Human oversight mechanism defined",
        "remediation": "Define human oversight allowing operators to monitor and override the system"
    },
    {
        "field": "conformity_assessment_completed",
        "article": "Article 43",
        "requirement": "Conformity assessment completed",
        "remediation": "Complete third-party conformity assessment before market placement"
    },
    {
        "field": "transparency_information_provided",
        "article": "Article 13",
        "requirement": "Transparency information provided to deployers",
        "remediation": "Provide documentation covering capabilities, limitations, and intended purpose"
    },
    {
        "field": "accuracy_metrics_documented",
        "article": "Article 15",
        "requirement": "Accuracy metrics documented",
        "remediation": "Document accuracy metrics across all population groups"
    },
    {
        "field": "robustness_testing_completed",
        "article": "Article 15",
        "requirement": "Robustness testing completed",
        "remediation": "Conduct robustness testing against adversarial inputs and edge cases"
    },
    {
        "field": "cybersecurity_measures_implemented",
        "article": "Article 15",
        "requirement": "Cybersecurity measures implemented",
        "remediation": "Implement measures protecting against unauthorized access and data poisoning"
    },
    {
        "field": "post_market_monitoring_plan_present",
        "article": "Article 72",
        "requirement": "Post-market monitoring plan present",
        "remediation": "Establish monitoring plan to track real-world performance after deployment"
    },
    {
        "field": "incident_reporting_mechanism_defined",
        "article": "Article 73",
        "requirement": "Incident reporting mechanism defined",
        "remediation": "Define mechanism to notify authorities of serious incidents"
    },
]

METRIC_CHECKS = [
    {
        "field": "accuracy_score",
        "threshold": 0.75,
        "article": "Article 15",
        "label": "Accuracy Score"
    },
    {
        "field": "robustness_score",
        "threshold": 0.70,
        "article": "Article 15",
        "label": "Robustness Score"
    }
]


def run_scan(scenario_name: str):
    scenario = SCENARIOS[scenario_name]
    model_path = Path(__file__).parent / scenario["file"]

    with open(model_path) as f:
        model = json.load(f)

    console.print()
    console.print(Panel.fit(
        "[bold blue]BiasOps EU AI Act Compliance Scan[/bold blue]\n"
        "[white]Policy: EU-AI-ACT-001 — High Risk System Obligations[/white]\n"
        "[white]Regulation: EU AI Act Annex III[/white]\n"
        "[white]Enforcement: BLOCK[/white]",
        box=box.DOUBLE
    ))

    console.print()
    console.print(Panel(
        f"[bold]Scenario:[/bold] {scenario_name.upper()}\n"
        f"[bold]Model:[/bold] {model['model_name']} v{model['version']}\n"
        f"[bold]Deployer:[/bold] {model['deployer']}\n"
        f"[bold]Decision Type:[/bold] {model['decision_type']}\n"
        f"[bold]Description:[/bold] {scenario['description']}",
        title="Model Under Review",
        border_style="blue"
    ))

    violations = []
    passed = []

    for check in EU_AI_ACT_CHECKS:
        value = model.get(check["field"], None)
        if value is True:
            passed.append(check)
        else:
            violations.append({
                **check,
                "severity": "CRITICAL",
                "value": value
            })

    for metric in METRIC_CHECKS:
        value = model.get(metric["field"], 0)
        if value >= metric["threshold"]:
            passed.append({"requirement": f"{metric['label']} >= {metric['threshold']}"})
        else:
            violations.append({
                "field": metric["field"],
                "article": metric["article"],
                "requirement": f"{metric['label']} must be >= {metric['threshold']}",
                "remediation": f"Improve {metric['label'].lower()} from {value:.2f} to minimum {metric['threshold']}",
                "severity": "CRITICAL",
                "value": value
            })

    console.print()

    checks_table = Table(
        title="Compliance Check Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white"
    )
    checks_table.add_column("Article", style="cyan", width=12)
    checks_table.add_column("Requirement", width=40)
    checks_table.add_column("Status", justify="center", width=10)

    for check in EU_AI_ACT_CHECKS:
        value = model.get(check["field"], None)
        status = "[green]✓ PASS[/green]" if value is True else "[red]✗ FAIL[/red]"
        checks_table.add_row(check["article"], check["requirement"], status)

    for metric in METRIC_CHECKS:
        value = model.get(metric["field"], 0)
        passed_check = value >= metric["threshold"]
        status = "[green]✓ PASS[/green]" if passed_check else "[red]✗ FAIL[/red]"
        checks_table.add_row(
            metric["article"],
            f"{metric['label']}: {value:.2f} (min {metric['threshold']})",
            status
        )

    console.print(checks_table)

    if violations:
        console.print()
        console.print(Panel(
            f"[bold red]Status: FAIL ✗[/bold red]\n"
            f"[white]Checks passed: {len(passed)}[/white]\n"
            f"[white]Violations found: {len(violations)}[/white]\n"
            f"[bold red]Deployment: BLOCKED[/bold red]\n\n"
            f"[yellow]Maximum penalty for non-compliance:\n"
            f"EUR 35,000,000 or 7% of global annual turnover[/yellow]",
            title="Scan Result",
            border_style="red"
        ))

        console.print()
        console.print("[bold red]Violations Requiring Remediation:[/bold red]")
        console.print()

        for i, v in enumerate(violations, 1):
            console.print(
                f"[red][{i}] CRITICAL — {v['requirement']}[/red]\n"
                f"    [cyan]Regulation: EU AI Act {v['article']}[/cyan]\n"
                f"    [white]Fix: {v['remediation']}[/white]\n"
            )
    else:
        console.print()
        console.print(Panel(
            f"[bold green]Status: PASS ✓[/bold green]\n"
            f"[white]Checks passed: {len(passed)}[/white]\n"
            f"[white]Violations found: 0[/white]\n"
            f"[bold green]Deployment: APPROVED[/bold green]\n\n"
            f"[green]This system meets EU AI Act High Risk\n"
            f"System Obligations under Annex III.[/green]",
            title="Scan Result",
            border_style="green"
        ))

    console.print()
    console.print(
        "[dim]Scan powered by BiasOps Policy Marketplace[/dim]\n"
        "[dim]Policy: EU-AI-ACT-001 v1.0.0 | "
        "github.com/sksvineeth/biasops-policy-marketplace[/dim]"
    )
    console.print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="EU AI Act Compliance Demo — NordBank AutoLend AI"
    )
    parser.add_argument(
        "--scenario",
        choices=["compliant", "non_compliant", "partial"],
        default="non_compliant",
        help="Which scenario to run"
    )
    args = parser.parse_args()
    run_scan(args.scenario)
