import json
from pathlib import Path

import typer

from sentinel.config import settings
from sentinel.experiments import PROFILES, run_experiment
from sentinel.modeling.cli import app as model_app
from sentinel.policy import evaluate_policy, load_policy
from sentinel.reporting.sarif import render_sarif
from sentinel.schemas.state import RuntimeState
from sentinel.service import run_scan

app = typer.Typer(help="Sentinel: closed-loop smart-contract security research CLI.")
app.add_typer(model_app, name="model")


@app.callback()
def main() -> None:
    """Run Sentinel commands."""


@app.command()
def scan(
    project: Path = typer.Argument(..., exists=True, file_okay=False),  # noqa: B008
    output: Path = typer.Option(settings.output_dir, "--output"),  # noqa: B008
    max_retries: int = typer.Option(settings.max_retries, "--max-retries", min=0, max=5),
    mock: bool = typer.Option(False, "--mock"),
    scout_only: bool = typer.Option(False, "--scout-only", help="Run Slither/Mythril triage without generating tests or patches."),
    verbose: bool = typer.Option(False, "--verbose"),
    no_docker: bool = typer.Option(False, "--no-docker"),
) -> None:
    del verbose, no_docker
    if scout_only:
        typer.echo("Starting tool-only Scout scan (Slither and bounded Mythril); this can take about a minute.")
    else:
        typer.echo("Starting agentic scan: Scout, Red Team, Blue Team, and Judge.")
    try:
        final_state = run_scan(project, output=output, max_retries=max_retries, mock=mock, scout_only=scout_only)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"Sentinel completed: {final_state.final_verification_state}")
    typer.echo(f"Audit report: {final_state.final_report_path}")
    completed_states = {"scout_complete"} if scout_only else {"verified", "no_candidates"}
    if final_state.final_verification_state not in completed_states:
        raise typer.Exit(code=2)


@app.command()
def gate(
    ledger: Path = typer.Argument(..., exists=True, dir_okay=False),  # noqa: B008
    baseline: Path | None = typer.Option(None, "--baseline", exists=True, dir_okay=False),  # noqa: B008
    policy: Path = typer.Option(Path("sentinel-policy.yml"), "--policy"),  # noqa: B008
    sarif: Path | None = typer.Option(None, "--sarif"),  # noqa: B008
) -> None:
    """Evaluate a persisted ledger against an explicit local release policy."""
    current = RuntimeState.model_validate_json(ledger.read_text(encoding="utf-8"))
    previous = RuntimeState.model_validate_json(baseline.read_text(encoding="utf-8")) if baseline else None
    decision = evaluate_policy(current, load_policy(policy), previous)
    if sarif:
        sarif.write_text(json.dumps(render_sarif(current), indent=2) + "\n", encoding="utf-8")
    typer.echo(f"Sentinel release gate: {decision.status}")
    for reason in decision.reasons:
        typer.echo(f"- {reason}")
    if decision.status == "blocked":
        raise typer.Exit(code=1)


@app.command("benchmark")
def benchmark(
    manifest: Path = typer.Argument(..., exists=True, dir_okay=False),  # noqa: B008
    profile: str = typer.Option("scout-union", "--profile", help=f"One of: {', '.join(PROFILES)}"),
    output: Path = typer.Option(Path("reports/experiments"), "--output"),  # noqa: B008
    limit: int | None = typer.Option(None, "--limit", min=1),
    mock: bool = typer.Option(False, "--mock"),
    require_qualification: bool = typer.Option(False, "--require-qualification", help="Exit nonzero unless the development evaluation gate passes."),
) -> None:
    """Run a declared experiment profile and emit label-aware research metrics."""
    try:
        report = run_experiment(manifest, output, profile, limit=limit, mock=mock)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    metrics = report["metrics"]
    typer.echo(f"Sentinel experiment report: {report['report_path']}")
    typer.echo(f"Labeled cases: {metrics['evaluated']}; unlabeled cases: {report['unlabeled_cases']}")
    typer.echo(f"Precision: {metrics['precision']}; recall: {metrics['recall']}; F1: {metrics['f1_score']}")
    typer.echo(f"Development qualification: {'passed' if report['qualification']['passed'] else 'not passed'}")
    if require_qualification and not report["qualification"]["passed"]:
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
