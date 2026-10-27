import shutil
from pathlib import Path

from sentinel.config import settings
from sentinel.graph.workflow import build_workflow
from sentinel.monitoring import evaluate_monitors
from sentinel.reporting.markdown import write_report
from sentinel.reproducibility import capture_reproducibility
from sentinel.runner import ControlledRunner
from sentinel.schemas.state import RuntimeState
from sentinel.telemetry import RunTelemetry


def run_scan(
    project: Path,
    *,
    output: Path | None = None,
    max_retries: int | None = None,
    mock: bool = False,
    scout_only: bool = False,
    experiment_profile: str = "sentinel-full",
    enabled_analyzers: list[str] | None = None,
    telemetry: RunTelemetry | None = None,
) -> RuntimeState:
    """Run a local Foundry audit and persist its report ledger.

    Callers pass paths, never commands. The workflow's allowlisted runner owns
    every subprocess invocation.
    """
    project = project.resolve()
    if not project.is_dir() or not (project / "foundry.toml").is_file():
        raise ValueError("Project must be a directory containing foundry.toml")
    state = RuntimeState(
        project_path=str(project),
        mock_mode=mock,
        experiment_profile=experiment_profile,
        enabled_analyzers=enabled_analyzers or ["slither", "mythril"],
        max_retries=settings.max_retries if max_retries is None else max_retries,
        scout_only=scout_only,
    )
    state.feedback.append(f"Maximum patch retries configured: {state.max_retries}")
    state.reproducibility = capture_reproducibility()
    workspace: Path | None = None
    try:
        def phase_observer(phase: str, current: RuntimeState, status: str, duration: float) -> None:
            nonlocal workspace
            if current.workspace_path:
                workspace = Path(current.workspace_path)
            if telemetry:
                telemetry.emit("phase", status, phase.replace("_", " "), duration_seconds=round(duration, 3))

        def command_observer(status: str, command, cwd: Path, result) -> None:
            if telemetry:
                telemetry.emit(
                    "command", status, " ".join(command), cwd=str(cwd),
                    duration_seconds=result.duration_seconds if result else 0.0,
                    success=result.success if result else None,
                )

        runner = ControlledRunner(settings.command_timeout_seconds, observer=command_observer if telemetry else None)
        final_state = RuntimeState.model_validate(build_workflow(runner=runner, observer=phase_observer).invoke(state))
        workspace = Path(final_state.workspace_path) if final_state.workspace_path else None
        final_state.workspace_path = None
        final_state.alerts = evaluate_monitors(final_state)
        write_report(final_state, output or settings.output_dir)
        return final_state
    finally:
        if workspace:
            shutil.rmtree(workspace.parent, ignore_errors=True)
