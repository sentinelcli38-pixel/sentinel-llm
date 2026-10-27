"""Shared full-coverage definition; bounded samples and demos are not complete."""

from sentinel.schemas.state import RuntimeState


def coverage_complete(state: RuntimeState) -> bool:
    return bool(
        not state.mock_mode and state.enabled_analyzers and state.analyzer_runs
        and all(run.status == "completed" for run in state.analyzer_runs)
        and set(state.enabled_analyzers) <= {run.tool for run in state.analyzer_runs}
    )
