"""Deterministic ledger comparison for Sentinel's local security memory."""
from __future__ import annotations

from sentinel.schemas.state import RuntimeState


def finding_key(finding) -> str:
    location = f"{finding.file}:{finding.line or 0}"
    return f"{finding.detector}|{location}|{finding.contract}|{finding.function}"


def compare_ledgers(base: RuntimeState, current: RuntimeState) -> dict[str, object]:
    base_findings = {finding_key(item): item for item in base.findings}
    current_findings = {finding_key(item): item for item in current.findings}
    introduced = [current_findings[key] for key in current_findings.keys() - base_findings.keys()]
    resolved = [base_findings[key] for key in base_findings.keys() - current_findings.keys()]
    persisted = [current_findings[key] for key in current_findings.keys() & base_findings.keys()]
    base_tools = {(run.tool, run.target): run.status for run in base.analyzer_runs}
    current_tools = {(run.tool, run.target): run.status for run in current.analyzer_runs}
    coverage_regressions = [
        {"tool": tool, "target": target, "before": before, "after": current_tools[(tool, target)]}
        for (tool, target), before in base_tools.items()
        if before == "completed" and current_tools.get((tool, target)) not in {"completed", "skipped"}
    ]
    return {
        "base_outcome": base.final_verification_state,
        "current_outcome": current.final_verification_state,
        "introduced": [item.model_dump(mode="json") for item in introduced],
        "resolved": [item.model_dump(mode="json") for item in resolved],
        "persisted": [item.model_dump(mode="json") for item in persisted],
        "coverage_regressions": coverage_regressions,
    }
