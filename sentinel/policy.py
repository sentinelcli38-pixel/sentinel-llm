"""Explicit local release-gate policy evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from sentinel.comparison import compare_ledgers
from sentinel.coverage import coverage_complete
from sentinel.schemas.state import RuntimeState

RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "optimization": 0, "unknown": 0}


@dataclass(frozen=True)
class GateDecision:
    status: str
    reasons: list[str]


def load_policy(path: Path) -> dict[str, object]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise TypeError("Policy must be a mapping")
    return document


def evaluate_policy(current: RuntimeState, policy: dict[str, object], baseline: RuntimeState | None = None) -> GateDecision:
    if set(policy) - {"block_severity", "require_complete_coverage"}:
        raise ValueError("Unknown release policy setting")
    if "require_complete_coverage" in policy and not isinstance(policy["require_complete_coverage"], bool):
        raise ValueError("require_complete_coverage must be a boolean")
    threshold = str(policy.get("block_severity", "critical")).lower()
    if threshold not in RANK:
        raise ValueError("Unknown block_severity")
    minimum_rank = RANK[threshold]
    findings = current.findings
    if baseline:
        introduced = compare_ledgers(baseline, current)["introduced"]
        finding_ids = {item["id"] for item in introduced}
        findings = [item for item in findings if item.id in finding_ids]
    reasons = [
        f"{item.severity} finding: {item.detector} at {item.file or 'unknown'}"
        for item in findings
        if item.severity == "unknown" or item.severity not in RANK or RANK[item.severity] >= minimum_rank
    ]
    # Verification covers a proposed patch in a temporary workspace, not the
    # unchanged project being released. A failed PoC also does not clear a warning.
    if policy.get("require_complete_coverage", True) and not coverage_complete(current):
        reasons.append("scanner coverage is incomplete")
    return GateDecision(status="blocked" if reasons else "passed", reasons=reasons)
