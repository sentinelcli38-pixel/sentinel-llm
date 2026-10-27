"""Local assessment monitors. These rules never contact a chain or send an alert externally."""
from __future__ import annotations

from datetime import UTC, datetime

from sentinel.schemas.operations import AlertRecord, MonitorRule
from sentinel.schemas.state import RuntimeState

DEFAULT_RULES = [
    MonitorRule(id="coverage-incomplete", kind="coverage", severity="high"),
    MonitorRule(id="confirmed-finding", kind="confirmed_finding", severity="critical"),
    MonitorRule(id="verification-failed", kind="verification", severity="high"),
    MonitorRule(id="novelty-review", kind="novelty_review", severity="high"),
]


def evaluate_monitors(state: RuntimeState, rules: list[MonitorRule] = DEFAULT_RULES) -> list[AlertRecord]:
    alerts: list[AlertRecord] = []
    now = datetime.now(UTC)
    incomplete = any(run.status not in {"completed", "skipped"} for run in state.analyzer_runs)
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.kind == "coverage" and incomplete:
            alerts.append(AlertRecord(id=f"{rule.id}:coverage", rule_id=rule.id, severity=rule.severity, summary="Scanner coverage is incomplete; absence of findings is not a safety claim.", created_at=now))
        if rule.kind == "confirmed_finding":
            for finding in state.findings:
                if finding.status.value == "confirmed":
                    alerts.append(AlertRecord(id=f"{rule.id}:{finding.id}", rule_id=rule.id, severity=rule.severity, summary=f"Confirmed finding requires response: {finding.detector}", evidence_ids=[finding.id], created_at=now))
        if rule.kind == "verification" and state.final_verification_state == "human_review_required":
            alerts.append(AlertRecord(id=f"{rule.id}:review", rule_id=rule.id, severity=rule.severity, summary="Automated remediation exhausted its retry budget; human review is required.", created_at=now))
        if rule.kind == "novelty_review":
            novelty = [finding for finding in state.findings if finding.source == "novelty-heuristic"]
            if novelty:
                alerts.append(AlertRecord(id=f"{rule.id}:unknown-risk", rule_id=rule.id, severity=rule.severity, summary=f"{len(novelty)} unknown-risk source signal(s) require human triage; no exploit was assumed.", evidence_ids=[finding.id for finding in novelty], created_at=now))
    return alerts
