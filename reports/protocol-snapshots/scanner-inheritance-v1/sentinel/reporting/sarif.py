"""SARIF 2.1.0 export for CI code-scanning integrations."""
from __future__ import annotations

from sentinel.schemas.state import RuntimeState


def render_sarif(state: RuntimeState) -> dict[str, object]:
    results = []
    rules: dict[str, dict[str, object]] = {}
    for finding in state.findings:
        rule_id = finding.detector
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id, "shortDescription": {"text": rule_id.replace("-", " ")}})
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning"}.get(finding.severity, "note"),
            "message": {"text": finding.description},
            "properties": {"sentinelStatus": finding.status.value, "confidence": finding.confidence, "evidence": finding.evidence},
        }
        if finding.file:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.file}, "region": {"startLine": finding.line or 1}}}]
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "Sentinel", "rules": list(rules.values())}}, "results": results}]}
