"""Explainable review-priority signals derived from the local protocol map."""
from __future__ import annotations

from sentinel.schemas.vulnerability import VulnerabilityFinding


def assess_protocol_risk(protocol_map: dict[str, object], findings: list[VulnerabilityFinding]) -> dict[str, object]:
    contracts = protocol_map.get("contracts", [])
    relationships = protocol_map.get("relationships", [])
    contract_by_file = {str(item.get("file")): item for item in contracts if isinstance(item, dict)}
    assessments = []
    for finding in findings:
        context = contract_by_file.get(finding.file, {})
        signals: list[str] = []
        external_calls = int(context.get("external_call_sites", 0)) if isinstance(context, dict) else 0
        upgrades = context.get("upgrade_signals", []) if isinstance(context, dict) else []
        if external_calls:
            signals.append(f"{external_calls} external-call surface(s) in the affected contract")
        if isinstance(upgrades, list) and upgrades:
            signals.append(f"upgrade boundary signals: {', '.join(str(item) for item in upgrades)}")
        contract_name = str(context.get("name", "")) if isinstance(context, dict) else ""
        imports = [item for item in relationships if isinstance(item, dict) and item.get("from") == contract_name]
        if imports:
            signals.append(f"{len(imports)} source dependency relationship(s) from the affected contract")
        priority = "elevated" if len(signals) >= 2 else "standard"
        assessments.append({"finding_id": finding.id, "priority": priority, "signals": signals})
    return {"assessments": assessments, "contract_count": len(contracts), "relationship_count": len(relationships)}
