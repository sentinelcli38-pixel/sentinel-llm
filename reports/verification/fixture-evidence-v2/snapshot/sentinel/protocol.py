"""Transparent source-level protocol relationship extraction."""
from __future__ import annotations

import re


def build_protocol_map(sources: dict[str, str]) -> dict[str, object]:
    contracts: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []
    for path, source in sorted(sources.items()):
        names = re.findall(r"\b(?:abstract\s+)?contract\s+(\w+)", source)
        imports = re.findall(r"\bimport\s+[\"']([^\"']+)[\"']", source)
        external_calls = len(re.findall(r"\.(?:call|delegatecall|staticcall)\s*\{?", source))
        upgrade_signals = [signal for signal in ("delegatecall", "implementation", "upgradeTo", "UUPS") if signal in source]
        for name in names:
            contracts.append({"name": name, "file": path, "external_call_sites": external_calls, "upgrade_signals": upgrade_signals})
            for target in imports:
                relationships.append({"from": name, "type": "imports", "to": target})
    return {"contracts": contracts, "relationships": relationships}
