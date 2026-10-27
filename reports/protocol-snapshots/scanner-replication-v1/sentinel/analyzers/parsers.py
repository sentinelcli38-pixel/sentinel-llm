"""Normalize documented Slither and Mythril JSON without treating exit codes as findings."""
import hashlib
import json
from pathlib import Path

from sentinel.schemas.vulnerability import VulnerabilityFinding

SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "optimization": 0, "unknown": -1}
CONFIDENCE = {"high": 0.9, "medium": 0.6, "low": 0.3, "unknown": 0.0}


def local_path(project: Path, filename: object) -> str:
    if not isinstance(filename, str) or not filename:
        return ""
    root = project.resolve()
    candidate = (root / filename).resolve()
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return ""


def _line(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _text(value: object, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _parent_contract(element: dict) -> str:
    # Slither normally attaches the contract to a function/node's parent chain.
    for _ in range(8):
        if element.get("type") == "contract":
            return _text(element.get("name"))
        fields = element.get("type_specific_fields")
        parent = fields.get("parent") if isinstance(fields, dict) else None
        if not isinstance(parent, dict):
            break
        element = parent
    return ""


def _document(raw: str, key: str) -> list[dict]:
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("success") is not True:
        raise ValueError("Analyzer did not report successful analysis")
    payload = data.get("results") if key == "detectors" else data
    if not isinstance(payload, dict):
        raise TypeError("Analyzer result must be an object")
    # Slither omits detectors for a successful scan with no findings.
    entries = payload.get(key, [] if key == "detectors" else None)
    if not isinstance(entries, list) or any(not isinstance(x, dict) for x in entries):
        raise ValueError(f"Analyzer {key} must be a list of objects")
    return entries


def _id(tool: str, detector: str, file: str, line: int | None, detail: str) -> str:
    digest = hashlib.sha256(json.dumps([detector, file, line, detail]).encode()).hexdigest()[:16]
    return f"{tool}-{digest}"


def parse_slither(raw: str, project: Path) -> list[VulnerabilityFinding]:
    findings = []
    for item in _document(raw, "detectors"):
        detector = _text(item.get("check"))
        description = _text(item.get("description"))
        if not detector or not description:
            raise ValueError("Slither detector is missing check or description")
        elements = item.get("elements", [])
        if not isinstance(elements, list) or any(not isinstance(x, dict) for x in elements):
            raise ValueError("Slither elements must be objects")
        primary = elements[0] if elements else {}
        mapping = primary.get("source_mapping") or {}
        if not isinstance(mapping, dict):
            raise TypeError("Slither source mapping must be an object")
        file = local_path(project, mapping.get("filename_relative") or mapping.get("filename_absolute"))
        lines = mapping.get("lines") or []
        if not isinstance(lines, list):
            raise TypeError("Slither source lines must be a list")
        line = next((n for n in map(_line, lines) if n is not None), None)
        function = next((_text(e.get("name")) for e in elements if e.get("type") == "function"), "")
        contract = _parent_contract(primary)
        severity = _text(item.get("impact"), "unknown").lower()
        confidence = _text(item.get("confidence"), "unknown").lower()
        findings.append(VulnerabilityFinding(
            id=_id("slither", detector, file, line, description), source="slither",
            detector=detector, severity=severity if severity in SEVERITY else "unknown",
            confidence=confidence if confidence in CONFIDENCE else "unknown",
            confidence_score=CONFIDENCE.get(confidence, 0.0), file=file, line=line,
            contract=contract, function=function, description=description,
            evidence=[f"slither:{detector}: {description}"], sources=["slither"],
            raw_output=json.dumps(item, sort_keys=True),
        ))
    return findings


def parse_mythril(raw: str, project: Path) -> list[VulnerabilityFinding]:
    findings = []
    for item in _document(raw, "issues"):
        swc = _text(item.get("swc-id"))
        title = _text(item.get("title"))
        if not swc or not title:
            raise ValueError("Mythril issue is missing swc-id or title")
        detector = f"SWC-{swc.removeprefix('SWC-')}"
        file = local_path(project, item.get("filename"))
        line = _line(item.get("lineno"))
        severity = _text(item.get("severity"), "unknown").lower()
        description = _text(item.get("description"), title)
        findings.append(VulnerabilityFinding(
            id=_id("mythril", detector, file, line, json.dumps([item.get("address"), title, item.get("function")], sort_keys=True)),
            source="mythril", sources=["mythril"], detector=detector,
            severity=severity if severity in SEVERITY else "unknown",
            # Mythril's JSON has no confidence field; do not invent one.
            confidence="unknown", confidence_score=0.0, file=file, line=line,
            contract=_text(item.get("contract")), function=_text(item.get("function")),
            description=f"{title}\n{description}", evidence=[f"mythril:{detector}: {description}"],
            raw_output=json.dumps(item, sort_keys=True),
        ))
    return findings


def parse_sentinel_static(raw: str, project: Path) -> list[VulnerabilityFinding]:
    findings = parse_slither(raw, project)
    for finding in findings:
        if finding.detector not in {"unused-call-result", "origin-auth-alternative"}:
            raise ValueError("Unexpected experimental static detector")
        elements = json.loads(finding.raw_output).get("elements", [])
        primary = elements[0] if elements else {}
        mapping = primary.get("source_mapping") or {}
        if mapping.get("filename_absolute"):
            finding.file = local_path(project, mapping["filename_absolute"])
        finding.id = finding.id.replace("slither-", "sentinel-static-", 1)
        finding.source = "sentinel-static"
        finding.sources = ["sentinel-static"]
        finding.evidence = [f"experimental sentinel-static:{finding.detector}: {finding.description}"]
    return findings


def rank_and_deduplicate(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """Conservatively merge identical detector/location evidence, never whole bug classes."""
    merged: dict[tuple, VulnerabilityFinding] = {}
    for finding in findings:
        # Distinct tools retain separate candidates: SWC categories are too broad to
        # prove two findings describe the same defect merely from an overlapping line.
        key = (finding.source, finding.detector, finding.file, finding.line,
               finding.contract, finding.function, finding.description)
        if key not in merged:
            merged[key] = finding.model_copy(deep=True)
        else:
            existing = merged[key]
            existing.evidence = list(dict.fromkeys(existing.evidence + finding.evidence))
            existing.sources = sorted(set(existing.sources + finding.sources))
            if SEVERITY.get(finding.severity, -1) > SEVERITY.get(existing.severity, -1):
                existing.severity = finding.severity
            if finding.confidence_score > existing.confidence_score:
                existing.confidence, existing.confidence_score = finding.confidence, finding.confidence_score
    return sorted(merged.values(), key=lambda f: (-SEVERITY.get(f.severity, -1), -f.confidence_score, f.file, f.line or 0, f.id))
