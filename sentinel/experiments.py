"""Reproducible, label-aware experiment execution for Sentinel research claims."""
from __future__ import annotations

import hashlib
import json
import platform
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from sentinel.analyzers.tools import project_compiler, project_sources
from sentinel.benchmark import summarize_benchmark
from sentinel.config import settings
from sentinel.coverage import coverage_complete as has_complete_coverage
from sentinel.detection import finding_class, normalized_class, supported_classes
from sentinel.evaluation import qualification_gate
from sentinel.scanner_protocol import verify_scanner_protocol
from sentinel.schemas.state import RuntimeState
from sentinel.service import run_scan

GroundTruth = Literal["vulnerable", "clean", "unknown"]


class ExperimentCase(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    project_path: str
    group: Literal["fixture", "held_out", "audit", "clean", "development"]
    vulnerability_class: str = "unspecified"
    ground_truth: GroundTruth = "unknown"
    target_contract: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    target_file: str | None = None
    source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    provenance: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scope(self):
        if self.source_sha256 and not self.target_file:
            raise ValueError("Pinned sources require target_file")
        if self.target_file and (Path(self.target_file).is_absolute() or ".." in Path(self.target_file).parts):
            raise ValueError("target_file must stay inside the project")
        return self


class ExperimentManifest(BaseModel):
    name: str
    cases: list[ExperimentCase] = Field(min_length=1)
    provenance: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Experiment case IDs must be unique")
        return self


class ExperimentProfile(BaseModel):
    name: str
    enabled_analyzers: list[Literal["slither", "mythril", "sentinel-static"]] = Field(default_factory=lambda: ["slither", "mythril"])
    scout_only: bool = False
    max_retries: int = 5


PROFILES = {
    "slither": ExperimentProfile(name="slither", enabled_analyzers=["slither"], scout_only=True),
    "sentinel-static": ExperimentProfile(name="sentinel-static", enabled_analyzers=["slither", "sentinel-static"], scout_only=True),
    "mythril": ExperimentProfile(name="mythril", enabled_analyzers=["mythril"], scout_only=True),
    "scout-union": ExperimentProfile(name="scout-union", scout_only=True),
    "sentinel-no-red-team": ExperimentProfile(name="sentinel-no-red-team", scout_only=True),
    "sentinel-no-retry": ExperimentProfile(name="sentinel-no-retry", max_retries=0),
    "sentinel-full": ExperimentProfile(name="sentinel-full"),
}


def load_manifest(path: Path) -> ExperimentManifest:
    return ExperimentManifest.model_validate_json(path.read_text(encoding="utf-8"))


def run_experiment(
    manifest_path: Path,
    output_dir: Path,
    profile_name: str,
    *,
    limit: int | None = None,
    mock: bool = False,
    scan: Callable[..., RuntimeState] = run_scan,
) -> dict[str, object]:
    """Run only declared local Foundry projects and report metrics from known labels."""
    if profile_name not in PROFILES:
        raise ValueError(f"Unknown experiment profile: {profile_name}")
    manifest = load_manifest(manifest_path)
    profile = PROFILES[profile_name]
    protocol = manifest.provenance.get("scanner_protocol")
    if protocol is not None:
        if not isinstance(protocol, dict) or profile_name not in protocol.get("profiles", []):
            raise ValueError("Profile is not part of the frozen scanner comparison")
        if mock or limit is not None:
            raise ValueError("Frozen scanner comparison requires a complete non-mock run")
        verify_scanner_protocol(protocol, settings.static_binary, settings.command_timeout_seconds)
    selected = manifest.cases[:limit] if limit is not None else manifest.cases
    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    for case in selected:
        project = (manifest_path.parent / case.project_path).resolve() if not Path(case.project_path).is_absolute() else Path(case.project_path)
        started = monotonic()
        try:
            if protocol is not None:
                verify_scanner_protocol(protocol, settings.static_binary, settings.command_timeout_seconds)
            if case.target_file:
                target = (project / case.target_file).resolve()
                if not target.is_relative_to(project.resolve()):
                    raise ValueError("Target source escapes project")
                if case.source_sha256 and hashlib.sha256(target.read_bytes()).hexdigest() != case.source_sha256:
                    raise ValueError("Target source differs from the frozen assessment")
                if case.source_sha256 and target not in {path.resolve() for path in project_sources(project)[0]}:
                    raise ValueError("Pinned target is excluded by the project source configuration")
            compiler_pin = case.provenance.get("compiler")
            if isinstance(compiler_pin, dict):
                compiler = Path(compiler_pin["path"]).resolve()
                configured = project_compiler(project, project_sources(project)[1], settings.solc_binary)
                if configured is None or configured.resolve() != compiler:
                    raise ValueError("Project compiler differs from the frozen assessment")
                if hashlib.sha256(compiler.read_bytes()).hexdigest() != compiler_pin["sha256"]:
                    raise ValueError("Compiler differs from the frozen assessment")
            state = scan(
                project, output=output_dir / "ledgers" / profile.name / case.id,
                mock=mock, scout_only=profile.scout_only, max_retries=profile.max_retries,
                experiment_profile=profile.name, enabled_analyzers=profile.enabled_analyzers,
            )
            scan_error = ""
        except Exception as exc:  # noqa: BLE001 - retain per-case evaluation failures
            state = None
            scan_error = f"{type(exc).__name__}: {exc}"
        label = normalized_class(case.vulnerability_class)
        label_supported = label in supported_classes(profile.enabled_analyzers) or (case.ground_truth == "clean" and label == "clean")
        category_findings = [item for item in state.findings if finding_class(item) is not None
                             and (label == "clean" or finding_class(item) == label)] if state else []
        relevant = [item for item in category_findings if not case.target_file or item.file == case.target_file]
        attribution_complete = not (
            (case.target_file and any(not item.file for item in category_findings))
            or (case.target_contract and any(not item.contract for item in relevant))
        )
        matched = [item.id for item in relevant if not case.target_contract or item.contract == case.target_contract]
        detected = bool(matched)
        confirmed = bool(state and state.exploit_confirmed and state.candidate_id in matched
                         and state.exploit_artifact and state.exploit_artifact.origin == "reviewed_fixture")
        verified = bool(confirmed and state and state.judge_result and state.judge_result.evidence_version == 1 and state.judge_result.verified and state.final_verification_state == "verified")
        coverage_complete = bool(state and not mock and has_complete_coverage(state) and attribution_complete)
        records.append({
            "case_id": case.id, "group": case.group, "vulnerability_class": case.vulnerability_class,
            "ground_truth": case.ground_truth, "detected": detected, "confirmed": confirmed,
            "verified": verified, "coverage_complete": coverage_complete,
            "label_supported": label_supported, "matched_finding_ids": matched,
            "attribution_complete": attribution_complete, "target_contract": case.target_contract,
            "target_file": case.target_file, "provenance": case.provenance,
            "source_sha256": case.source_sha256,
            "unmatched_findings": len(state.findings) - len(matched) if state else 0,
            "outcome": state.final_verification_state if state else "invalid_project",
            "findings": len(state.findings) if state else 0,
            "analyzer_statuses": [{"tool": run.tool, "target": run.target, "status": run.status} for run in state.analyzer_runs] if state else [],
            "retries": state.retry_count if state else 0,
            "duration_seconds": round(monotonic() - started, 3),
            "ledger": state.final_report_path if state else None, "error": scan_error,
        })
    known = [row for row in records if row["ground_truth"] != "unknown"]
    measured = [row for row in known if row["coverage_complete"] and row["label_supported"]]
    tp = sum(row["detected"] and row["ground_truth"] == "vulnerable" for row in measured)
    fp = sum(row["detected"] and row["ground_truth"] == "clean" for row in measured)
    fn = sum(not row["detected"] and row["ground_truth"] == "vulnerable" for row in measured)
    tn = sum(not row["detected"] and row["ground_truth"] == "clean" for row in measured)
    metrics = summarize_benchmark(int(tp), int(fp), int(fn), int(tn)).model_dump(mode="json")
    clean_controls = sum(row["ground_truth"] == "clean" for row in measured)
    if not clean_controls:
        metrics["precision"] = None
        metrics["f1_score"] = None
        metrics["false_positive_rate"] = None
    by_class: dict[str, object] = {}
    for label in sorted({str(row["vulnerability_class"]) for row in known}):
        rows = [row for row in measured if row["vulnerability_class"] == label]
        by_class[label] = {
            "evaluated": len(rows), "detected": sum(bool(row["detected"]) for row in rows),
            "confirmed": sum(bool(row["confirmed"]) for row in rows), "verified": sum(bool(row["verified"]) for row in rows),
            "metrics": summarize_benchmark(
                sum(bool(row["detected"]) and row["ground_truth"] == "vulnerable" for row in rows),
                sum(bool(row["detected"]) and row["ground_truth"] == "clean" for row in rows),
                sum(not row["detected"] and row["ground_truth"] == "vulnerable" for row in rows),
                sum(not row["detected"] and row["ground_truth"] == "clean" for row in rows),
            ).model_dump(mode="json"),
        }
        if not any(row["ground_truth"] == "clean" for row in rows):
            for key in ("precision", "f1_score", "false_positive_rate"):
                by_class[label]["metrics"][key] = None
    report = {
        "experiment": manifest.name, "profile": profile.model_dump(mode="json"),
        "created_at": datetime.now(UTC).isoformat(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "dataset_provenance": manifest.provenance,
        "reproducibility": {
            "platform": platform.platform(), "python": platform.python_version(),
            "llm_provider": settings.llm_provider, "scout_model": settings.scout_model,
            "red_team_model": settings.red_team_model, "blue_team_model": settings.blue_team_model,
            "command_timeout_seconds": settings.command_timeout_seconds,
        },
        "metrics": metrics,
        "metric_scope": {
            "labeled_cases": len(known),
            "completed_labeled_cases": len(measured),
            "incomplete_labeled_cases": sum(not row["coverage_complete"] for row in known),
            "unsupported_labeled_cases": sum(not row["label_supported"] for row in known),
            "scope": "Case-level scanner category matching for supported profile detectors; explicit contract/file scope when supplied, not exact defect localization. Negative controls cover the assessed category only. Mock runs are excluded.",
            "clean_controls": clean_controls,
            "precision_and_f1_available": bool(clean_controls),
        },
        "poC_success_rate": sum(bool(row["confirmed"]) for row in measured if row["ground_truth"] == "vulnerable") / sum(row["ground_truth"] == "vulnerable" for row in measured) if any(row["ground_truth"] == "vulnerable" for row in measured) else None,
        "validated_repair_rate": sum(bool(row["verified"]) for row in measured) / sum(bool(row["confirmed"]) for row in measured) if any(bool(row["confirmed"]) for row in measured) else None,
        "average_retries": sum(int(row["retries"]) for row in records) / len(records) if records else None,
        "average_duration_seconds": sum(float(row["duration_seconds"]) for row in records) / len(records) if records else None,
        "coverage_complete_cases": sum(bool(row["coverage_complete"]) for row in records),
        "unlabeled_cases": len(records) - len(known), "by_vulnerability_class": by_class, "cases": records,
    }
    report["qualification"] = qualification_gate(report)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    path = output_dir / f"sentinel-experiment-{profile.name}-{stamp}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["report_path"] = str(path)
    return report
