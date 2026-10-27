"""Offline, source-pinned repair evidence audit; not a detector accuracy benchmark."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.agents.blue_team import BlueTeam  # noqa: E402
from sentinel.agents.judge import Judge  # noqa: E402
from sentinel.agents.red_team import RedTeam  # noqa: E402
from sentinel.config import settings  # noqa: E402
from sentinel.foundry.evidence import passed, test_results  # noqa: E402
from sentinel.foundry.runner import FoundryRunner  # noqa: E402
from sentinel.schemas.execution import ExecutionResult  # noqa: E402
from sentinel.schemas.state import RuntimeState  # noqa: E402
from sentinel.schemas.vulnerability import VulnerabilityFinding  # noqa: E402

CASES = (
    ("reentrancy", "vulnerable_reentrancy", "src/VulnerableVault.sol"),
    ("access-control", "vulnerable_access_control", "src/VulnerableTreasury.sol"),
    ("tx-origin", "vulnerable_tx_origin", "src/TxOriginWallet.sol"),
    ("unchecked-call", "vulnerable_unchecked_call", "src/UncheckedCallWallet.sol"),
)
CONTROLS = ("unchanged_patch", "altered_oracle", "missing_regression", "empty_regression", "invalid_patch")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def input_files() -> list[Path]:
    files = [Path(__file__).resolve(), *ROOT.glob("sentinel/**/*.py"), *ROOT.glob("benchmarks/verification/*.sol")]
    for _, fixture, _ in CASES:
        files.extend(path for path in (ROOT / "examples" / fixture).rglob("*")
                     if path.is_file() and path.suffix in {".sol", ".toml", ".yml"}
                     and not {"out", "cache"}.intersection(path.relative_to(ROOT).parts))
    return sorted(set(files))


def pins(files: list[Path]) -> dict[str, str]:
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in files}


class OfflineRunner:
    """Only local Forge build/test; no inherited credentials or project overrides."""

    def __init__(self, forge: Path, home: Path, log: Path, timeout: int = 60):
        self.forge, self.home, self.log, self.timeout = forge, home, log, timeout
        self.sequence = 0
        self.environment = {"HOME": str(home), "PATH": "/usr/bin:/bin", "RAYON_NUM_THREADS": "1",
                            "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}

    def execute(self, command: list[str], cwd: Path) -> ExecutionResult:
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd, env=self.environment, timeout=self.timeout,
                                    capture_output=True, text=True, check=False)
            execution = ExecutionResult(command=command, cwd=str(cwd), exit_code=result.returncode,
                                        stdout=result.stdout, stderr=result.stderr,
                                        success=result.returncode == 0)
        except subprocess.TimeoutExpired as exc:
            def decode(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            execution = ExecutionResult(command=command, cwd=str(cwd), stdout=decode(exc.stdout),
                                        stderr=decode(exc.stderr), timed_out=True)
        except OSError as exc:
            execution = ExecutionResult.failed(command, str(cwd), str(exc))
        execution.duration_seconds = time.monotonic() - start
        self.sequence += 1
        write_json(self.log / f"{self.sequence:04d}.json", execution.model_dump(mode="json"))
        return execution

    def run(self, command, cwd, env=None):
        if env is not None or list(command[:2]) not in (["forge", "build"], ["forge", "test"]):
            raise ValueError("Audit accepts framework-owned Forge build/test commands only")
        return self.execute([str(self.forge), *command[1:], "--offline", "--threads", "1"], cwd)


def security_transition(before: ExecutionResult, after: ExecutionResult) -> bool:
    baseline, current = test_results(before), test_results(after)
    return bool(before.exit_code == 1 and len(baseline) == 1 and baseline.keys() == current.keys()
                and all(key.endswith("::testSecurity()") for key in baseline)
                and all(status == "Failure" for status in baseline.values())
                and passed(after, "testSecurity"))


def pending_external(report_path: Path) -> list[dict]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    rows, seen = [], set()
    for case in report["cases"]:
        identifier = case["case_id"]
        if identifier in seen:
            raise ValueError("Duplicate external case")
        seen.add(identifier)
        findings = case["matched_finding_ids"]
        if len(set(findings)) != len(findings):
            raise ValueError("Duplicate external finding")
        rows.append({"case_id": identifier, "target_contract": case["target_contract"],
                     "source_sha256": case["source_sha256"], "ground_truth": case["ground_truth"],
                     "matched_finding_ids": findings, "unmatched_findings": case["unmatched_findings"],
                     "verification_status": "not_attempted_no_target_specific_reviewed_oracle",
                     "confirmed_by_this_audit": False})
    return rows


def copy_project(source: Path, destination: Path) -> None:
    # Copy only the trusted fixture's declared inputs, never caches, .env or keys.
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if path.is_file() and path.suffix in {".sol", ".toml", ".yml"} and not {"out", "cache"}.intersection(relative.parts):
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())


def rejection_control(name: str, state: RuntimeState, root: Path, foundry: FoundryRunner) -> dict:
    project = root / name
    copy_project(Path(state.project_path), project)
    trial = state.model_copy(deep=True)
    trial.project_path = str(project)
    trial.workspace_path = None
    relative_oracle = Path(state.exploit_artifact.test_file).relative_to(state.project_path)
    trial.exploit_artifact.test_file = str(project / relative_oracle)
    if name == "unchanged_patch":
        for file, source in trial.original_source.items():
            (project / file).write_text(source, encoding="utf-8")
        trial.patched_source = dict(trial.original_source)
    elif name == "altered_oracle":
        path = project / relative_oracle
        path.write_text(path.read_text() + "\n// intentional oracle-tampering control\n")
    elif name == "missing_regression":
        trial.baseline_regression_result = None
    elif name == "empty_regression":
        # Explicit synthetic gate mutation; never represented as executed evidence.
        trial.baseline_regression_result = ExecutionResult(command=["synthetic-empty-suite-control"],
                                                         cwd=str(project), exit_code=0, success=True, stdout="{}")
    elif name == "invalid_patch":
        for file in trial.patched_source:
            trial.patched_source[file] += "\ncontract {\n"
            (project / file).write_text(trial.patched_source[file], encoding="utf-8")
    else:
        raise ValueError("Unknown rejection control")
    Judge(foundry).verify(trial)
    return {"name": name, "accepted": bool(trial.judge_result and trial.judge_result.verified),
            "synthetic_result_injection": name == "empty_regression",
            "judge": trial.judge_result.model_dump(mode="json") if trial.judge_result else None,
            "state": trial.final_verification_state}


def run_case(case: tuple[str, str, str], root: Path, artifacts: Path, foundry: FoundryRunner) -> dict:
    name, fixture, file = case
    project = root / name
    copy_project(ROOT / "examples" / fixture, project)
    positive = ROOT / "benchmarks/verification" / f"{name}-positive.sol"
    (project / "test/Functional.t.sol").write_bytes(positive.read_bytes())
    original = (project / file).read_text(encoding="utf-8")
    identifier = f"heuristic-{name}"
    finding = VulnerabilityFinding(id=identifier, source="local-heuristic", detector="reviewed-fixture",
                                   description="Existing local demonstration, not a new discovery", file=file)
    state = RuntimeState(project_path=str(project), source_files=[file], original_source={file: original},
                         findings=[finding], candidate_id=identifier)
    row = {"case_id": name, "cohort": "existing_demonstration_fixture", "confirmed": False,
           "repair_verified": False, "security_transition": False, "controls": [], "error": None}
    try:
        RedTeam(foundry).generate_and_validate(state)
        row["confirmed"] = state.exploit_confirmed
        if not state.exploit_confirmed or not passed(state.baseline_regression_result):
            raise ValueError("Exploit or nonempty baseline regressions did not pass")
        BlueTeam().generate_and_apply(state)
        if not state.patched_source:
            raise ValueError("No repair produced")
        for control in CONTROLS:
            row["controls"].append(rejection_control(control, state, root / f"{name}-controls", foundry))
        Judge(foundry).verify(state)
        row["repair_verified"] = bool(state.judge_result and state.judge_result.verified)
        functional = foundry.named_test(project, "testFunctional")
        row["functional_passed"] = passed(functional, "testFunctional")

        # Security assertions are kept separate from the passing-regression oracle.
        security_path = project / "test/Security.t.sol"
        security_path.write_bytes((ROOT / "benchmarks/verification" / f"{name}-security.sol").read_bytes())
        (project / file).write_text(original, encoding="utf-8")
        before = foundry.named_test(project, "testSecurity")
        (project / file).write_text(state.patched_source[file], encoding="utf-8")
        after = foundry.named_test(project, "testSecurity")
        row["security_before"] = before.model_dump(mode="json")
        row["security_after"] = after.model_dump(mode="json")
        row["security_transition"] = security_transition(before, after)
        destination = artifacts / name
        copy_project(project, destination)
        (destination / "original.sol").write_text(original, encoding="utf-8")
        (destination / "repair.diff").write_text("".join(difflib.unified_diff(
            original.splitlines(True), state.patched_source[file].splitlines(True),
            fromfile=f"a/{file}", tofile=f"b/{file}")), encoding="utf-8")
        row["artifact_sha256"] = {path.relative_to(destination).as_posix(): digest(path)
                                  for path in destination.rglob("*") if path.is_file()}
    except Exception as exc:  # Keep every planned case, including execution failures.
        row["error"] = f"{type(exc).__name__}: {exc}"
    row["runtime_state"] = state.model_dump(mode="json")
    row["audit_passed"] = bool(not row["error"] and row["confirmed"] and row["repair_verified"]
                               and row.get("functional_passed") and row["security_transition"]
                               and len(row["controls"]) == len(CONTROLS)
                               and all(not control["accepted"] for control in row["controls"]))
    return row


def run(output: Path, forge: Path, solc: Path, external_report: Path | None = None) -> dict:
    forge, solc = forge.expanduser().resolve(), solc.expanduser().resolve()
    if not forge.is_file() or not solc.is_file():
        raise ValueError("Installed Forge and a local solc executable are required")
    files = input_files()
    if external_report:
        files.append(external_report.resolve())
    before = pins(files)
    pending = pending_external(external_report) if external_report else []
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "commands"
    logs.mkdir()
    for source in files:
        destination = output / "snapshot" / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    protocol = {"version": 1, "scope": "offline_fixture_evidence_audit_not_accuracy",
                "cases": [case[0] for case in CASES], "controls": list(CONTROLS), "input_sha256": before,
                "tools": {"forge": {"path": str(forge), "sha256": digest(forge)},
                          "solc": {"path": str(solc), "sha256": digest(solc)}},
                "precision_target": 0.99, "recall_target": 0.80,
                "independent_benchmark": False, "external_pending": pending}
    write_json(output / "protocol.json", protocol)
    rows = []
    previous_solc = settings.solc_binary
    try:
        settings.solc_binary = solc
        with tempfile.TemporaryDirectory(prefix="sentinel-evidence-") as folder:
            temporary = Path(folder)
            home = temporary / "home"
            home.mkdir()
            runner = OfflineRunner(forge, home, logs)
            versions = [runner.execute([str(tool), "--version"], temporary) for tool in (forge, solc)]
            if any(not result.success for result in versions):
                raise ValueError("Tool version check failed; see saved commands")
            foundry = FoundryRunner(runner)
            for case in CASES:
                row = run_case(case, temporary, output / "artifacts", foundry)
                rows.append(row)
                write_json(output / f"case-{case[0]}.json", row)
    finally:
        settings.solc_binary = previous_solc
        inputs_unchanged = pins(files) == before
        tools_unchanged = all(digest(Path(tool["path"])) == tool["sha256"] for tool in protocol["tools"].values())
        complete = len(rows) == len(CASES)
        report = {"scope": protocol["scope"], "protocol_sha256": digest(output / "protocol.json"),
                  "cases_planned": len(CASES), "cases_completed": len(rows),
                  "cases_passed": sum(row["audit_passed"] for row in rows), "cases": rows,
                  "controls_planned": len(CASES) * len(CONTROLS),
                  "controls_rejected": sum(not control["accepted"] for row in rows for control in row["controls"]),
                  "inputs_unchanged": inputs_unchanged, "tools_unchanged": tools_unchanged,
                  "external_pending": pending, "precision": None, "recall": None,
                  "precision_target_met": False, "model_or_detector_promoted": False,
                  "audit_passed": bool(complete and inputs_unchanged and tools_unchanged
                                       and all(row["audit_passed"] for row in rows))}
        write_json(output / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing results are never overwritten")
    parser.add_argument("--forge", type=Path, default=Path.home() / ".foundry/bin/forge")
    parser.add_argument("--solc", type=Path, default=Path.home() / ".solc-select/artifacts/solc-0.8.20/solc-0.8.20")
    parser.add_argument("--external-report", type=Path, help="Saved in-repository candidate-only report to retain as pending")
    args = parser.parse_args()
    report = run(args.output.resolve(), args.forge, args.solc, args.external_report)
    print(json.dumps({key: value for key, value in report.items() if key not in {"cases", "external_pending"}}, indent=2))
    raise SystemExit(0 if report["audit_passed"] else 2)


if __name__ == "__main__":
    main()
