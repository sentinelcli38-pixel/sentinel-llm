import json
import re
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.analyzers.parsers import (
    parse_mythril,
    parse_sentinel_static,
    parse_slither,
    rank_and_deduplicate,
)
from sentinel.runner import ControlledRunner
from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.vulnerability import VulnerabilityFinding


@dataclass
class AnalysisBundle:
    runs: list[AnalyzerRun] = field(default_factory=list)
    findings: list[VulnerabilityFinding] = field(default_factory=list)


def project_compiler(project: Path, profile: dict, fallback: Path | None) -> Path | None:
    configured = profile.get("solc")
    if isinstance(configured, str) and "/" in configured:
        compiler = (project / configured).resolve()
        if not compiler.is_file():
            raise ValueError("The project's explicit compiler path is unavailable")
        return compiler
    return fallback


def project_sources(project: Path) -> tuple[list[Path], dict]:
    project = project.resolve()
    config = tomllib.loads((project / "foundry.toml").read_text(encoding="utf-8"))
    profile = config.get("profile", {}).get("default", {})
    root = (project / profile.get("src", "src")).resolve()
    if root != project and project not in root.parents:
        raise ValueError("Foundry source directory escapes project")
    paths = sorted(root.rglob("*.sol")) if root.is_dir() else []
    for path in paths:
        if project not in path.resolve().parents:
            raise ValueError(f"Source symlink escapes project: {path.name}")
    return paths, profile


def _analyze(tool: str, target: str, command: list[str], project: Path,
             runner: ControlledRunner, parser, env: dict[str, str] | None = None) -> tuple[AnalyzerRun, list[VulnerabilityFinding]]:
    execution = runner.run(command, project, env=env)
    if execution.timed_out:
        return AnalyzerRun(tool=tool, target=target, status="timed_out", execution=execution,
                           diagnostics=["Analysis exceeded its process time limit; coverage is incomplete"]), []
    if execution.exit_code == -1:
        return AnalyzerRun(tool=tool, target=target, status="unavailable", execution=execution,
                           diagnostics=[execution.stderr]), []
    try:
        document = json.loads(execution.stdout)
        if isinstance(document, dict) and document.get("success") is False:
            detail = document.get("error")
            return AnalyzerRun(
                tool=tool, target=target, status="failed", execution=execution,
                diagnostics=[detail if isinstance(detail, str) else "Analyzer reported failure"],
            ), []
        findings = parser(execution.stdout, project)
    except (ValueError, TypeError) as exc:
        status = "invalid_output" if execution.success else "failed"
        return AnalyzerRun(tool=tool, target=target, status=status, execution=execution,
                           diagnostics=[str(exc), execution.stderr or execution.stdout]), []
    # A signal/crash must not be masked by an earlier successful JSON document.
    if execution.exit_code not in (0, 1, 255):
        return AnalyzerRun(tool=tool, target=target, status="failed", execution=execution,
                           diagnostics=["Unexpected process exit after analyzer output"]), []
    return AnalyzerRun(tool=tool, target=target, status="completed", execution=execution,
                       finding_count=len(findings)), findings


def run_scout_tools(project: Path, runner: ControlledRunner, *, mythril_timeout: int = 60,
                    transaction_count: int = 2, solc_binary: Path | None = None,
                    mythril_binary: Path | None = None,
                    static_binary: Path | None = None,
                    mythril_max_sources: int = 10,
                    enabled_analyzers: set[str] | None = None,
                    demo_fallback: bool = False) -> AnalysisBundle:
    """Run Slither plus bounded Mythril analysis without unbounded corpus runtimes."""
    project = project.resolve()
    enabled = enabled_analyzers or {"slither", "mythril"}
    if not enabled <= {"slither", "mythril", "sentinel-static"} or not enabled:
        raise ValueError("At least one supported analyzer must be enabled")
    paths, profile = project_sources(project)
    solc_binary = project_compiler(project, profile, solc_binary)
    # Slither follows imports and will otherwise report hundreds of issues in vendored
    # libraries.  Keep the audit focused on the target project's configured source
    # directory; callers can scan a dependency as its own Foundry project when needed.
    configured_source = (project / profile.get("src", "src")).resolve()

    def is_project_source(finding: VulnerabilityFinding) -> bool:
        if not finding.file:
            return False
        candidate = (project / finding.file).resolve()
        return candidate == configured_source or configured_source in candidate.parents

    bundle = AnalysisBundle()
    if "slither" in enabled:
        run, findings = _analyze("slither", ".", ["slither", ".", "--json", "-"], project, runner, parse_slither)
        # Preserve unlocated evidence so scoped evaluation can flag ambiguous
        # attribution instead of silently counting it as an absent finding.
        findings = [finding for finding in findings if not finding.file or is_project_source(finding)]
        # The report describes the target-project findings, rather than the scanner's
        # raw total which also includes imported third-party dependencies.
        run.finding_count = len(findings)
        bundle.runs.append(run)
        bundle.findings.extend(findings)
    if "sentinel-static" in enabled:
        static_command = str(static_binary.resolve()) if static_binary else "sentinel-static"
        run, findings = _analyze("sentinel-static", ".", [static_command, "."], project, runner, parse_sentinel_static)
        findings = [finding for finding in findings if not finding.file or is_project_source(finding)]
        run.finding_count = len(findings)
        bundle.runs.append(run)
        bundle.findings.extend(findings)
    # Keep compiler settings/remappings aligned with the default Foundry profile.
    remappings = list(profile.get("remappings", []))
    remapping_file = project / "remappings.txt"
    if remapping_file.is_file():
        remappings.extend(line.strip() for line in remapping_file.read_text().splitlines()
                          if line.strip() and not line.lstrip().startswith("#"))
    with tempfile.TemporaryDirectory(prefix="sentinel-solc-") as temp:
        settings_file = Path(temp) / "settings.json"
        solc_settings = {"remappings": remappings}
        if "optimizer" in profile:
            solc_settings["optimizer"] = {"enabled": bool(profile["optimizer"]), "runs": profile.get("optimizer_runs", 200)}
        if "evm_version" in profile:
            solc_settings["evmVersion"] = profile["evm_version"]
        if "via_ir" in profile:
            solc_settings["viaIR"] = bool(profile["via_ir"])
        settings_file.write_text(json.dumps(solc_settings), encoding="utf-8")
        selected_paths = paths[:mythril_max_sources] if "mythril" in enabled else []
        for path in selected_paths:
            myth_command = str(mythril_binary.resolve()) if mythril_binary and mythril_binary.is_file() else "myth"
            command = [myth_command, "analyze", str(path), "-o", "json", "--no-onchain-data",
                       "--execution-timeout", str(mythril_timeout),
                       "--transaction-count", str(transaction_count), "--solc-json", str(settings_file)]
            version = profile.get("solc_version", profile.get("solc"))
            myth_env = {"MYTHRIL_DIR": str(Path(temp) / "mythril")}
            has_configured_solc = bool(solc_binary and solc_binary.is_file())
            if has_configured_solc:
                myth_env["SOLC"] = str(solc_binary.resolve())
            if not has_configured_solc and isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version):
                command.extend(["--solv", version])
            run, findings = _analyze("mythril", path.relative_to(project).as_posix(), command,
                                     project, runner, parse_mythril, myth_env)
            bundle.runs.append(run)
            bundle.findings.extend(findings)
            if run.status == "unavailable":
                bundle.runs.append(AnalyzerRun(tool="mythril", target="remaining sources", status="skipped",
                                               diagnostics=["Mythril unavailable; remaining source files were not analyzed"]))
                break
        if "mythril" in enabled and len(paths) > len(selected_paths):
            bundle.runs.append(AnalyzerRun(
                tool="mythril", target="remaining sources", status="skipped",
                diagnostics=[f"Mythril source limit is {mythril_max_sources}; {len(paths) - len(selected_paths)} source file(s) were not analyzed"],
            ))
    if "mythril" in enabled and not paths:
        bundle.runs.append(AnalyzerRun(tool="mythril", target=".", status="skipped",
                                       diagnostics=["No Solidity source files found"]))
    # Mock mode is an explicitly labeled deterministic fixture workflow. Keep its
    # reviewed hint even when installed analyzers also produce unrelated candidates.
    if demo_fallback:
        bundle.findings.extend(_demo_findings(project, paths))
    bundle.findings = rank_and_deduplicate(bundle.findings)
    return bundle


def _demo_findings(project: Path, paths: list[Path]) -> list[VulnerabilityFinding]:
    """Explicit demo-only hints retained for the existing example workflow."""
    findings = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        call = source.find(".call{")
        effect = source.find("balances[msg.sender] = 0;")
        if (path.name in {"Vault.sol", "VulnerableVault.sol"} or "// reentrancy demo" in source) and call >= 0 and effect > call:
            findings.append(VulnerabilityFinding(
                id="heuristic-reentrancy", source="local-heuristic", sources=["local-heuristic"],
                detector="external-call-order", severity="high", confidence="low", confidence_score=0.3,
                file=path.relative_to(project).as_posix(), line=source[:call].count("\n") + 1,
                description="Demo heuristic: external call before balance update; requires validation.",
                evidence=["Demo-only lexical pattern; not a Slither or Mythril result"],
            ))
        if "function sweep" in source and "owner" in source and "msg.sender" not in source.split("function sweep", 1)[1].split("}", 1)[0]:
            findings.append(VulnerabilityFinding(
                id="heuristic-access-control", source="local-heuristic", sources=["local-heuristic"],
                detector="missing-authorization", severity="critical", confidence="low", confidence_score=0.3,
                file=path.relative_to(project).as_posix(), description="Demo heuristic: sweep lacks a caller check.",
                evidence=["Demo-only lexical pattern; not a Slither or Mythril result"],
            ))
        if "tx.origin" in source:
            findings.append(VulnerabilityFinding(
                id="heuristic-tx-origin", source="local-heuristic", sources=["local-heuristic"],
                detector="tx-origin-authentication", severity="high", confidence="low", confidence_score=0.3,
                file=path.relative_to(project).as_posix(), line=source[:source.find("tx.origin")].count("\n") + 1,
                description="Demo heuristic: authorization uses tx.origin instead of msg.sender.",
                evidence=["Demo-only lexical pattern; not a Slither or Mythril result"],
            ))
        if ".call{" in source and "unchecked low-level call" in source:
            call = source.find(".call{")
            findings.append(VulnerabilityFinding(
                id="heuristic-unchecked-call", source="local-heuristic", sources=["local-heuristic"],
                detector="unchecked-low-level-call", severity="medium", confidence="low", confidence_score=0.3,
                file=path.relative_to(project).as_posix(), line=source[:call].count("\n") + 1,
                description="Demo heuristic: low-level call result is ignored.",
                evidence=["Demo-only lexical pattern; not a Slither or Mythril result"],
            ))
    return findings


def extract_solidity_context(project: Path) -> tuple[list[str], dict[str, str], dict[str, object]]:
    project = project.resolve()
    paths, _ = project_sources(project)
    source_files = [path.relative_to(project).as_posix() for path in paths]
    original = {name: (project / name).read_text(encoding="utf-8") for name in source_files}
    context = {"contracts": [], "functions": [], "state_variables": [], "source_locations": []}
    for source in original.values():
        context["contracts"].extend(line.strip() for line in source.splitlines() if line.strip().startswith("contract "))
        context["functions"].extend(line.strip() for line in source.splitlines() if " function " in f" {line}")
    return source_files, original, context
