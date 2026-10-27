import json
from datetime import UTC, datetime
from pathlib import Path

from sentinel.coverage import coverage_complete
from sentinel.reporting.sarif import render_sarif
from sentinel.schemas.state import RuntimeState


def _tool_message(run) -> str:
    if run.status == "completed":
        return f"{run.tool} finished and reported {run.finding_count} candidate(s)."
    if run.status == "unavailable":
        return "not available on this machine."
    if run.status == "timed_out":
        return "exceeded its time limit."
    if run.status == "skipped":
        return "was skipped."
    return "failed; technical output is retained only in the JSON ledger."


def _scout_summary(state: RuntimeState) -> str:
    has_fixture = any(finding.source == "local-heuristic" for finding in state.findings)
    if state.mock_mode and has_fixture:
        return "fixture candidate selected for the deterministic demonstration"
    if coverage_complete(state):
        return "live scanner analysis completed"
    return "live scanner coverage is incomplete"


def render_report(state: RuntimeState) -> str:
    lines = [
        "# Sentinel Security Audit",
        "",
        "## Project",
        f"`{state.project_path}`",
        "",
        "## Execution Summary",
        f"- Final state: **{state.final_verification_state}**",
        f"- Source files: {len(state.source_files)}",
        f"- Runtime: {state.gas_metrics.get('duration_seconds', 'not measured')}",
        "",
        "## Pipeline Timeline",
        f"- **1. Scout:** {_scout_summary(state)} — {len(state.findings)} candidate(s) recorded.",
        f"- **2. Red Team:** {'PoC confirmed' if state.exploit_confirmed else 'not confirmed'} — {'exploit test created' if state.exploit_artifact else 'no exploit test created'}.",
        f"- **3. Blue Team:** {'patch proposed' if state.patch_artifact else 'no patch proposed'}.",
        f"- **4. Judge:** {'verified' if state.judge_result and state.judge_result.verified else 'not run or not verified'}.",
        "",
        "## Findings",
    ]
    novelty = state.novelty_assessment
    if novelty:
        lines.extend([
            "",
            "## Unknown-Risk Triage",
            f"- Method: `{novelty.get('method', 'not recorded')}`",
            f"- Signals requiring review: {novelty.get('candidate_count', 0)}",
            f"- Scope: {novelty.get('scope', 'not recorded')}",
        ])
    if not state.findings:
        lines.append("No vulnerability candidates were recorded.")
    for index, finding in enumerate(state.findings, start=1):
        location = f"{finding.file}:{finding.line}" if finding.file else "unknown"
        lines.extend([
            f"### {index}. {finding.detector.replace('-', ' ').title()}",
            f"- **Severity:** {finding.severity}; **status:** {finding.status}.",
            f"- **Location:** `{location}`.",
            f"- **What was observed:** {finding.description}",
            f"- **Evidence:** {'; '.join(finding.evidence) or 'No additional evidence recorded.'}",
            "",
        ])
    lines.extend([
        "",
        "## Tool Availability",
        *[f"- **{run.tool}** / `{run.target}`: {_tool_message(run)}" for run in state.analyzer_runs],
        "",
        "## Reproducibility",
        *([f"- **{key}:** {value}" for key, value in state.reproducibility.items()] or ["- Runtime metadata was not recorded."]),
        "",
        "## Notes",
        *([f"- {message}" for message in state.feedback] or ["- No workflow diagnostics."]),
        "",
        "## Judge Verification",
        f"- Build: {state.judge_result.build_passed if state.judge_result else 'not run'}",
        f"- Exploit defense: {state.judge_result.exploit_neutralized if state.judge_result else 'not run'}",
        f"- Regression: {state.judge_result.regression_passed if state.judge_result else 'not run'}",
        f"- Verified: {state.judge_result.verified if state.judge_result else 'not run'}",
        "",
        "## Exploit Artifact",
        f"- Result: {'The exploit was reproduced before patching.' if state.exploit_confirmed else 'No exploit was confirmed.'}",
        *([f"- Saved test source: `{Path(path).name}`" for path in state.report_artifacts if ".exploit.t.sol" in Path(path).name] or ["- Test source was not saved because no PoC was generated."]),
        "```solidity",
        state.exploit_source or "No exploit source was generated.",
        "```",
        "",
        "## Proposed Patch",
        f"- Purpose: {state.patch_artifact.rationale if state.patch_artifact else 'No patch was generated.'}",
        *([f"- Saved patched Solidity file: `{Path(path).name}`" for path in state.report_artifacts if ".patch.sol" in Path(path).name] or []),
        "```diff",
        state.patch_diff or "No patch was generated.",
        "```",
        "",
        "## Retry History",
        f"Attempts recorded: {len(state.retry_history)}",
        "",
        "## Gas Comparison",
        "Gas comparison unavailable for this execution unless measured by Foundry.",
        "",
        "## How to read this report",
        "- A **candidate** is a scanner or fixture pattern, not a proven exploit.",
        "- **confirmed** means the Red Team's Forge test reproduced the impact.",
        "- **verified** means a reviewed, unchanged exploit passed on the original and failed on the patched copy, while the same nonempty regression suite and configured checks passed. It is not a guarantee that the contract is safe.",
        "- **execution_unavailable** or **analysis_incomplete** means install/configure the listed local tool before treating the absence of findings as meaningful.",
        "",
        "## Final Outcome",
        f"**{state.final_verification_state}**",
        "",
    ])
    return "\n".join(lines)


def write_report(state: RuntimeState, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    stem = f"sentinel-report-{stamp}"
    report_path = output_dir / f"{stem}.md"
    state.final_report_path = str(report_path)
    state.report_artifacts = []
    if state.exploit_source:
        candidate = "".join(char if char.isalnum() or char in "-_" else "-" for char in (state.candidate_id or "candidate"))
        exploit_path = output_dir / f"{stem}__{candidate}.exploit.t.sol"
        exploit_path.write_text(state.exploit_source, encoding="utf-8")
        state.report_artifacts.append(str(exploit_path))
    for relative, source in state.patched_source.items():
        name = Path(Path(relative).name).stem
        patched_path = output_dir / f"{stem}__{name}.patch.sol"
        patched_path.write_text(source, encoding="utf-8")
        state.report_artifacts.append(str(patched_path))
    report_path.write_text(render_report(state), encoding="utf-8")
    sarif_path = report_path.with_suffix(".sarif")
    sarif_path.write_text(json.dumps(render_sarif(state), indent=2) + "\n", encoding="utf-8")
    state.report_artifacts.append(str(sarif_path))
    report_path.with_suffix(".json").write_text(state.json_ledger(), encoding="utf-8")
    summary_path = output_dir / f"{stem}__summary.json"
    summary_path.write_text(json.dumps({
        "outcome": state.final_verification_state,
        "pipeline": {
            "scout": _scout_summary(state),
            "red_team": "exploit confirmed" if state.exploit_confirmed else "exploit not confirmed",
            "blue_team": "patch proposed" if state.patch_artifact else "no patch proposed",
            "judge": "verified" if state.judge_result and state.judge_result.verified else "not verified",
        },
        "findings": [{
            "type": finding.detector.replace("-", " "),
            "severity": finding.severity,
            "status": finding.status.value,
            "location": {"file": finding.file, "line": finding.line},
            "what_was_observed": finding.description,
            "evidence": finding.evidence,
        } for finding in state.findings],
        "unknown_risk_triage": state.novelty_assessment,
        "reproducibility": state.reproducibility,
        "patch": {
            "purpose": state.patch_artifact.rationale if state.patch_artifact else None,
            "changed_file": state.patch_artifact.original_file if state.patch_artifact else None,
            "patched_solidity_files": [Path(path).name for path in state.report_artifacts if ".patch.sol" in Path(path).name],
        },
        "verification": {
            "verified": bool(state.judge_result and state.judge_result.verified),
            "coverage_complete": coverage_complete(state),
            "build_passed": state.judge_result.build_passed if state.judge_result else False,
            "exploit_blocked": state.judge_result.exploit_neutralized if state.judge_result else False,
            "regression_passed": state.judge_result.regression_passed if state.judge_result else False,
        },
    }, indent=2) + "\n", encoding="utf-8")
    # One concise record per candidate keeps a large Scout scan reviewable without
    # pretending every candidate has an approved patch.
    findings_dir = output_dir / f"{stem}__findings"
    findings_dir.mkdir(exist_ok=True)
    for index, finding in enumerate(state.findings, start=1):
        contract = Path(finding.file).stem or "contract"
        safe_id = "".join(char if char.isalnum() or char in "-_" else "-" for char in finding.id)
        finding_stem = f"{index:04d}__{contract}__{safe_id}"
        is_selected = finding.id == state.candidate_id
        patch_name = next((Path(path).name for path in state.report_artifacts if ".patch.sol" in Path(path).name), None) if is_selected else None
        record = {
            "finding_id": finding.id,
            "type": finding.detector,
            "severity": finding.severity,
            "location": {"file": finding.file, "line": finding.line},
            "what_was_observed": finding.description,
            "evidence": finding.evidence,
            "pipeline_status": "selected_for_agentic_validation" if is_selected else "scout_candidate",
            "patch_file": patch_name,
            "patch_verified": bool(is_selected and state.judge_result and state.judge_result.verified),
        }
        (findings_dir / f"{finding_stem}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        lines = [f"# {contract}: {finding.detector}", "", f"- **Severity:** {finding.severity}",
                 f"- **Location:** `{finding.file}:{finding.line or 'unknown'}`", "", "## Observation", finding.description,
                 "", "## Evidence", *[f"- {item}" for item in finding.evidence], "", "## Status",
                 "Selected for Gemini/Forge validation." if is_selected else "Scout candidate; no exploit or patch has been approved yet."]
        if patch_name:
            label = "Verified" if state.judge_result and state.judge_result.verified else "Proposed, unverified"
            lines.extend(["", f"{label} patch artifact: `{patch_name}`"])
        (findings_dir / f"{finding_stem}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path
