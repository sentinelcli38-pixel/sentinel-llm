import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from time import monotonic

from langgraph.graph import END, START, StateGraph

from sentinel.agents.blue_team import BlueTeam
from sentinel.agents.judge import Judge
from sentinel.agents.red_team import RedTeam
from sentinel.agents.scout import Scout
from sentinel.analyzers.tools import (
    extract_solidity_context,
    project_compiler,
    project_sources,
)
from sentinel.config import settings
from sentinel.coverage import coverage_complete
from sentinel.foundry.runner import FoundryRunner
from sentinel.llm.gemini import GeminiProvider, GeminiScout
from sentinel.llm.mock import MockProvider
from sentinel.llm.ollama import OllamaBlueTeam
from sentinel.llm.openai import OpenAIRedTeam
from sentinel.novelty import detect_novelty_signals
from sentinel.protocol import build_protocol_map
from sentinel.risk import assess_protocol_risk
from sentinel.runner import ControlledRunner
from sentinel.schemas.state import RetryRecord, RuntimeState

WorkflowObserver = Callable[[str, RuntimeState, str, float], None]


def build_workflow(runner: ControlledRunner | None = None, observer: WorkflowObserver | None = None):
    controlled = runner or ControlledRunner(settings.command_timeout_seconds)
    foundry = FoundryRunner(controlled)
    if settings.llm_provider == "gemini":
        red_blue_provider = GeminiProvider(settings.gemini_model)
    elif settings.llm_provider == "openai":
        red_blue_provider = OpenAIRedTeam(settings.red_team_model)
    else:
        red_blue_provider = OllamaBlueTeam(settings.ollama_host, settings.blue_team_model)
    red_team = RedTeam(foundry, red_blue_provider)
    blue_team = BlueTeam(red_blue_provider)
    judge = Judge(foundry)

    def observed(name: str, handler: Callable[[RuntimeState], RuntimeState]):
        def wrapped(state: RuntimeState) -> RuntimeState:
            started = monotonic()
            if observer:
                observer(name, state, "started", 0.0)
            try:
                result = handler(state)
            except Exception:
                if observer:
                    observer(name, state, "failed", monotonic() - started)
                raise
            if observer:
                observer(name, result, "completed", monotonic() - started)
            return result
        return wrapped

    def ingest(state: RuntimeState) -> RuntimeState:
        project = Path(state.project_path).resolve()
        if not (project / "foundry.toml").is_file():
            state.feedback.append("Target is not a Foundry project: foundry.toml is missing")
            state.final_verification_state = "invalid_project"
            return state
        workspace = Path(tempfile.mkdtemp(prefix="sentinel-workspace-")) / "project"
        state.workspace_path = str(workspace)
        try:
            shutil.copytree(project, workspace, ignore=shutil.ignore_patterns("out", "cache", ".git", "__pycache__"))
            files, original, context = extract_solidity_context(workspace)
        except (OSError, ValueError, TypeError) as exc:
            shutil.rmtree(workspace.parent, ignore_errors=True)
            state.workspace_path = None
            state.feedback.append(f"Invalid project source configuration: {exc}")
            state.final_verification_state = "invalid_project"
            return state
        state.workspace_path = str(workspace)
        state.source_files, state.original_source, state.ast_context = files, original, context
        state.protocol_map = build_protocol_map(original)
        return state

    def static_analysis(state: RuntimeState) -> RuntimeState:
        project = Path(state.workspace_path or state.project_path)
        compiler_path = project_compiler(project, project_sources(project)[1], settings.solc_binary)
        compiler_command = str(compiler_path) if compiler_path else "solc"
        compiler = controlled.run([compiler_command, "--version"], project)
        state.compiler_info = {
            "command": f"{compiler_command} --version",
            "output": compiler.stdout or compiler.stderr,
        }
        return state

    def scout_node(state: RuntimeState) -> RuntimeState:
        scout = Scout(MockProvider() if state.mock_mode else GeminiScout(settings.scout_model), controlled)
        state = scout.analyze(state)
        state.novelty_assessment, novelty_findings = detect_novelty_signals(state.original_source)
        state.findings.extend(novelty_findings)
        # Novelty signals are intentionally not candidate_id values: only scanner
        # evidence may enter the automated exploit/patch loop.
        state.risk_assessment = assess_protocol_risk(state.protocol_map, state.findings)
        complete = coverage_complete(state)
        if state.scout_only:
            state.final_verification_state = "scout_complete" if complete else "scout_incomplete"
        elif not state.findings:
            state.final_verification_state = "no_candidates" if complete else "analysis_incomplete"
        if novelty_findings and state.final_verification_state in {
            "no_candidates", "scout_complete", "scout_incomplete", "analysis_incomplete",
        }:
            state.final_verification_state = "novelty_review_required"
            state.feedback.append("Unknown-risk signals were recorded for human review; no exploit or patch was generated from source heuristics alone.")
        return state

    def route_after_scout(state: RuntimeState) -> str:
        return "red_team" if state.final_verification_state == "not_started" else "report"

    def red_team_node(state: RuntimeState) -> RuntimeState:
        return red_team.generate_and_validate(state)

    def discard_node(state: RuntimeState) -> RuntimeState:
        state.final_verification_state = "finding_discarded"
        state.feedback.append("Red Team PoC did not empirically confirm the candidate.")
        return state

    def blue_team_node(state: RuntimeState) -> RuntimeState:
        if state.retry_count and state.candidate_id:
            finding = next((item for item in state.findings if item.id == state.candidate_id), None)
            if finding and finding.file in state.original_source:
                (Path(state.workspace_path or state.project_path) / finding.file).write_text(state.original_source[finding.file], encoding="utf-8")
        return blue_team.generate_and_apply(state)

    def judge_node(state: RuntimeState) -> RuntimeState:
        result = judge.verify(state)
        if result.final_verification_state == "retry_required":
            state.retry_count += 1
            feedback = state.judge_result.feedback if state.judge_result else "Judge failure"
            state.retry_history.append(RetryRecord(
                attempt=state.retry_count, failure_type=state.judge_result.failure_reason if state.judge_result else "unknown",
                feedback=feedback, patch=state.patch_diff, execution=state.compilation_result,
            ))
            if state.retry_count >= state.max_retries:
                state.final_verification_state = "human_review_required"
        return result

    def route_after_exploit(state: RuntimeState) -> str:
        if state.final_verification_state in {"execution_unavailable", "human_review_required"}:
            return "report"
        return "blue_team" if state.exploit_confirmed else "discard"

    def route_after_judge(state: RuntimeState) -> str:
        if state.final_verification_state != "retry_required":
            return "report"
        if state.retry_count >= state.max_retries:
            return "report"
        return "blue_team"

    def report_node(state: RuntimeState) -> RuntimeState:
        if state.final_verification_state == "not_started":
            state.final_verification_state = "completed_without_confirmation"
        return state

    graph = StateGraph(RuntimeState)
    graph.add_node("ingest", observed("ingest", ingest))
    graph.add_node("static_analysis", observed("static_analysis", static_analysis))
    graph.add_node("scout", observed("scout", scout_node))
    graph.add_node("red_team", observed("red_team", red_team_node))
    graph.add_node("discard", observed("discard", discard_node))
    graph.add_node("blue_team", observed("blue_team", blue_team_node))
    graph.add_node("judge", observed("judge", judge_node))
    graph.add_node("report", observed("report", report_node))
    graph.add_edge(START, "ingest")
    graph.add_conditional_edges("ingest", lambda state: "report" if state.final_verification_state == "invalid_project" else "static_analysis")
    graph.add_edge("static_analysis", "scout")
    graph.add_conditional_edges("scout", route_after_scout, {"report": "report", "red_team": "red_team"})
    graph.add_conditional_edges("red_team", route_after_exploit, {"blue_team": "blue_team", "discard": "discard", "report": "report"})
    graph.add_edge("discard", "report")
    graph.add_conditional_edges("blue_team", lambda state: "judge" if state.final_verification_state in {"not_started", "retry_required"} and state.patch_diff else "report", {"judge": "judge", "report": "report"})
    graph.add_conditional_edges("judge", route_after_judge, {"blue_team": "blue_team", "report": "report"})
    graph.add_edge("report", END)
    return graph.compile()
