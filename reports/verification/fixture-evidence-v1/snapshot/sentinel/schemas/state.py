from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.artifacts import ExploitArtifact, PatchArtifact
from sentinel.schemas.execution import ExecutionResult, JudgeResult
from sentinel.schemas.operations import AlertRecord
from sentinel.schemas.vulnerability import VulnerabilityFinding


class RetryRecord(BaseModel):
    attempt: int
    failure_type: str
    feedback: str
    patch: str = ""
    execution: ExecutionResult | None = None


class RuntimeState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=False)

    project_path: str
    workspace_path: str | None = None
    mock_mode: bool = False
    experiment_profile: str = "sentinel-full"
    enabled_analyzers: list[str] = Field(default_factory=lambda: ["slither", "mythril"])
    max_retries: int = 5
    source_files: list[str] = Field(default_factory=list)
    compiler_info: dict[str, str] = Field(default_factory=dict)
    ast_context: dict[str, object] = Field(default_factory=dict)
    protocol_map: dict[str, object] = Field(default_factory=dict)
    risk_assessment: dict[str, object] = Field(default_factory=dict)
    novelty_assessment: dict[str, object] = Field(default_factory=dict)
    alerts: list[AlertRecord] = Field(default_factory=list)
    natspec_context: dict[str, str] = Field(default_factory=dict)
    slither_result: ExecutionResult | None = None
    mythril_results: list[ExecutionResult] = Field(default_factory=list)
    analyzer_runs: list[AnalyzerRun] = Field(default_factory=list)
    scout_only: bool = False
    aderyn_result: ExecutionResult | None = None
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    scout_results: list[str] = Field(default_factory=list)
    candidate_id: str | None = None
    exploit_source: str = ""
    exploit_artifact: ExploitArtifact | None = None
    exploit_result: ExecutionResult | None = None
    baseline_exploit_result: ExecutionResult | None = None
    baseline_regression_result: ExecutionResult | None = None
    oracle_test_hashes: dict[str, str] = Field(default_factory=dict)
    exploit_confirmed: bool = False
    original_source: dict[str, str] = Field(default_factory=dict)
    patched_source: dict[str, str] = Field(default_factory=dict)
    patch_diff: str = ""
    patch_artifact: PatchArtifact | None = None
    compilation_result: ExecutionResult | None = None
    regression_result: ExecutionResult | None = None
    judge_result: JudgeResult | None = None
    gas_metrics: dict[str, object] = Field(default_factory=dict)
    reproducibility: dict[str, object] = Field(default_factory=dict)
    retry_count: int = 0
    retry_history: list[RetryRecord] = Field(default_factory=list)
    feedback: list[str] = Field(default_factory=list)
    final_verification_state: str = "not_started"
    final_report_path: str | None = None
    report_artifacts: list[str] = Field(default_factory=list)

    def json_ledger(self) -> str:
        return self.model_dump_json(indent=2)
