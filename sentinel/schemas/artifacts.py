from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.execution import ExecutionResult


class ExploitArtifact(BaseModel):
    vulnerability_id: str
    test_file: str
    test_name: str = "testExploit"
    source: str
    rationale: str
    execution: ExecutionResult | None = None
    confirmed: bool = False
    origin: Literal["unreviewed", "reviewed_fixture", "model_generated"] = "unreviewed"


class PatchArtifact(BaseModel):
    vulnerability_id: str
    original_file: str
    patch: str
    modified_lines: list[int] = Field(default_factory=list)
    rationale: str
    attempt: int


class AuditReport(BaseModel):
    project: str
    timestamp: str
    findings: list[dict[str, object]] = Field(default_factory=list)
    confirmed_vulnerabilities: list[str] = Field(default_factory=list)
    discarded_findings: list[str] = Field(default_factory=list)
    exploits: list[ExploitArtifact] = Field(default_factory=list)
    patches: list[PatchArtifact] = Field(default_factory=list)
    verification: dict[str, object] = Field(default_factory=dict)
    gas_metrics: dict[str, object] = Field(default_factory=dict)
    retry_history: list[dict[str, object]] = Field(default_factory=list)
