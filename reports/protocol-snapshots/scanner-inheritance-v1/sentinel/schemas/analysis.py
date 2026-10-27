from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.execution import ExecutionResult


class AnalyzerRun(BaseModel):
    tool: str
    target: str
    status: Literal["completed", "failed", "unavailable", "timed_out", "invalid_output", "skipped"]
    execution: ExecutionResult | None = None
    finding_count: int = 0
    diagnostics: list[str] = Field(default_factory=list)
