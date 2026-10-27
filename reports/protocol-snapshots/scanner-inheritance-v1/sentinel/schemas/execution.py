from collections.abc import Sequence

from pydantic import BaseModel, Field


class ExecutionResult(BaseModel):
    command: list[str]
    cwd: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    success: bool = False

    @classmethod
    def failed(cls, command: Sequence[str], cwd: str, error: str) -> "ExecutionResult":
        return cls(command=list(command), cwd=cwd, stderr=error, exit_code=-1)


class JudgeResult(BaseModel):
    evidence_version: int = 0
    build_passed: bool = False
    exploit_neutralized: bool = False
    regression_passed: bool = False
    verified: bool = False
    failure_reason: str = ""
    feedback: str = ""
    positive_tests_passed: bool | None = None
    security_tests_passed: bool | None = None
    abi_compatible: bool | None = None
    storage_layout_compatible: bool | None = None
    additional_checks: list[str] = Field(default_factory=list)
