import re
from pathlib import Path

from sentinel.config import settings
from sentinel.runner import ControlledRunner
from sentinel.schemas.execution import ExecutionResult


class FoundryRunner:
    def __init__(self, runner: ControlledRunner) -> None:
        self.runner = runner

    def build(self, project: Path) -> ExecutionResult:
        return self.runner.run(["forge", "build", *self._compiler_args()], project)

    @staticmethod
    def _compiler_args() -> list[str]:
        return ["--use", str(settings.solc_binary)] if settings.solc_binary else []

    def exploit(self, project: Path, test_name: str = "testExploit", *, test_file: str) -> ExecutionResult:
        return self.runner.run(["forge", "test", "--json", "--match-test", self._selector(test_name), "--match-path", test_file, *self._compiler_args()], project)

    def regression(self, project: Path, test_name: str = "testExploit") -> ExecutionResult:
        return self.runner.run(["forge", "test", "--json", "--no-match-test", self._selector(test_name), *self._compiler_args()], project)

    def named_test(self, project: Path, test_name: str) -> ExecutionResult:
        return self.runner.run(["forge", "test", "--json", "--match-test", self._selector(test_name), *self._compiler_args()], project)

    @staticmethod
    def _selector(name: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("Test name must be a Solidity identifier")
        return rf"^{re.escape(name)}\(.*\)$"
