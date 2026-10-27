import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from sentinel.schemas.execution import ExecutionResult

ALLOWED_COMMANDS = frozenset({"solc", "slither", "sentinel-static", "myth", "aderyn", "forge", "cast", "docker"})
CommandObserver = Callable[[str, Sequence[str], Path, ExecutionResult | None], None]


class ControlledRunner:
    """Run only framework-owned local developer tools; never executes LLM commands."""

    def __init__(self, timeout_seconds: int = 120, observer: CommandObserver | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.observer = observer

    def _emit(self, status: str, command: Sequence[str], cwd: Path, result: ExecutionResult | None = None) -> None:
        if self.observer:
            try:
                self.observer(status, command, cwd, result)
            except Exception:  # noqa: BLE001 - telemetry cannot affect execution
                return

    def run(self, command: Sequence[str], cwd: Path, env: Mapping[str, str] | None = None) -> ExecutionResult:
        executable = Path(command[0]).name if command else ""
        allowed_versioned_solc = re.fullmatch(r"solc-\d+\.\d+\.\d+", executable)
        if not command or (executable not in ALLOWED_COMMANDS and not allowed_versioned_solc):
            raise ValueError(f"Command is not allowlisted: {command!r}")
        cwd = cwd.resolve()
        if not cwd.is_dir():
            raise ValueError(f"Working directory does not exist: {cwd}")
        if env is not None and set(env) - {"SOLC", "SOLC_VERSION", "MYTHRIL_DIR"}:
            raise ValueError("Only compiler environment and Mythril workspace overrides are allowed")
        started = time.monotonic()
        self._emit("started", command, cwd)
        try:
            completed = subprocess.run(
                list(command), cwd=cwd, capture_output=True, text=True,
                env={**os.environ, **(dict(env) if env else {})},
                timeout=self.timeout_seconds, check=False,
            )
            result = ExecutionResult(
                command=list(command), cwd=str(cwd), exit_code=completed.returncode,
                stdout=completed.stdout, stderr=completed.stderr,
                duration_seconds=time.monotonic() - started,
                success=completed.returncode == 0,
            )
            self._emit("completed", command, cwd, result)
            return result
        except subprocess.TimeoutExpired as exc:
            result = ExecutionResult(
                command=list(command), cwd=str(cwd), exit_code=None,
                stdout=_decode(exc.stdout), stderr=_decode(exc.stderr),
                duration_seconds=time.monotonic() - started, timed_out=True,
            )
            self._emit("completed", command, cwd, result)
            return result
        except OSError as exc:
            result = ExecutionResult.failed(list(command), str(cwd), str(exc))
            self._emit("completed", command, cwd, result)
            return result


def _decode(value: str | bytes | None) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
