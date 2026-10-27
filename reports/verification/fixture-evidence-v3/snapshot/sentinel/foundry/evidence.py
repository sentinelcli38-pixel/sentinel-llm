"""Fail-closed evidence from Forge's JSON test output, not its exit code alone."""

import hashlib
import json
from pathlib import Path

from sentinel.schemas.execution import ExecutionResult


def oracle_hashes(project: Path, source_files: set[str]) -> dict[str, str]:
    return {
        path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in project.rglob("*.sol")
        if path.relative_to(project).as_posix() not in source_files
        and not {"out", "cache", ".git"}.intersection(path.relative_to(project).parts)
    }


def test_results(result: ExecutionResult | None) -> dict[str, str]:
    if result is None or result.timed_out or result.exit_code not in {0, 1}:
        return {}
    try:
        suites = json.loads(result.stdout)
        if not isinstance(suites, dict):
            return {}
        tests = {}
        for suite, value in suites.items():
            if not isinstance(value, dict) or not isinstance(value.get("test_results"), dict):
                return {}
            for name, test in value["test_results"].items():
                if not isinstance(test, dict) or test.get("status") not in {"Success", "Failure", "Skipped"}:
                    return {}
                # A failed setup is not an executed exploit or regression test.
                if not name.startswith("test"):
                    return {}
                tests[f"{suite}::{name}"] = test["status"]
        return tests
    except (ValueError, TypeError, AttributeError):
        return {}


def passed(result: ExecutionResult | None, name: str | None = None) -> bool:
    tests = test_results(result)
    return bool(
        result and result.exit_code == 0 and tests
        and all(status == "Success" for status in tests.values())
        and (name is None or all(key.rsplit("::", 1)[1].split("(", 1)[0] == name for key in tests))
    )


def exploit_tests(result: ExecutionResult | None, test_file: str, name: str) -> dict[str, str]:
    tests = test_results(result)
    for key in tests:
        suite, signature = key.rsplit("::", 1)
        file = suite.rsplit(":", 1)[0]
        if Path(file).as_posix() != Path(test_file).as_posix() or signature != f"{name}()":
            return {}
    return tests if len(tests) == 1 else {}


def neutralized(before: ExecutionResult | None, after: ExecutionResult, test_file: str, name: str) -> bool:
    baseline = exploit_tests(before, test_file, name)
    current = exploit_tests(after, test_file, name)
    return bool(
        passed(before, name) and baseline and baseline.keys() == current.keys()
        and after.exit_code == 1 and all(status == "Failure" for status in current.values())
    )


def regressions_preserved(before: ExecutionResult | None, after: ExecutionResult) -> bool:
    return passed(before) and passed(after) and test_results(before).keys() == test_results(after).keys()
