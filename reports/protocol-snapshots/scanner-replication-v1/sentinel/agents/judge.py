from pathlib import Path

from sentinel.agents.red_team import RedTeam
from sentinel.foundry.evidence import (
    neutralized,
    oracle_hashes,
    passed,
    regressions_preserved,
)
from sentinel.foundry.runner import FoundryRunner
from sentinel.schemas.execution import JudgeResult
from sentinel.schemas.state import RuntimeState
from sentinel.validation import (
    declared_public_api,
    declared_storage,
    load_validation_profile,
)


class Judge:
    """Layer 4: deterministic build, exploit-defense, and regression gate."""

    def __init__(self, foundry: FoundryRunner) -> None:
        self.foundry = foundry

    def verify(self, state: RuntimeState) -> RuntimeState:
        project = Path(state.workspace_path or state.project_path)
        try:
            profile = load_validation_profile(project)
        except (TypeError, ValueError) as exc:
            state.judge_result = JudgeResult(failure_reason="invalid validation profile", feedback=str(exc))
            state.final_verification_state = "human_review_required"
            return state
        artifact = state.exploit_artifact
        try:
            test_file = Path(artifact.test_file).resolve().relative_to(project.resolve()).as_posix() if artifact else ""
            finding = next((item for item in state.findings if item.id == state.candidate_id), None)
            reviewed_source = RedTeam._fixture_test(finding.id, finding.file) if finding else None
            valid_oracle = bool(
                artifact and artifact.origin == "reviewed_fixture" and artifact.source == reviewed_source
                and artifact.vulnerability_id == state.candidate_id
                and (project / test_file).read_text(encoding="utf-8") == artifact.source
                and state.oracle_test_hashes
                and oracle_hashes(project, set(state.original_source)) == state.oracle_test_hashes
            )
            valid_patch = bool(
                state.patch_diff and state.patched_source
                and set(state.patched_source) <= set(state.original_source)
                and any(source != state.original_source[file] for file, source in state.patched_source.items())
                and all((project / file).resolve().is_relative_to(project.resolve())
                        and (project / file).read_text(encoding="utf-8") == source
                        for file, source in {**state.original_source, **state.patched_source}.items())
            )
        except (OSError, ValueError):
            valid_oracle = valid_patch = False
        if not (state.exploit_confirmed and valid_oracle and valid_patch
                and passed(state.baseline_exploit_result, "testExploit")
                and passed(state.baseline_regression_result)):
            state.judge_result = JudgeResult(failure_reason="missing or changed baseline evidence", feedback="A reviewed, unchanged exploit oracle, confirmed baseline, nonempty passing regression suite, and actual source patch are required.")
            state.final_verification_state = "human_review_required"
            return state
        build = self.foundry.build(project)
        state.compilation_result = build
        if build.exit_code != 0 or build.timed_out or not build.success:
            reason = "forge build failed"
            state.judge_result = JudgeResult(failure_reason=reason, feedback=build.stderr or build.stdout)
            state.feedback.append(state.judge_result.feedback)
            state.final_verification_state = "retry_required"
            return state
        exploit = self.foundry.exploit(project, test_file=test_file)
        state.exploit_result = exploit
        exploit_neutralized = neutralized(state.baseline_exploit_result, exploit, test_file, artifact.test_name)
        regression = self.foundry.regression(project)
        state.regression_result = regression
        positive_runs = [self.foundry.named_test(project, name) for name in profile.positive_tests]
        security_runs = [self.foundry.named_test(project, name) for name in profile.security_tests]
        regression_passed = regressions_preserved(state.baseline_regression_result, regression)
        positive_passed = all(passed(run, name) for name, run in zip(profile.positive_tests, positive_runs, strict=True)) if positive_runs else None
        security_passed = all(passed(run, name) for name, run in zip(profile.security_tests, security_runs, strict=True)) if security_runs else None
        patched = {**state.original_source, **state.patched_source}
        abi_compatible = declared_public_api(state.original_source) == declared_public_api(patched) if profile.require_abi_compatibility else None
        storage_compatible = declared_storage(state.original_source) == declared_storage(patched) if profile.require_storage_declaration_compatibility else None
        additional_checks = [
            *[f"positive:{name}:{'passed' if passed(run, name) else 'failed'}" for name, run in zip(profile.positive_tests, positive_runs, strict=True)],
            *[f"security:{name}:{'passed' if passed(run, name) else 'failed'}" for name, run in zip(profile.security_tests, security_runs, strict=True)],
            *([f"declared-abi:{'passed' if abi_compatible else 'failed'}"] if abi_compatible is not None else []),
            *([f"declared-storage:{'passed' if storage_compatible else 'failed'}"] if storage_compatible is not None else []),
        ]
        extra_passed = all(value is not False for value in (positive_passed, security_passed, abi_compatible, storage_compatible))
        state.judge_result = JudgeResult(
            evidence_version=1,
            build_passed=True, exploit_neutralized=exploit_neutralized,
            regression_passed=regression_passed, positive_tests_passed=positive_passed,
            security_tests_passed=security_passed, abi_compatible=abi_compatible,
            storage_layout_compatible=storage_compatible, additional_checks=additional_checks,
            verified=exploit_neutralized and regression_passed and extra_passed,
            failure_reason="" if exploit_neutralized and regression_passed and extra_passed else "Exploit, regression, or configured validation gate failed",
            feedback=(exploit.stderr or exploit.stdout or "") + (regression.stderr or regression.stdout or "") + "\n".join(run.stderr or run.stdout for run in [*positive_runs, *security_runs]),
        )
        state.final_verification_state = "verified" if state.judge_result.verified else "retry_required"
        return state
