import json
import shutil
from pathlib import Path

import pytest

from sentinel.agents.blue_team import BlueTeam
from sentinel.agents.red_team import RedTeam
from sentinel.schemas.execution import ExecutionResult
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import VulnerabilityFinding


def forge_result(file: str, name: str, status: str = "Success") -> ExecutionResult:
    code = 0 if status == "Success" else 1
    return ExecutionResult(command=["forge", "test", "--json"], cwd="/tmp", exit_code=code, success=code == 0,
                           stdout=json.dumps({f"{file}:Test": {"test_results": {f"{name}()": {"status": status}}}}))


@pytest.fixture
def repair_foundry():
    class Foundry:
        exploit_status = "Success"
        exploit_override = None
        regression_override = None

        def build(self, project):
            return ExecutionResult(command=["forge", "build"], cwd=str(project), exit_code=0, success=True)

        def exploit(self, project, *, test_file):
            return self.exploit_override or forge_result(test_file, "testExploit", self.exploit_status)

        def regression(self, project):
            return self.regression_override or forge_result("test/Vault.t.sol", "testDepositAndWithdraw")

        def named_test(self, project, name):
            return forge_result("test/Vault.t.sol", name)

    return Foundry()


@pytest.fixture
def repair_state(tmp_path, repair_foundry):
    project = tmp_path / "project"
    shutil.copytree(Path(__file__).parent.parent / "examples/vulnerable_reentrancy", project)
    file = "src/VulnerableVault.sol"
    finding = VulnerabilityFinding(id="heuristic-reentrancy", source="local-heuristic", detector="fixture", description="fixture", file=file)
    state = RuntimeState(project_path=str(project), candidate_id=finding.id, findings=[finding],
                         original_source={file: (project / file).read_text()}, source_files=[file])
    RedTeam(repair_foundry).generate_and_validate(state)
    assert state.exploit_confirmed
    BlueTeam().generate_and_apply(state)
    repair_foundry.exploit_status = "Failure"
    return state
