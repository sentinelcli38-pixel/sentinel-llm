"""Real Forge repair checks; skipped explicitly when the local tools are absent."""

import shutil
from pathlib import Path

import pytest

from sentinel.agents.blue_team import BlueTeam
from sentinel.agents.judge import Judge
from sentinel.agents.red_team import RedTeam
from sentinel.config import settings
from sentinel.foundry.runner import FoundryRunner
from sentinel.runner import ControlledRunner
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import VulnerabilityFinding


@pytest.mark.parametrize("fixture,identifier,file", [
    ("vulnerable_reentrancy", "heuristic-reentrancy", "src/VulnerableVault.sol"),
    ("vulnerable_access_control", "heuristic-access-control", "src/VulnerableTreasury.sol"),
    ("vulnerable_tx_origin", "heuristic-tx-origin", "src/TxOriginWallet.sol"),
    ("vulnerable_unchecked_call", "heuristic-unchecked-call", "src/UncheckedCallWallet.sol"),
])
def test_real_reviewed_fixture_repair(tmp_path, monkeypatch, fixture, identifier, file):
    forge = shutil.which("forge") or str(Path.home() / ".foundry/bin/forge")
    solc = Path.home() / ".solc-select/artifacts/solc-0.8.20/solc-0.8.20"
    if not Path(forge).is_file() or not solc.is_file():
        pytest.skip("Requires installed Forge and pinned local solc 0.8.20")
    monkeypatch.setattr(settings, "solc_binary", solc)

    class OfflineRunner(ControlledRunner):
        def run(self, command, cwd, env=None):
            return super().run([forge, *command[1:], "--offline"], cwd, env)

    project = tmp_path / "project"
    shutil.copytree(Path(__file__).parents[2] / "examples" / fixture, project,
                    ignore=shutil.ignore_patterns("out", "cache"))
    original = (project / file).read_text()
    finding = VulnerabilityFinding(id=identifier, source="local-heuristic", detector="fixture", description="fixture", file=file)
    state = RuntimeState(project_path=str(project), source_files=[file], original_source={file: original}, findings=[finding], candidate_id=identifier)
    foundry = FoundryRunner(OfflineRunner())
    RedTeam(foundry).generate_and_validate(state)
    assert state.exploit_confirmed, state.exploit_result
    assert state.final_verification_state == "not_started", state.feedback
    BlueTeam().generate_and_apply(state)
    Judge(foundry).verify(state)
    assert state.judge_result.verified, state.judge_result
    assert state.final_verification_state == "verified"
    assert (Path(__file__).parents[2] / "examples" / fixture / file).read_text() == original
