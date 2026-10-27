from pathlib import Path

from sentinel.agents.judge import Judge
from sentinel.validation import ValidationProfile, declared_public_api, declared_storage


def test_declared_compatibility_fingerprints_detect_surface_changes() -> None:
    original = {"src/Vault.sol": "contract Vault { uint256 balance; function withdraw(uint256 amount) external {} }"}
    changed_api = {"src/Vault.sol": "contract Vault { uint256 balance; function withdraw(address to) external {} }"}
    changed_storage = {"src/Vault.sol": "contract Vault { address owner; function withdraw(uint256 amount) external {} }"}

    assert declared_public_api(original) != declared_public_api(changed_api)
    assert declared_storage(original) != declared_storage(changed_storage)


def test_validation_profile_rejects_non_identifier_test_selectors() -> None:
    try:
        ValidationProfile(positive_tests=["testGood; forge build"])
    except ValueError as exc:
        assert "test selectors" in str(exc)
    else:
        raise AssertionError("Unsafe test selector must be rejected")


def test_judge_rejects_patch_that_breaks_required_declared_abi(repair_state, repair_foundry) -> None:
    project = Path(repair_state.project_path)
    (project / "sentinel-validation.yml").write_text("require_abi_compatibility: true\n")
    file = "src/VulnerableVault.sol"
    repair_state.patched_source[file] = repair_state.patched_source[file].replace("function withdraw()", "function withdraw(uint256 amount)")
    (project / file).write_text(repair_state.patched_source[file])
    state = Judge(repair_foundry).verify(repair_state)

    assert state.judge_result is not None
    assert state.judge_result.abi_compatible is False
    assert not state.judge_result.verified
