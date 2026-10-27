import json
import os
import shutil
from pathlib import Path

import pytest

from sentinel.analyzers.call_results import analyze_project
from sentinel.analyzers.parsers import parse_sentinel_static


def test_real_slither_ssa_checks_dead_results_not_checked_returned_stored_or_transfer(tmp_path, monkeypatch):
    pytest.importorskip("slither")
    forge = shutil.which("forge") or str(Path.home() / ".foundry/bin/forge")
    compiler = Path.home() / ".solc-select/artifacts/solc-0.8.20/solc-0.8.20"
    if not Path(forge).is_file() or not compiler.is_file():
        pytest.skip("Requires Forge and installed solc 0.8.20")
    monkeypatch.setenv("PATH", f"{Path(forge).parent}:{os.environ['PATH']}")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "foundry.toml").write_text(f'[profile.default]\nsrc = "src"\nsolc = {json.dumps(str(compiler))}\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Results.sol").write_text("""pragma solidity ^0.8.20;
contract Results {
    bool stored;
    function assigned(address payable dst) external { bool success = dst.send(1); }
    function checked(address payable dst) external { bool success = dst.send(1); require(success); }
    function copied(address payable dst) external { bool success = dst.send(1); bool copy = success; require(copy); }
    function dataOnly(address dst) external returns (bytes memory) {
        (, bytes memory data) = dst.call(""); return data;
    }
    function returned(address dst) external returns (bool) { (bool success,) = dst.call(""); return success; }
    function persistent(address payable dst) external { stored = dst.send(1); }
    function transferred(address payable dst) external { dst.transfer(1); }
    function before(address payable dst) external {
        bool success = false; require(!success); success = dst.send(1);
    }
}
""")
    findings = parse_sentinel_static(json.dumps({"success": True, "results": {"detectors": analyze_project(tmp_path)}}), tmp_path)
    assert {finding.function for finding in findings} == {"assigned", "dataOnly", "before"}
    assert all(finding.contract == "Results" and finding.file == "src/Results.sol" for finding in findings)
    assert next(finding.line for finding in findings if finding.function == "assigned") == 4


@pytest.mark.parametrize("version", ["0.4.26", "0.8.20"])
def test_real_origin_guards_have_precise_attribution_and_do_not_flag_sender_guarded_paths(tmp_path, monkeypatch, version):
    pytest.importorskip("slither")
    forge = shutil.which("forge") or str(Path.home() / ".foundry/bin/forge")
    compiler = Path.home() / f".solc-select/artifacts/solc-{version}/solc-{version}"
    if not Path(forge).is_file() or not compiler.is_file():
        pytest.skip(f"Requires Forge and installed solc {version}")
    monkeypatch.setenv("PATH", f"{Path(forge).parent}:{os.environ['PATH']}")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "foundry.toml").write_text(f'[profile.default]\nsrc = "src"\nsolc = {json.dumps(str(compiler))}\n')
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Guards.sol").write_text(f"pragma solidity {version};\n" + """contract Guards {
    address owner;
    event Identity(address who);
    modifier mixed() { require(msg.sender == owner || tx.origin == owner); _; }
    function alternative() external { require(msg.sender == owner || tx.origin == owner); }
    function reversed() external { require(owner == tx.origin || owner == msg.sender); }
    function asserted() external { assert(tx.origin == owner || msg.sender == owner); }
    function originOnly() external { require(tx.origin == owner, "owner"); }
    function both() external { require(msg.sender == owner && tx.origin == owner); }
    function eoa() external { require(tx.origin == msg.sender); }
    function nestedGuarded() external {
        require((tx.origin == owner || msg.sender == owner) && tx.origin == msg.sender);
    }
    function logged() external { emit Identity(tx.origin); }
    function viaModifier() external mixed { }
    function opaque() external { require(allowed() && tx.origin == owner); }
    function allowed() internal view returns (bool) { return msg.sender == owner; }
    function aliased() external { bool ok = tx.origin == owner; require(ok); }
    function customRequire() external { pretend(tx.origin == owner); }
    function pretend(bool ok) internal pure { }
    function callerSupplied(address who) external { require(tx.origin == who || msg.sender == owner); }
    function unequal() external { require(tx.origin != owner || msg.sender != owner); }
}
contract Neighbor {
    address owner;
    function neighborOnly() external { require(tx.origin == owner || msg.sender == owner); }
}
""")
    findings = parse_sentinel_static(json.dumps({"success": True, "results": {"detectors": analyze_project(tmp_path)}}), tmp_path)
    origin = [finding for finding in findings if finding.detector == "origin-auth-alternative"]
    assert {(finding.contract, finding.function) for finding in origin} == {
        ("Guards", name) for name in ("mixed", "alternative", "reversed", "asserted", "originOnly")
    } | {("Neighbor", "neighborOnly")}
    assert all(finding.file == "src/Guards.sol" for finding in origin)
    assert next(finding.line for finding in origin if finding.function == "alternative") == 6
    assert all(json.loads(finding.raw_output)["additional_fields"]["experimental"] for finding in origin)


def test_compiled_inheritance_retains_source_and_excludes_overrides_and_siblings(tmp_path, monkeypatch):
    pytest.importorskip("slither")
    forge = shutil.which("forge") or str(Path.home() / ".foundry/bin/forge")
    compiler = Path.home() / ".solc-select/artifacts/solc-0.8.20/solc-0.8.20"
    if not Path(forge).is_file() or not compiler.is_file():
        pytest.skip("Requires Forge and installed solc 0.8.20")
    monkeypatch.setenv("PATH", f"{Path(forge).parent}:{os.environ['PATH']}")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "foundry.toml").write_text(f'[profile.default]\nsrc = "src"\nsolc = {json.dumps(str(compiler))}\n')
    (tmp_path / "src").mkdir()
    source = """pragma solidity 0.8.20;
contract Base {
    mapping(address => uint) balances;
    address owner;
    function cash(address payable dst) public virtual { bool success = dst.send(1); }
    function withdraw() public virtual {
        uint amount = balances[msg.sender];
        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success); balances[msg.sender] = 0;
    }
    function check() public virtual { require(msg.sender == owner || tx.origin == owner); }
    function internalUnused(address payable dst) internal { bool success = dst.send(1); }
}
contract Derived is Base { }
contract Deep is Derived { }
contract SafeOverride is Base {
    function cash(address payable dst) public override { require(dst.send(1)); }
    function withdraw() public override {
        uint amount = balances[msg.sender]; balances[msg.sender] = 0;
        (bool success,) = payable(msg.sender).call{value: amount}(""); require(success);
    }
    function check() public override { require(msg.sender == owner); }
}
contract OtherBase {
    function cash(address payable dst) public virtual { require(dst.send(1)); }
    function withdraw() public virtual { }
    function check() public virtual { }
}
contract Diamond is Base, OtherBase {
    function cash(address payable dst) public override(Base, OtherBase) { OtherBase.cash(dst); }
    function withdraw() public override(Base, OtherBase) { OtherBase.withdraw(); }
    function check() public override(Base, OtherBase) { OtherBase.check(); }
}
contract Sibling {
    function cash(address payable dst) public { require(dst.send(1)); }
}
contract HelperBase {
    mapping(address => uint) balances;
    function forwarded() public { pay(); balances[msg.sender] = 0; }
    function pay() internal virtual {
        (bool success,) = payable(msg.sender).call{value: balances[msg.sender]}(""); require(success);
    }
}
contract HelperChild is HelperBase { }
contract NoPayOverride is HelperBase {
    function pay() internal override { }
}
"""
    (tmp_path / "src/Inheritance.sol").write_text(source)
    findings = parse_sentinel_static(json.dumps({"success": True, "results": {"detectors": analyze_project(tmp_path)}}), tmp_path)
    assert {finding.contract for finding in findings} == {"Base", "Derived", "Deep", "HelperChild"}
    assert all(finding.function == "forwarded" for finding in findings if finding.contract == "HelperChild")
    for context in ("Derived", "Deep"):
        inherited = [finding for finding in findings if finding.contract == context]
        assert {finding.function for finding in inherited} == {"cash", "withdraw", "check"}
        assert any(finding.detector == "inherited-reentrancy-eth" for finding in inherited)
        assert all(finding.file == "src/Inheritance.sol" for finding in inherited)
        for finding in inherited:
            raw = json.loads(finding.raw_output)
            assert raw["additional_fields"]["declaring_contract"] == "Base"
            assert raw["additional_fields"]["execution_contract"] == context
            assert "Execution contract" in finding.description
        cash = next(finding for finding in inherited if finding.function == "cash")
        assert cash.line == 5
    assert len({finding.id for finding in findings}) == len(findings)
