pragma solidity ^0.8.20;
import "../src/VulnerableVault.sol";

interface Funding { function deal(address, uint256) external; }

contract ReentrantReceiver {
    VulnerableVault immutable vault;
    bool entered;
    constructor(VulnerableVault target) { vault = target; }
    function attempt() external payable { vault.deposit{value: msg.value}(); vault.withdraw(); }
    receive() external payable {
        if (!entered && address(vault).balance >= 1 ether) { entered = true; vault.withdraw(); }
    }
}

contract SecurityTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testSecurity() public {
        vm.deal(address(this), 2 ether);
        VulnerableVault vault = new VulnerableVault();
        vault.deposit{value: 1 ether}();
        ReentrantReceiver receiver = new ReentrantReceiver(vault);
        receiver.attempt{value: 1 ether}();
        require(address(vault).balance == 1 ether, "victim funds stolen");
        require(vault.balances(address(this)) == 1 ether, "victim accounting changed");
        require(address(receiver).balance == 1 ether, "receiver overpaid");
    }
}
