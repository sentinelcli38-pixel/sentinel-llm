pragma solidity ^0.8.20;
import "../src/VulnerableVault.sol";

interface Funding { function deal(address, uint256) external; }

contract FunctionalTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    receive() external payable {}
    function testFunctional() public {
        vm.deal(address(this), 3 ether);
        VulnerableVault vault = new VulnerableVault();
        vault.deposit{value: 1 ether}();
        vault.deposit{value: 2 ether}();
        require(vault.balances(address(this)) == 3 ether, "deposit accounting");
        vault.withdraw();
        require(address(this).balance == 3 ether, "legitimate withdrawal");
        require(address(vault).balance == 0 && vault.balances(address(this)) == 0, "residual funds");
    }
}
