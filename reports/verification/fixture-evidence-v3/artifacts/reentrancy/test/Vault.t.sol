pragma solidity ^0.8.20;

import "../src/VulnerableVault.sol";

interface Vm {
    function deal(address account, uint256 newBalance) external;
}

contract VaultTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    VulnerableVault vault;

    function setUp() public {
        vm.deal(address(this), 1 ether);
        vault = new VulnerableVault();
    }

    receive() external payable {}

    function testDepositAndWithdraw() public {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
        require(vault.balances(address(this)) == 0, "withdraw did not clear balance");
    }
}
