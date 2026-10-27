pragma solidity ^0.8.20;
import "../src/VulnerableTreasury.sol";

interface Funding { function deal(address, uint256) external; }

contract FunctionalTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testFunctional() public {
        vm.deal(address(this), 2 ether);
        address payable recipient = payable(address(0xBEEF));
        vm.deal(recipient, 0);
        VulnerableTreasury treasury = new VulnerableTreasury{value: 2 ether}();
        require(treasury.owner() == address(this), "incorrect owner");
        treasury.sweep(recipient);
        require(recipient.balance == 2 ether && address(treasury).balance == 0, "owner sweep broken");
    }
}
