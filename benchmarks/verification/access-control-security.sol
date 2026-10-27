pragma solidity ^0.8.20;
import "../src/VulnerableTreasury.sol";

interface Funding { function deal(address, uint256) external; function prank(address) external; }

contract SecurityTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testSecurity() public {
        vm.deal(address(this), 1 ether);
        address payable thief = payable(address(0xA11CE));
        vm.deal(thief, 0);
        VulnerableTreasury treasury = new VulnerableTreasury{value: 1 ether}();
        vm.prank(thief);
        (bool ok,) = address(treasury).call(abi.encodeWithSelector(treasury.sweep.selector, thief));
        require(!ok, "unauthorized sweep accepted");
        require(address(treasury).balance == 1 ether && thief.balance == 0, "funds changed");
        require(treasury.owner() == address(this), "owner changed");
    }
}
