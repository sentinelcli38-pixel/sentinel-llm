pragma solidity ^0.8.20;

import "../src/VulnerableTreasury.sol";

contract TreasuryTest {
    VulnerableTreasury treasury;

    function setUp() public {
        treasury = new VulnerableTreasury{value: 1 ether}();
    }

    function testOwnerIsRecorded() public {
        require(treasury.owner() == address(this), "owner was not recorded");
    }
}
