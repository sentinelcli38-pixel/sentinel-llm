pragma solidity ^0.8.20;

/// @notice Deliberately vulnerable local access-control demonstration.
contract VulnerableTreasury {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function sweep(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }
}
