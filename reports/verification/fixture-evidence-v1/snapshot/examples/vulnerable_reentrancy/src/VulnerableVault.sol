pragma solidity ^0.8.20;

/// @notice Deliberately vulnerable local demonstration contract.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool sent,) = msg.sender.call{value: amount}(""); // reentrancy demo
        require(sent, "send failed");
        balances[msg.sender] = 0;
    }
}
