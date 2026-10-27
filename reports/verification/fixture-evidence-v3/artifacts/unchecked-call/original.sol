pragma solidity ^0.8.20;

/// @notice Deliberately vulnerable: failed payment clears the caller's accounting credit.
contract UncheckedCallWallet {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(address payable recipient) external {
        uint256 amount = balances[msg.sender];
        recipient.call{value: amount}(""); // unchecked low-level call
        balances[msg.sender] = 0;
    }
}
