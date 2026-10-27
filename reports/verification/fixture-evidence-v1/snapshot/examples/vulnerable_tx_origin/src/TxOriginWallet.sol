pragma solidity ^0.8.20;

/// @notice Deliberately vulnerable: tx.origin permits phishing through an intermediary contract.
contract TxOriginWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function withdraw(address payable recipient) external {
        require(tx.origin == owner, "not owner");
        recipient.transfer(address(this).balance);
    }
}
