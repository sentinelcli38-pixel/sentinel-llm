pragma solidity ^0.8.20;

import "../src/UncheckedCallWallet.sol";

contract WalletTest {
    function testDeposit() public {
        UncheckedCallWallet wallet = new UncheckedCallWallet();
        wallet.deposit();
        require(wallet.balances(address(this)) == 0, "unexpected accounting");
    }
}
