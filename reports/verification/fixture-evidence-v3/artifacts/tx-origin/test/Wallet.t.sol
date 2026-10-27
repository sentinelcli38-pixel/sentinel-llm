pragma solidity ^0.8.20;

import "../src/TxOriginWallet.sol";

contract WalletTest {
    function testDeploy() public {
        TxOriginWallet wallet = new TxOriginWallet();
        require(wallet.owner() == address(this), "owner not set");
    }
}
