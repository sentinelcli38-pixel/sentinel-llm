pragma solidity ^0.8.20;
import "../src/UncheckedCallWallet.sol";

interface Funding { function deal(address, uint256) external; }

contract FunctionalTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testFunctional() public {
        vm.deal(address(this), 3 ether);
        address payable recipient = payable(address(0xBEEF));
        vm.deal(recipient, 0);
        UncheckedCallWallet wallet = new UncheckedCallWallet();
        wallet.deposit{value: 1 ether}();
        wallet.deposit{value: 2 ether}();
        require(wallet.balances(address(this)) == 3 ether, "deposit accounting");
        wallet.withdraw(recipient);
        require(recipient.balance == 3 ether && address(wallet).balance == 0, "successful payout broken");
        require(wallet.balances(address(this)) == 0, "credit not cleared");
    }
}
