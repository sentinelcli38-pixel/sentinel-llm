pragma solidity ^0.8.20;
import "../src/UncheckedCallWallet.sol";

interface Funding { function deal(address, uint256) external; }

contract RejectingReceiver { receive() external payable { revert("reject payment"); } }

contract SecurityTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testSecurity() public {
        vm.deal(address(this), 1 ether);
        UncheckedCallWallet wallet = new UncheckedCallWallet();
        RejectingReceiver recipient = new RejectingReceiver();
        wallet.deposit{value: 1 ether}();
        (bool ok,) = address(wallet).call(abi.encodeWithSelector(wallet.withdraw.selector, payable(address(recipient))));
        require(!ok, "failed payout accepted");
        require(wallet.balances(address(this)) == 1 ether, "credit lost");
        require(address(wallet).balance == 1 ether && address(recipient).balance == 0, "funds changed");
    }
}
