pragma solidity ^0.8.20;
import "../src/TxOriginWallet.sol";

interface Funding {
    function deal(address, uint256) external;
    function startPrank(address, address) external;
    function stopPrank() external;
}

contract Intermediary {
    function attempt(TxOriginWallet wallet, address payable recipient) external {
        wallet.withdraw(recipient);
    }
}

contract SecurityTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testSecurity() public {
        address owner = address(0xB0B);
        address payable thief = payable(address(0xA11CE));
        vm.deal(owner, 1 ether);
        vm.deal(thief, 0);
        vm.startPrank(owner, owner);
        TxOriginWallet wallet = new TxOriginWallet{value: 1 ether}();
        vm.stopPrank();
        Intermediary relay = new Intermediary();
        vm.startPrank(owner, owner);
        (bool ok,) = address(relay).call(abi.encodeWithSelector(relay.attempt.selector, wallet, thief));
        vm.stopPrank();
        require(!ok, "phishing accepted");
        require(address(wallet).balance == 1 ether && thief.balance == 0, "funds changed");
        require(wallet.owner() == owner, "owner changed");
    }
}
