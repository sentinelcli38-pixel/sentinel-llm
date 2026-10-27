pragma solidity ^0.8.20;
import "../src/TxOriginWallet.sol";

interface Funding {
    function deal(address, uint256) external;
    function startPrank(address, address) external;
    function stopPrank() external;
}

contract FunctionalTest {
    Funding constant vm = Funding(address(uint160(uint256(keccak256("hevm cheat code")))));
    function testFunctional() public {
        address owner = address(0xB0B);
        address payable recipient = payable(address(0xBEEF));
        vm.deal(owner, 2 ether);
        vm.deal(recipient, 0);
        vm.startPrank(owner, owner);
        TxOriginWallet wallet = new TxOriginWallet{value: 2 ether}();
        wallet.withdraw(recipient);
        vm.stopPrank();
        require(wallet.owner() == owner, "incorrect owner");
        require(recipient.balance == 2 ether && address(wallet).balance == 0, "owner withdrawal broken");
    }
}
