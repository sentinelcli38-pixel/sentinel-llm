# Case: SWC-105

- **Severity:** high
- **Location:** `src/Case.sol:21`

## Observation
Unprotected Ether Withdrawal
Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.

## Evidence
- mythril:SWC-105: Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether from the contract account. Verify the business logic carefully and make sure that appropriate security controls are in place to prevent unexpected loss of funds.

## Status
Scout candidate; no exploit or patch has been approved yet.
