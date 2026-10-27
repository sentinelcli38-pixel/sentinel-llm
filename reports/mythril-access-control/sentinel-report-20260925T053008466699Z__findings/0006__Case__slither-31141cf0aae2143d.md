# Case: missing-zero-check

- **Severity:** low
- **Location:** `src/Case.sol:18`

## Observation
Phishable.withdrawAll(address)._recipient (src/Case.sol#18) lacks a zero-check on :
		- _recipient.transfer(this.balance) (src/Case.sol#21)


## Evidence
- slither:missing-zero-check: Phishable.withdrawAll(address)._recipient (src/Case.sol#18) lacks a zero-check on :
		- _recipient.transfer(this.balance) (src/Case.sol#21)


## Status
Scout candidate; no exploit or patch has been approved yet.
