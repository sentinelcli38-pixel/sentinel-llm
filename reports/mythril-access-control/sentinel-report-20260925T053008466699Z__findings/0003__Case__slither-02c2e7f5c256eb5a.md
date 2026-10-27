# Case: tx-origin

- **Severity:** medium
- **Location:** `src/Case.sol:18`

## Observation
Phishable.withdrawAll(address) (src/Case.sol#18-22) uses tx.origin for authorization: require(bool)(tx.origin == owner) (src/Case.sol#20)


## Evidence
- slither:tx-origin: Phishable.withdrawAll(address) (src/Case.sol#18-22) uses tx.origin for authorization: require(bool)(tx.origin == owner) (src/Case.sol#20)


## Status
Scout candidate; no exploit or patch has been approved yet.
