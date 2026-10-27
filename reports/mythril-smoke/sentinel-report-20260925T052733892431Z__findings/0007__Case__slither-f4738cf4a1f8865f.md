# Case: missing-zero-check

- **Severity:** low
- **Location:** `src/Case.sol:11`

## Observation
Proxy.transferOwner(address)._owner (src/Case.sol#11) lacks a zero-check on :
		- Owner = _owner (src/Case.sol#11)


## Evidence
- slither:missing-zero-check: Proxy.transferOwner(address)._owner (src/Case.sol#11) lacks a zero-check on :
		- Owner = _owner (src/Case.sol#11)


## Status
Scout candidate; no exploit or patch has been approved yet.
