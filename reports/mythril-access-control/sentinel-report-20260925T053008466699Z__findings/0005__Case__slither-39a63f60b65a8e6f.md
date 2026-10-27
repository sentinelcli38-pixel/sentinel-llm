# Case: missing-zero-check

- **Severity:** low
- **Location:** `src/Case.sol:12`

## Observation
Phishable.constructor(address)._owner (src/Case.sol#12) lacks a zero-check on :
		- owner = _owner (src/Case.sol#13)


## Evidence
- slither:missing-zero-check: Phishable.constructor(address)._owner (src/Case.sol#12) lacks a zero-check on :
		- owner = _owner (src/Case.sol#13)


## Status
Scout candidate; no exploit or patch has been approved yet.
