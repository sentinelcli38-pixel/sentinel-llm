# Case: events-access

- **Severity:** low
- **Location:** `src/Case.sol:11`

## Observation
Proxy.transferOwner(address) (src/Case.sol#11) should emit an event for: 
	- Owner = _owner (src/Case.sol#11) 


## Evidence
- slither:events-access: Proxy.transferOwner(address) (src/Case.sol#11) should emit an event for: 
	- Owner = _owner (src/Case.sol#11) 


## Status
Scout candidate; no exploit or patch has been approved yet.
