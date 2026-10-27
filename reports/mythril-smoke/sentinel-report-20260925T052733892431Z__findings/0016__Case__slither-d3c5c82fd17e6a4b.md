# Case: low-level-calls

- **Severity:** informational
- **Location:** `src/Case.sol:12`

## Observation
Low level call in Proxy.proxy(address,bytes) (src/Case.sol#12-15):
	- target.call.value(msg.value)(data) (src/Case.sol#14)


## Evidence
- slither:low-level-calls: Low level call in Proxy.proxy(address,bytes) (src/Case.sol#12-15):
	- target.call.value(msg.value)(data) (src/Case.sol#14)


## Status
Scout candidate; no exploit or patch has been approved yet.
