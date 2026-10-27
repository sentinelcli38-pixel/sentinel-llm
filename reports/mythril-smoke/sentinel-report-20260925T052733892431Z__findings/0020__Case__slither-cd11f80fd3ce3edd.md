# Case: external-function

- **Severity:** optimization
- **Location:** `src/Case.sol:12`

## Observation
proxy(address,bytes) should be declared external:
	- Proxy.proxy(address,bytes) (src/Case.sol#12-15)


## Evidence
- slither:external-function: proxy(address,bytes) should be declared external:
	- Proxy.proxy(address,bytes) (src/Case.sol#12-15)


## Status
Scout candidate; no exploit or patch has been approved yet.
