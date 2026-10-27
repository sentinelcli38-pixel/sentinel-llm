# Case: unchecked-lowlevel

- **Severity:** medium
- **Location:** `src/Case.sol:12`

## Observation
Proxy.proxy(address,bytes) (src/Case.sol#12-15) ignores return value by target.call.value(msg.value)(data) (src/Case.sol#14)


## Evidence
- slither:unchecked-lowlevel: Proxy.proxy(address,bytes) (src/Case.sol#12-15) ignores return value by target.call.value(msg.value)(data) (src/Case.sol#14)


## Status
Scout candidate; no exploit or patch has been approved yet.
