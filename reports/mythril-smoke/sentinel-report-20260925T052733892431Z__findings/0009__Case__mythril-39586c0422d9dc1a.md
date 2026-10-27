# Case: SWC-115

- **Severity:** low
- **Location:** `src/Case.sol:10`

## Observation
Dependence on tx.origin
Use of tx.origin as a part of authorization control.
The tx.origin environment variable has been found to influence a control flow decision. Note that using tx.origin as a security control might cause a situation where a user inadvertently authorizes a smart contract to perform an action on their behalf. It is recommended to use msg.sender instead.

## Evidence
- mythril:SWC-115: Use of tx.origin as a part of authorization control.
The tx.origin environment variable has been found to influence a control flow decision. Note that using tx.origin as a security control might cause a situation where a user inadvertently authorizes a smart contract to perform an action on their behalf. It is recommended to use msg.sender instead.

## Status
Scout candidate; no exploit or patch has been approved yet.
