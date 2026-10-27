# Case: SWC-104

- **Severity:** medium
- **Location:** `src/Case.sol:14`

## Observation
Unchecked return value from external call.
The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.

## Evidence
- mythril:SWC-104: The return value of a message call is not checked.
External calls return a boolean value. If the callee halts with an exception, 'false' is returned and execution continues in the caller. The caller should check whether an exception happened and react accordingly to avoid unexpected behavior. For example it is often desirable to wrap external calls in require() so the transaction is reverted if the call fails.

## Status
Scout candidate; no exploit or patch has been approved yet.
