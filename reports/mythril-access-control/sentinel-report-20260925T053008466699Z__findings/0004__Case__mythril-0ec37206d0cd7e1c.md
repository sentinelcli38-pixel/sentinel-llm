# Case: SWC-114

- **Severity:** medium
- **Location:** `src/Case.sol:21`

## Observation
Transaction Order Dependence
The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call

## Evidence
- mythril:SWC-114: The value of the call is dependent on balance or storage write
This can lead to race conditions. An attacker may be able to run a transaction after our transaction which can change the value of the call

## Status
Scout candidate; no exploit or patch has been approved yet.
