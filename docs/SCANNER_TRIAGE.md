# Scanner Discrepancy Review

Reviewed locally on October 13, 2026. These observations guide development; they do not replace the original CGT assessments or establish a contract's overall safety.

## Matthew: Stored But Unused Send Results

- Frozen pilot case: `cgt-a9d0ab78f7476a0e`, SWC-104, positive.
- Assessed contract: `Matthew`.
- Source: [pinned CGT contract](https://github.com/gsalzer/cgt/blob/f8cd72cf7fbbfebc809c454667eee271706a4b2b/source/e21708560a41c4e69248853021afb37f.sol).
- Calls: `whale.send(stake - nextStake)` at line 40 and `msg.sender.send(stake)` at line 48.
- The returned Boolean is assigned to a local variable. Neither post-call value is consumed. The earlier read of `isSuccess` precedes the call, so it cannot check the outcome of that call.
- Slither's [unused-return implementation](https://github.com/crytic/slither/blob/master/slither/detectors/operations/unused_return_values.py) treats assignment as a read of the intermediate result. Its [unchecked-send detector](https://github.com/crytic/slither/blob/master/slither/detectors/operations/unchecked_send_return_value.py) inherits that behavior. This was also checked against the locally installed 0.11.6 code. The installed baseline reports no matching unchecked-send finding for this case.

Resolution: add an **experimental, opt-in** `sentinel-static` analyzer using Slither SSA objects. It follows copies of success results through local assignments, tuple unpacking, and phi merges. A non-copy use, including returning, logging, storing, or passing a result elsewhere, suppresses this narrow check. SSA separates reads of an earlier value from reads of the call result. Reading a low-level call's returned data does not count as using its success Boolean.

Both calls now produce candidate findings with contract, function, source file, and call-site line. This establishes a static-analysis signal, not exploitation or verified repair. There is no generated exploit execution in this experiment.

## EthMultiplier: Assessment/Definition Discrepancy

- Frozen pilot case: `cgt-e1ea0252dc27e7dd`, SWC-104, positive.
- Assessed contract: `EthMultiplier`.
- Source: [pinned CGT contract](https://github.com/gsalzer/cgt/blob/f8cd72cf7fbbfebc809c454667eee271706a4b2b/source/e0c5c509220781adbf325c43b27f4eed.sol).
- CGT preserves a Zeus `Unchkd_send` positive assessment.
- Inspection of this source finds Ether transfers using `transfer()`, not Boolean-returning `send()` or low-level calls.
- For this compiler era, the [Solidity 0.4.24 documentation](https://docs.soliditylang.org/en/v0.4.24/units-and-global-variables.html#address-related) specifies that `transfer()` throws on failure, while `send()` returns a Boolean.

Resolution: retain the positive label and the miss in all metrics. Do **not** manufacture an unchecked-return warning for `transfer()`, remove the case to improve recall, or count unrelated Slither warnings as SWC-104 detections. This is a candidate assessment/definition discrepancy requiring independent review, not a confirmed dataset error. Other weaknesses may still be present.

## Experimental Boundary

The dead-result checker is not a complete failure-handling analysis. It may miss results used in irrelevant arithmetic or insufficient conditional checks because all non-copy uses conservatively suppress its warning. It does not prove path-sensitive handling, inspect consumers across calls, certify inherited-contract attribution, or detect zero days. It must remain separately named and opt-in until broader evidence justifies promotion.

The code is `sentinel/analyzers/call_results.py`. Its source hash and Slither version are included in raw analyzer output. Reports preserve the `sentinel-static` provenance separately from vanilla Slither. The standard profile and default scan configuration remain unchanged.

The later [inherited execution-context extension](SCANNER_INHERITANCE.md) addresses a narrow attribution gap using compiled inherited entry points. It does not reassign sibling warnings or certify all inheritance/call-graph behavior. Earlier frozen results and their implementation boundaries remain separately recorded.

## UnicornManagement: Mixed Authorization Alternative

- Expanded case: `cgt-bcaafb19bcd32ee5`, SWC-115, positive.
- Source: [pinned CGT contract](https://github.com/gsalzer/cgt/blob/f8cd72cf7fbbfebc809c454667eee271706a4b2b/source/8a49841965d7f5828e0266ef3b2bd72a.sol).
- `registerInit`, line 141: `require(msg.sender == ownerAddress || tx.origin == ownerAddress)`.
- The installed Slither 0.11.6 [tx-origin check](https://github.com/crytic/slither/blob/master/slither/detectors/statements/tx_origin.py) excludes a conditional node whenever it also reads `msg.sender`. This suppresses an independent origin-based authorization alternative, not just the intended `tx.origin == msg.sender` exception.

Resolution: the experimental `origin-auth-alternative` check walks Slither's Boolean expression objects for direct `require`/`assert` guards. It summarizes `&&` and `||` over equalities between `msg.sender`/`tx.origin` and address state variables. An origin-based alternative with no sender-equality requirement produces a candidate. Reversed equalities and modifier declarations are supported. Direct `tx.origin == msg.sender` checks and guards requiring both identities do not produce this candidate.

This is a deliberately narrow structural check. Any unknown operand makes that entire guard unsupported. It does not follow local aliases, helper functions, negation, inequality, custom errors, inline assembly, prior guards, or branch feasibility. An address state variable is a possible authority, not proof of a privilege boundary. It can warn even if another guard makes the branch unreachable or otherwise protects it. Modifier findings stay attributed to their declaration; they are not reassigned to every caller or derived contract. Absence of a warning is not a safety verdict.

Regression tests compile real sources with Solidity 0.4.26 and 0.8.20. They cover OR, AND, nested sender guards, reversed comparisons, modifiers, assertion guards, logs, caller-supplied addresses, opaque helper calls, aliases, and separate neighboring contracts. No attack transaction is generated or executed.

## Other Origin Misses: Preserve the Assessment Boundary

- `cgt-6190f9e27d2d23e9`, `apexSolids`: its `notContract` modifier uses `require(tx.origin == msg.sender)` at line 54. This is a direct-caller restriction, not equality against a stored privileged address. Slither deliberately excludes this form, and the extension does too. The original Doublade positive assessment and the miss remain in the metrics; this is a weakness-definition discrepancy for independent review, not a confirmed label error.
- `cgt-1c30fe17b663edd2`, `Escrow`: the origin check is in `Tokens.refundTokens`, line 542, and Slither attributes it to `Tokens`. `Escrow` inherits `System` and `HardcodedWallets`, not `Tokens`; holding a `Tokens` reference does not establish that its function belongs to `Escrow`. Do not count this sibling-contract warning as a target-contract detection. The positive label and miss remain.

## Reentrancy Review: Do Not Silently Clear Alerts

- Miss `cgt-a4a65d1d6cacf27f`, `DSExec`: the assessed contract contains internal call wrappers, including a returned low-level success result and a reverting caller, without the post-call state update pattern reported elsewhere in the file. Slither's matching warnings belong to `DSAuth`, `DSStop`, and `DSToken`, not `DSExec`. Preserve the target-specific miss pending independent label/scope review.
- False positive relative to its label, `cgt-b8361d1efc1ea9f9`, `SharkPool`: Slither reports external interactions before state changes in mining/redemption paths. Several external entry points use a state-lock `nonReentrant` modifier, but the payable fallback does not. A guarded function name or a fixed external contract address alone is insufficient grounds to clear all reports. Review requires cross-function reachability and the dependency implementation; this phase does not prove safety or exploitability.
- False positive relative to its label, `cgt-39f5e2095cd25ae4`, `Moongang`: matching findings are `reentrancy-benign`, involving `token.balanceOf` before accounting updates in withdrawals. The [Slither detector documentation](https://github.com/crytic/slither/wiki/Detector-Documentation) distinguishes benign double-call behavior from Ether/non-Ether impact checks. The existing benchmark maps benign candidates to the broad reentrancy property. This difference in definitions is recorded, not silently fixed by narrowing the mapping after observing the labels. External token behavior and compiler-era execution semantics still need review.

Both negative assessments and all raw warnings are retained. No reentrancy findings are suppressed, no source hashes or labels are changed, and no alternative accuracy score is substituted for the preserved baseline.
