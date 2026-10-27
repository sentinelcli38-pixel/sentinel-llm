# Inherited Execution Context

This is an experimental, opt-in scanner improvement developed after reviewing the frozen 120-case CGT replication. That set is now **development data for this implementation**. The original labels, sources, protocol, and reports remain unchanged; new measurements must not be described as independent validation of this version.

## Cause

Slither 0.11.6 serializes a function's parent as its declaring contract. Its [reentrancy implementation](https://github.com/crytic/slither/blob/master/slither/detectors/reentrancy/reentrancy.py) and rule-specific result collection walk declared functions. The older Sentinel extension also walked only declared functions. A property assessed against a derived contract could therefore miss a candidate in a genuinely inherited entry point. A finding in a sibling contract is not evidence of inheritance.

Two reviewed examples from the preserved manifest:

- `cgt-98f6229c5cfb81ea`, `SaleClockAuction`: `withdrawBalance()` is declared in `ClockAuction` and remains an inherited external entry point. The send result at line 407 is assigned but unused. Keep `ClockAuction` as the declaration and the original source line; report `SaleClockAuction` as the execution contract.
- `cgt-d00ae63c298599cc`, `SKYBITToken`: vulnerable-pattern candidates occur in inherited functions declared in `ERC777`, `MinterRole`, and other parents. The compiler-derived entry-point list, not a shared source file or a similar name, determines applicability.

Other reviewed unchecked-call positives visibly use the result: `Investment` restores a balance after a failed send; `KobyShop` restores a pending withdrawal or throws; other cases return failure, check success, or use reverting transfers. This inspection is not an independent adjudication of the entire contract. Preserve the original positive assessments and any remaining misses rather than inventing unused-return findings for those forms.

## Implementation

The `sentinel-static` analyzer now walks declared functions plus compiled, non-shadowed inherited public/external entry points for its dead-result and direct-origin checks. Slither's four existing mapped reentrancy rules also run on that expanded compiled context. A small adapter changes their function traversal, not their vulnerability rules.

Inherited reentrancy candidates use separately named detector IDs: `inherited-reentrancy-eth`, `inherited-reentrancy-no-eth`, `inherited-reentrancy-benign`, and `inherited-reentrancy-events`. They preserve the underlying rule name and confidence. Raw metadata records the declaring contract, execution contract, function signature, and `compiled-inherited-entry-point` attribution. The parser verifies coherent declaration/context metadata before attributing a candidate to the execution contract. Original source mappings and underlying call nodes remain evidence; findings are not relocated to the derived contract's declaration line.

Tests compile real Solidity sources and cover direct inheritance, deeper inheritance, separate siblings, safe entry-point overrides, diamond inheritance, an overridden internal helper that removes the external call, internal-only unused results, distinct IDs, source locations, and invalid metadata. Existing compiler-era regression tests remain in place.

This uses pinned Slither detector hooks and is not a new reentrancy algorithm, formal proof, or zero-day detector. It inherits the underlying rules' false positives and path-sensitivity limitations. It does not independently certify arbitrary inherited internal functions/modifiers, helper-call failure handling, or cross-file benchmark scope. A guarded function or an override is not automatically safe; only the compiled analysis context is used. Default scans and the vanilla Slither category mapping remain unchanged.

## Reanalysis Workflow

Freeze all source edits before preparation:

```bash
make prepare-scanner-reanalysis
make validate-scanner-reanalysis
make validate-scanner-reanalysis-static
```

The new manifest is `datasets/scanner-inheritance-development/manifest.json`. It references the original pinned projects, retains all 120 original case IDs and assessments, marks every case as development, records the original manifest hash and previous protocol, and freezes the current implementation separately. Output cannot overwrite an existing reanalysis. Mock and partial runs remain prohibited. Reports go to `reports/experiments/scanner-inheritance-development`.

The original v1 protocol correctly rejects the new working implementation. A local archived implementation at `reports/protocol-snapshots/scanner-replication-v1` matches all 65 original code-file hashes. Both the archived code and local runtime have been checked against that original protocol. To use it, run the repository's absolute `.venv/bin/python` from the archive directory, set `PYTHONPATH` to that archive directory for analyzer child processes, and pass the original manifest's absolute path. Keep the original absolute `STATIC_BINARY`, compiler paths, and 30-second timeout. The archive does not include or pin full third-party environments.

No model test data, RPC endpoint, generated exploit, or repair execution is used in this phase. Qualification failures still return exit code 2 while retaining reports. Results below are development comparisons, not a replacement for the original replication.

## Development Results

Both profiles completed all 120 cases with no case errors. The new vanilla baseline matched all original predictions. The extension detected three previously missed labelled positives, with no changed negative-case predictions:

| Measure | Vanilla Slither | Inheritance-aware extension |
| --- | ---: | ---: |
| True positives | 40 | 43 |
| False positives | 5 | 5 |
| False negatives | 20 | 17 |
| True negatives | 55 | 55 |
| Precision | 88.89% | 89.58% |
| Recall | 66.67% | 71.67% |
| F1 | 76.19% | 79.63% |

Reentrancy recall increased from 55% to 65% (11 to 13 of 20 positives); unchecked-call recall increased from 50% to 55% (10 to 11 of 20); origin-authorization recall remained 95% (19 of 20). False positives remained 4, 1, and 0 respectively. These are case/property metrics, not counts of individual warnings; additional warnings can occur in an already detected case.

The changed cases were `SKYBITToken` (`cgt-d00ae63c298599cc`), `OpenLongevityPresale` (`cgt-c1c287a9f6e075c9`), and `SaleClockAuction` (`cgt-98f6229c5cfb81ea`). The presale's inherited `Presale.fallback()` and `finishPresale()` candidates retain their base-function source mappings while naming the compiled child context.

Reports:

- Baseline: `reports/experiments/scanner-inheritance-development/sentinel-experiment-slither-20261013T134103487677Z.json`.
- Extension: `reports/experiments/scanner-inheritance-development/sentinel-experiment-sentinel-static-20261013T134704686871Z.json`.
- Shared development manifest SHA-256: `f6f57b915a9c140aa417cb02e75317f26fc84f7b226403b1891c136c8bf24955`.

Both profiles still fail qualification: reentrancy and unchecked-call recall remain below 80%. No exploitability or repair was confirmed by these candidate-only runs. Next validation requires fresh, independently assessed cases under a new frozen protocol; reusing this set cannot establish generalization. The model's reserved test data remains untouched.

The subsequent [fresh same-corpus follow-up](SCANNER_FRESH_VALIDATION.md) excludes all cases used here and keeps this implementation fixed. Its smaller positive buckets and unchanged qualification requirements remain explicit; it is not independent re-adjudication or an external benchmark.
