# Verification-First Evidence Audit

## Purpose

The held-out kernel experiment did not meet the unchanged 99% precision / 80%
recall targets. This stage checks the executable evidence workflow before
attempting broader candidate confirmation. It does not train a model, change a
detector, relabel the validation set, or read the reserved model test split.

The cohort is the four existing, deliberately vulnerable local demonstrations:
reentrancy, missing authorization, `tx.origin` authorization, and unchecked calls.
Their PoC and repair templates were already part of Sentinel. They are familiar
engineering fixtures, not independent discoveries or representative gold data.
The new assertions are software tests, not replacement expert annotations.

## Checks

For every fixture the runner copies only Solidity/configuration inputs to a
temporary workspace and adds a nonzero-value functional test. It then:

1. Executes the existing fixture-specific exploit and requires passing,
   nonempty baseline regression tests.
2. Applies the existing fixture repair, without changing the user's project.
3. Requires Judge to reject five deliberately invalid variants: an unchanged
   source, altered exploit oracle, missing baseline regressions, an empty
   regression result, and an uncompilable repair. Rejection must have the
   expected reason, not merely a false `verified` field. The empty-result
   variant is explicitly synthetic result injection, not a real Forge run.
4. Runs the real build, unchanged exploit oracle and identical regression-test
   inventory through Judge. It separately checks the meaningful functional test.
5. Runs exactly the same additional security test against the original and
   repaired source. The original must have one executed failing test; the repair
   must pass that same test. Compilation errors, absent tests, setup failures,
   skipped tests and timeouts do not qualify as an executed failing oracle.

The security tests check preserved victim funds and balances for reentrancy,
rejection of unauthorized sweeps/phishing, and restored accounting credit after
failed payment. Functional tests require successful authorized transfers and
correct nonzero deposit/withdrawal accounting. They improve these particular
fixtures' coverage; they are not formal proofs or exhaustive invariants.

The new security suite is separate from Judge's passing-regression oracle. It is
added only after Judge finishes; its before/after results are independent audit
checks, not retroactively inserted baseline evidence.

## Reproduce

Requires local Forge and solc 0.8.20; no tools are downloaded automatically.

```bash
make test-verification-audit
make verification-audit VERIFICATION_AUDIT_OUTPUT=reports/verification/my-new-run
```

Optionally retain the saved external pilot's unresolved findings in the report:

```bash
make verification-audit \
  VERIFICATION_AUDIT_OUTPUT=reports/verification/my-new-external-context-run \
  VERIFICATION_EXTERNAL_REPORT=reports/experiments/external-forge-curated-v3/sentinel-experiment-sentinel-static-20261014T041629048651Z.json
```

`FOUNDRY_BIN` and `SCANNER_SOLC_CURRENT` override installed executable paths.
Existing output directories are refused. Exit 0 means the engineering audit
passed; exit 2 means an audit gate failed. Neither means 99% precision.

The subprocess environment is restricted to a temporary HOME, system PATH and
two thread/warning settings. Inherited RPC, wallet, FFI and Foundry overrides
are not forwarded. Only pinned compiler versions and narrow Forge build/test
selectors are permitted; commands add `--offline --threads 1`. There is no
provider invocation, RPC target, fork, deployment, dependency install or live
chain transaction. This is not an OS sandbox for arbitrary untrusted projects;
the harness accepts its fixed repository-owned fixture cohort only.

## Evidence And Limits

Each output includes a pre-run protocol, SHA-256 pins and source snapshots,
raw command results, per-case results, original/repaired source and diffs, and
an aggregate report. Sources and tools must remain unchanged through the run.
All four planned cases and all 20 planned controls remain in the denominators;
an error is not removed to make the audit pass.

`precision` and `recall` are deliberately null, `precision_target_met` is false,
and no model/detector is promoted. This cohort does not exercise false-positive
classification on an independently labeled population. Passing 4/4 fixtures or
20/20 rejection controls cannot establish 99% detector precision.

When external context is supplied, the two OracleLess/DepositPool records retain
their unknown ground truth, all 28 target-matched candidate IDs, and their
unmatched-finding counts. They are **not attempted** by this fixture audit and
are not silently counted as safe or confirmed. Target-specific human-reviewed
oracles and independent labels remain necessary before evaluating confirmation
accuracy on those projects.

### Saved Attempts

- `reports/verification/fixture-evidence-v1`: failed harness attempt. Baseline
  Forge runs executed, but macOS `/var` versus `/private/var` path spelling broke
  control workspace attribution. All four cases were retained as failures.
- `reports/verification/fixture-evidence-v2`: path-normalized intermediate run;
  four fixture audits passed and 20 controls were rejected.
- `reports/verification/fixture-evidence-v3`: hardened runner and expected-reason
  checks: **4/4 fixture audits passed, 20/20 expected control rejections**.
  The 38 raw commands and 88 input snapshot files were checked, including all
  65 unchanged frozen scanner files. Each security test failed on the original
  with its intended invariant failure reason and passed on the repair.
  Precision/recall remain null, and all 28 external target-matched candidates
  remain unverified. Earlier snapshots and results are retained unchanged.

After this stage, the full Python suite passed 598 tests with 20 optional
runtime tests skipped in the main environment. Those 20 tests passed separately
in the MLX environment; all 19 Node frontend/AST tests also passed. This is
software test coverage, not vulnerability-detection performance.

The next research stage needs target-specific buildable external cases,
vulnerability/fix pairs, negative controls, and source-pinned review decisions.
Freeze candidate confirmation rules before using a fresh evaluation cohort;
report precision, recall and unresolved coverage together. The current small
unknown-label external pilot cannot support that statistical claim.
