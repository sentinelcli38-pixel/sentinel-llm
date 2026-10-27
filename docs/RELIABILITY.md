# Reliability Boundaries

Sentinel is a local research and developer-assistance tool, not a certified smart-contract auditor. These safeguards prevent unsupported success claims; they do not establish general detection accuracy or zero-day coverage.

## Evidence Required for Repair Verification

- A reviewed fixture oracle must execute exactly one selected `testExploit()` in its own test file and pass on the original source.
- A nonempty regression suite must pass before patching. Canonical `testExploit` methods are excluded from that suite, including legacy fixture PoCs.
- The generated exploit and other non-source Solidity files are fingerprinted. Changed or removed test files invalidate verification.
- The patch must change an existing source file, be recorded, and match the patched files on disk.
- Forge must build the patched copy. Its JSON must show the same selected exploit actually executed and failed; compiler errors, setup failures, timeouts, missing tools, malformed output, skips, and zero selected tests are inconclusive.
- The same regression test identities must execute and pass afterward. Configured positive and security tests must also execute matching methods and pass.
- Optional ABI/storage checks are source-declaration comparisons, not compiler layout or upgrade-safety proofs.

`verified` covers this proposed patch and these tests only. It does not imply complete scanner coverage, all possible exploit paths blocked, or a safe deployment. The input project is not modified by `run_scan`.

New Judge results carry `evidence_version: 1`. Archived reports using earlier exit-code-only checks are not retroactively qualified: the dashboard marks their verification as legacy and requires a rescan.

## Models and Candidate Review

Model-generated PoCs are saved as **unexecuted review drafts**, never auto-confirmed. Generic scanner candidates therefore stop at human review unless a reviewed oracle is available. A failed PoC cannot establish that a scanner warning was false.

Neither trained local adapter passed qualification. Local inference requires `--experimental`, returns candidate-only research predictions, and cannot approve releases. See [property results](MODEL_PROPERTY_RESULTS.md). The frozen property test set remains reserved; these changes do not consume it or improve measured model accuracy.

## Coverage, Reports, and Release Policy

Full coverage requires every enabled analyzer to have completed runs, no skipped targets, and a non-mock scan. Bounded sampling remains useful partial evidence but is not full analysis. CLI reports and dashboard gates use this same definition.

Release policies require complete coverage by default, reject unknown settings and malformed thresholds, and retain warnings even when a PoC was discarded or a temporary patch was verified. Unknown severities require review. Scan the actually applied patch again before releasing it. An explicitly supplied baseline gates introduced findings only; it does not clear existing issues. Turning off `require_complete_coverage` deliberately weakens this gate.

Benchmark detection matches explicitly mapped detector categories to reviewed labels, not arbitrary warnings. Unsupported labels, incomplete coverage, and demos are excluded from accuracy denominators and reported separately. Global clean controls cover the mapped categories only. This is not source-line or exact-defect matching.

Reports retain proposed patches but label unsuccessful ones unverified. Workflows stop on review-required states and remove their owned temporary workspace even after unexpected failures.

CLI scans exit with code 2 for incomplete, inconclusive, or review-required outcomes; code 0 means workflow completion, not a security release approval. Use `sentinel gate` for that separate decision. Dashboard event streams remain open across intermediate phase/command completion; already-finished runs replay their evidence immediately. Transient disconnects reconnect automatically. After three consecutive connection failures, the UI stops monitoring and marks the run status unknown, not failed. In-flight telemetry is not durable across API restarts; completed reports are persisted separately.

## Local Execution Trust Boundary

Run only projects you trust on this Mac. The command allowlist and temporary copy are **not an operating-system sandbox**: Foundry project configuration and cheatcodes can access resources. Inspect imported tests, configuration, and dependencies first. Do not expose the local API to the public Internet; multi-user isolation and hosted execution require a separate hardened design.

## Verification

Run the full Python suite with `.venv/bin/pytest -q` and the dashboard logic checks with `make test-dashboard`. Real offline Forge integration tests cover the four reviewed repair fixtures when Forge and the pinned local solc 0.8.20 are available; they explicitly skip when those tools are absent. Synthetic tests additionally cover empty/malformed runs, setup failures, changed oracles, removed/mismatched regressions, absent baselines, misconfigured policy, category matching, unverified report labels, model opt-in, CLI exit codes, terminal routing, and exception cleanup. Dashboard tests cover complete/incomplete coverage, stream lifetime, and escaping untrusted evidence. CI runs both suites and checks that demo evidence is rejected by release policy.

Passing those tests proves the covered behaviour, not broad security performance. Remaining work includes independently reviewed held-out vulnerable/negative contracts, exact-defect localization, broader approved oracles, compiler-level compatibility checks, reproducible dependency locks, and hardened execution isolation.

### Local Check on October 13, 2026

- Python: 141 tests passed, including all four real offline Forge repair cases, with no skips on this Mac.
- Dashboard: five Node logic tests passed; browser inspection confirmed incomplete scanner coverage stays separate from a verified fixture repair.
- Ruff and `git diff --check` passed. Workflow YAML parsed locally; GitHub Actions has not been run remotely for these changes.
- Full CLI fixture smoke test reached `verified` with structured before/after evidence. Slither completed; Mythril exceeded the deliberately short verification budget, so scanner coverage stayed incomplete.
- The same ledger was rejected by `sentinel gate` with exit code 1, preserving high-severity original findings and the incomplete-coverage reason.
- No retraining or held-out model test evaluation was performed. The previously failed adapter remains research-only.
