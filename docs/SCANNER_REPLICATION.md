# Frozen Scanner Replication

This follow-up checks the fixed candidate detector on new, disjoint lexical components from the same pinned CGT corpus. It is **not** an external-dataset replication, a final model test, or a production qualification claim. Do not tune the detector using these results and continue calling the set independent validation.

## Protocol

- Use only the prepared corpus `train.jsonl` candidate pool, excluding every component and normalized source used in fitted-model `train.jsonl` and `valid.jsonl`.
- Exclude the original eight-case scanner pilot and the expanded 27-case development set by component ID and exact raw-source hash. Exclusion manifest hashes are recorded.
- Never read either reserved model `test.jsonl` file. Selecting from a partition named `train` does not mean the selected examples were used to fit the pilot model; the actual fitted subset is explicitly excluded. Prior base-model pretraining contamination remains unknown.
- Sampling seed: 109. Request 20 positives and 20 negatives for each of SWC-104, SWC-107, and SWC-115, without replacement and with at most one assessed property per source/component.
- Keep the existing raw-source limit of 32 KB, no imports, a Solidity pragma, a deployable assessed contract, and six installed compiler versions: 0.4.24, 0.4.26, 0.5.17, 0.6.12, 0.7.6, 0.8.20. Companion contracts may compile; findings must match the assessed contract and file.
- Before preparing the set, freeze all Sentinel Python sources, `pyproject.toml`, scanner entry-point paths/hashes, local Python and selected package versions, profiles, 30-second command timeout, and qualification thresholds in the manifest.
- Compare vanilla `slither` against `sentinel-static` (Slither plus both experimental checks). Both collect candidates only. No model inference, generated exploit execution, patch execution, or RPC access is part of this evaluation.
- Require complete non-mock runs. Validate the frozen protocol before scanning and before each case. Mid-run drift becomes an incomplete case and cannot pass qualification.
- Keep the pre-existing engineering thresholds: at least 20 positives and 20 negatives per property, recall >= 0.80, specificity >= 0.80, complete supported-label coverage, and frozen case/compiler sources. Underfilled buckets and failures remain visible.

The protocol hashes console entry points, not the complete external Python environments behind those scripts. Its package versions describe Sentinel's local interpreter. It is a local drift guard, not a hermetic container or signed, externally registered protocol. Compiler binaries are pinned separately per case. Lexical exclusions do not prove semantic independence, ground-truth correctness, or absence from model pretraining.

## Reproduce

Install the optional analyzer and all six compilers first. Preserve earlier evaluation manifests. From the repository root:

```bash
make prepare-scanner-replication
make validate-scanner-replication
make validate-scanner-replication-static
```

The preparation target creates `datasets/scanner-replication-v1/manifest.json` once and refuses to overwrite it. Evaluations save timestamped JSON reports and per-case raw ledgers under `reports/experiments/scanner-replication-v1`. A failed qualification returns exit code 2 from the benchmark; `make` reports an unsuccessful target even though the evidence was saved.

Source or runtime drift requires an explicitly new protocol and manifest in a new output directory, not silently refreshing the old pins. Freeze all code changes before preparing a run. Never pool this set with development cases as though they were independent observations from different corpora.

## Interpretation

All confusion matrices are property-specific, case-level detector matches, not exact-defect localization or exploitability results. A negative label is not whole-contract safety. Report denominator counts, exclusions, incomplete scans, attribution errors, and each property separately. A stronger score on these sampled components would still not establish zero-day capability or production readiness.

## Prepared Set

Prepared locally on October 13, 2026, with 120 cases in 120 distinct lexical components and 120 distinct raw-source hashes. Each property has 20 positive and 20 negative assessments. Explicit overlap checks found no shared components or raw-source hashes with either prior scanner manifest, and no shared components with either fitted-model subset.

Manifest SHA-256: `87aa65aaebb4d62b37db71cade3de54e09810bb28ff62b083175000ce25ded88`.

The candidate pool is pinned at SHA-256 `fd3b0ab32364edadb5f97230e321fafd27a52e6a9482abee55f07c385b588de5`. The protocol records hashes for 65 implementation files. Preparation excluded 667 rows belonging to fitted-model components or normalized fitted sources, and 517 rows for unsupported arithmetic properties. During bounded sampling, 72 candidates were excluded for size/import/pragma restrictions, 15 for incompatible target builds, and 42 for already selected components. These selection constraints introduce bias and accompany all reported results.

The sample deliberately has 50% positives per property. Its precision is not an estimate of production precision at a different vulnerability prevalence. The gate's minimum sample count is an engineering convention, not a statistical guarantee.

## First Run Results

Both profiles completed all 120 cases locally on October 13, 2026. There were no incomplete cases, unsupported labels, or attribution failures. All 240 case ledgers are retained. Both reports use the same manifest hash and frozen protocol; no detector changes were made between the runs.

| Profile | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Vanilla Slither | 40 | 5 | 20 | 55 | 88.89% | 66.67% | 76.19% |
| Slither + experimental checks | 40 | 5 | 20 | 55 | 88.89% | 66.67% | 76.19% |

There are **zero case-level prediction changes** between profiles. The extension neither improves recall nor adds false positives on this set. This result does not reproduce the incremental detection benefit observed in the development cases. Extra warnings within an already detected case do not count as an additional true positive.

Per-property results are identical across the two profiles:

| Property | TP | FP | FN | TN | Recall | Specificity | Thresholds Met |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Reentrancy | 11 | 4 | 9 | 16 | 55.00% | 80.00% | No |
| Authorization using tx.origin | 19 | 0 | 1 | 20 | 95.00% | 100.00% | Yes, on this sample only |
| Unchecked low-level calls | 10 | 1 | 10 | 19 | 50.00% | 95.00% | No |

**Both profiles fail qualification:** reentrancy and unchecked-call recall are below 80%. Sample-count and scanner-completion requirements are met this time, but that does not compensate for missed positive assessments. Zero origin-related false positives among 20 controls is not evidence of a zero population false-positive rate.

Evidence under `reports/experiments/scanner-replication-v1`:

- Baseline: `sentinel-experiment-slither-20261013T130508722474Z.json`.
- Extended: `sentinel-experiment-sentinel-static-20261013T130807811742Z.json`.
- Original assessments, case/compiler pins, tool status, matched finding IDs, and ledger paths are preserved in the reports.

No exploitation or repair was attempted: legacy report fields for those stages are not measured performance for this experiment. The detector remains opt-in, and default scans are unchanged. The earlier development results remain separately recorded; do not combine their denominators with these results or describe their gains as demonstrated generalization.

## Next Development Decision

Prioritize reentrancy and unchecked-call coverage, with independent adjudication of possible label/scope disagreements. The frozen run is a baseline, not a reason to change ground truth or suppress inconvenient warnings. If these new cases are used to tune a detector, they become development data for that version; a subsequent independent check needs new excluded components or a separate corpus. Keep the reserved model test split sealed until the final model protocol is fixed.

The subsequent [inheritance-context work](SCANNER_INHERITANCE.md) uses this set for development. Its reanalysis has a separate manifest/protocol; the v1 metrics above remain historical results for the original frozen implementation. An archived source snapshot under `reports/protocol-snapshots/scanner-replication-v1` matches the original 65 implementation hashes.
