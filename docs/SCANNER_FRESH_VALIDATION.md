# Fresh Inheritance Follow-Up

This phase checks the unchanged inheritance-aware scanner on fresh lexical components from the same pinned CGT corpus. It is not an external corpus or independent re-adjudication of labels. The earlier 120 cases informed the inheritance change and remain development data for it.

## Frozen Plan

- Exclude all components and normalized sources used in actual fitted-model train/validation subsets.
- Exclude all four earlier scanner manifests by component and raw-source hash: original pilot, expanded pilot, v1 replication, and inheritance development reanalysis.
- Use only the prepared training-partition candidate pool, seed 211, and request 20 positives and 20 negatives per property. Do not open reserved model test data.
- Keep the existing 32 KB/no-import/source-pragma restrictions, assessed-contract scoring, six local compiler pins, and companion-contract support.
- Freeze the current implementation and runtime before scanning. Do not tune the detector or change labels between the two full runs.
- Compare vanilla Slither and opt-in `sentinel-static`, collecting candidates only. No model, RPC, exploit execution, or repair execution.
- Keep the existing qualification requirement: at least 20 positives and 20 negatives per property, recall and specificity at least 80%, and complete coverage. Report underfilled buckets without duplication, supplementation from sealed test data, or reduced thresholds.

Before compilation checks, only 11 unused origin-authorization positives and 21 reentrancy positives remain in this candidate pool. The requested sample may therefore be underfilled and cannot establish qualification even if its accuracy were perfect. Selection constraints and lexical deduplication do not prove semantic independence or representative prevalence. Historical public data may have appeared in model pretraining; no model is evaluated here.

## Commands

```bash
make prepare-scanner-fresh
make validate-scanner-fresh
make validate-scanner-fresh-static
```

Preparation refuses to overwrite `datasets/scanner-inheritance-fresh-v1`. Reports and per-case evidence go to `reports/experiments/scanner-inheritance-fresh-v1`. Failed qualification saves the report and exits 2; run the second profile separately even when the first fails its gate.

Compare the exact two reports, supplying their timestamped paths:

```bash
.venv/bin/python scripts/compare_scanner_profiles.py \
  --manifest datasets/scanner-inheritance-fresh-v1/manifest.json \
  --baseline BASELINE_REPORT.json --extended EXTENDED_REPORT.json \
  --output reports/experiments/scanner-inheritance-fresh-v1/paired-comparison.json
```

The comparison refuses mixed manifests/protocols, missing or duplicate cases, altered assessments/targets/source hashes, incomplete coverage/attribution, unsupported labels, and metrics inconsistent with case predictions. It preserves both qualification outcomes, reports every changed prediction including false positives, and recomputes per-property counts. It does not adjudicate the annotations or certify an exploit. Existing output is not overwritten.

For stronger evidence, obtain a separately licensed corpus with independent positive and negative property assessments, enough eligible cases, and expert adjudication. Do not count this same-corpus sample as that evidence, pool it with tuned development cases, or claim zero-day detection.

## Prepared Sample

Prepared locally on October 14, 2026, with 85 distinct lexical components and raw-source hashes. Explicit audits verified source pins and no component/raw-source overlap with any of the four prior scanner manifests, or component/normalized-source overlap with either actual fitted-model subset. The implementation hashes are unchanged from the inheritance development reanalysis.

| Property | Positive assessments | Negative assessments |
| --- | ---: | ---: |
| Unchecked low-level calls | 15 | 20 |
| Reentrancy | 7 | 20 |
| Origin authorization | 3 | 20 |

Manifest SHA-256: `4ca61227535fd9e6ccef729c15c6e6c59a916128bedb6d01af23d51c198135fe`.

A local source snapshot at `reports/protocol-snapshots/scanner-inheritance-v1` matches all 65 implementation hashes in this protocol (and the preceding development reanalysis). It preserves Sentinel sources and `pyproject.toml`, not complete third-party environments. For a historical rerun, use the repository's absolute Python interpreter from that archive directory, set `PYTHONPATH` to the archive for child analyzers, and supply absolute manifest and `STATIC_BINARY` paths while retaining the pinned compilers and 30-second timeout. A source snapshot alone does not restore changed external tooling.

Preparation excluded 671 rows belonging to prior scanner components, 667 belonging to fitted-model components/sources, and 395 unsupported-property rows. Bounded selection rejected 119 candidates for size/import/pragma restrictions, 28 for incompatible deployable target builds, and 11 for duplicate components. All original assessments remain intact. The sample's prevalence is not balanced, and neither its precision nor its tiny positive-property denominators should be generalized to production.

## Measured Results

Both full runs completed on October 14, 2026: all 85 cases had complete coverage, supported labels, and attribution, with no case errors. The paired checker verified the same frozen manifest/provenance, retained every original assessment, and recomputed the confusion matrices. No scanner implementation changes were made in this phase.

| Profile | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Vanilla Slither | 17 | 8 | 8 | 52 | 68.00% | 68.00% | 68.00% |
| Opt-in extension | 18 | 9 | 7 | 51 | 66.67% | 72.00% | 69.23% |

| Property | Baseline TP/FP/FN/TN | Extended TP/FP/FN/TN | Baseline / Extended Recall | Baseline / Extended Specificity |
| --- | --- | --- | --- | --- |
| Reentrancy | 6/7/1/13 | 6/8/1/12 | 85.71% / 85.71% | 65.00% / 60.00% |
| Origin authorization | 2/1/1/19 | 2/1/1/19 | 66.67% / 66.67% | 95.00% / 95.00% |
| Unchecked low-level calls | 9/0/6/20 | 10/0/5/20 | 60.00% / 66.67% | 100.00% / 100.00% |

There are exactly two changed case predictions:

- `cgt-5339f06c8bf2e597`, `Mattew`: a positive unchecked-call assessment is newly matched. The candidates are `unused-call-result` warnings for unused send results at lines 30 and 39 in its declared fallback. This gain comes from the existing SSA check, not a newly detected inherited vulnerability.
- `cgt-832a5c10513da8fd`, `BurnableCrowdsaleToken`: a negative reentrancy assessment is newly matched, counting as an additional false-positive case. The inherited `reentrancy-events` candidates arise in `UpgradeableToken.upgrade()` and `setUpgradeAgent()`, with base source mappings and child execution context intact. The original negative property assessment is preserved; disagreement is not a reason to relabel the case or drop that detector after seeing its score.

Thus the clean three-positive/no-new-false-positive development improvement did **not** reproduce as such on these fresh cases. The full extension trades one additional labelled positive for one additional false-positive case; this sample does not demonstrate an inheritance-specific true-positive gain. Candidate matches are not exploitability confirmations. A negative reentrancy assessment does not certify the whole contract as safe.

**Both profiles fail qualification.** All properties have fewer than 20 eligible positives. Reentrancy specificity is below 80%, while origin and unchecked-call recall are below 80%. Keep the extension experimental and opt-in. Do not pool these scores with the preceding tuned set, declare population false-positive rates from these denominators, or claim production readiness.

Evidence in `reports/experiments/scanner-inheritance-fresh-v1`:

- Baseline: `sentinel-experiment-slither-20261014T030204592481Z.json`.
- Extension: `sentinel-experiment-sentinel-static-20261014T030426959061Z.json`.
- Strict paired summary with report hashes and changed predictions: `paired-comparison.json`.
- All 170 case ledgers are retained; no model test data, exploit, repair, or RPC access was used.

Next, obtain independently adjudicated positive/negative assessments from a separate corpus and review the event-pattern/property-label boundary. Any rule change motivated by these cases makes this sample development data for the changed version and requires another fresh protocol. Do not silently suppress event warnings, loosen thresholds, or use reserved model test cases to fill the minority buckets.
