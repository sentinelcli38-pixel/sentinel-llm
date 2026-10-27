# Scanner Development Validation

This workflow evaluates real scanner output on public local Solidity sources. It does not generate or run exploits, contact RPC endpoints, or evaluate the reserved model test set. It is a development baseline, not a model-quality or zero-day detection claim.

## Data Boundary

The importer uses the [CGT dataset](https://github.com/gsalzer/cgt) at revision `f8cd72cf7fbbfebc809c454667eee271706a4b2b`. Labels assess a named contract for a particular weakness. A negative SWC-104 assessment is not a declaration that the contract has no other weaknesses. Original source comments and license notices are preserved.

Inputs come from `datasets/model-properties/valid.jsonl`. Components already selected for model fitting or model validation are excluded using `datasets/model-properties-fit/train.jsonl` and `valid.jsonl`. No `test.jsonl` file is opened. The resulting cases have distinct lexical components, not proven semantic independence; prior model pretraining overlap is unknown.

Sampling requests positive and negative cases for SWC-104, SWC-107, and SWC-115. Slither's reviewed mapping does not cover SWC-101, so arithmetic is excluded for this profile. Each source must have a matching frozen content hash, a Solidity pragma, no imports, <= 32 KB of raw source, and exactly the assessed contract as its deployable compiler output. These constraints create compilation and selection bias and must accompany any reported result.

The expanded run explicitly enables `--allow-multiple-contracts`: companion contracts may compile, but the assessed contract must be deployable and detections must still match its name and file. This relaxes the default single-contract build constraint, not the attribution requirement. It uses a new frozen manifest, never overwrites the original pilot, and still excludes fitted model components.

## Reproduce

Use the project Python environment, Slither, Forge, and installed Solidity compilers. The prepared model-property and fitted subsets must already exist; these targets do not download data or train a model.

```bash
make prepare-scanner-validation
make validate-scanner
```

Override `SCANNER_SOLC_CURRENT`, `SCANNER_SOLC_LEGACY`, `SCANNER_DATA`, and `SCANNER_PER_BUCKET` as necessary. The default compiler versions are 0.8.20 and 0.4.24. For more compiler versions, use repeated `--compiler` arguments directly:

```bash
.venv/bin/python scripts/prepare_scanner_validation.py \
  --compiler /absolute/path/to/solc-0.8.20 \
  --compiler /absolute/path/to/solc-0.4.24 \
  --output datasets/scanner-validation-v2 --per-bucket 2
```

An existing prepared output cannot be overwritten: choose a new directory for a new sampling run. The manifest records validation and fitted-subset hashes, source URLs, original assessments, component IDs, sampling seed, compiler hashes/versions, skipped case counts, and missing buckets. Evaluation verifies the source and configured compiler before each scan.

`validate-scanner` writes JSON reports and individual scan ledgers under `reports/experiments/scanner-validation`. It runs Slither-only candidate collection with a 30-second command timeout, no mocks, no model inference, and no patch execution. Failed cases remain visible and are excluded from accuracy denominators. `--require-qualification` returns exit code 2 when the engineering gate fails; `make` consequently reports an unsuccessful target while preserving all evidence.

## Pilot Result

Local run on October 13, 2026, using the two default compilers and two requested cases per bucket:

| Property | Positive cases | Negative cases | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Unchecked low-level calls | 2 | 2 | 0 | 0 | 2 | 2 |
| Reentrancy | 0 | 2 | 0 | 0 | 0 | 2 |
| Authorization using tx.origin | 0 | 2 | 0 | 0 | 0 | 2 |

All eight scans completed. Aggregate recall is 0/2, and observed false-positive rate is 0/6. Precision is undefined because there were no matching positive predictions. Reentrancy and tx.origin recall cannot be calculated because compatible positive cases were unavailable. Warnings in other categories do not count against property-specific negatives.

**Qualification failed.** The pilot lacks two required positive buckets, falls below the minimum sample size, and misses both available positive unchecked-call labels. A zero observed false-positive count across six controls is not evidence of a low population false-positive rate.

The minimum engineering gate requires 20 positives and 20 negatives per property, recall >= 0.80, specificity >= 0.80, complete supported-label coverage, and pinned sources. These are configurable development thresholds, not statistical confidence bounds or security certification.

## Experimental Check and Expanded Run

Install the optional analyzer and compare it with the unchanged baseline:

```bash
make install-static
make validate-scanner-static
```

The opt-in profile adds a Slither-SSA check for call success results copied to locals but never consumed. On the original eight cases it finds `Matthew`, raising observed recall from 0/2 to 1/2, with no matching alerts on the six negatives. This result was used for detector development and is not held-out evidence. The `EthMultiplier` discrepancy remains in the scores. See [triage notes](SCANNER_TRIAGE.md) for the technical explanation and limitations.

The expanded manifest uses six local compiler versions and requests five cases per positive/negative bucket. Prepare it only once:

```bash
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6
make prepare-scanner-expanded
make validate-scanner SCANNER_DATA=datasets/scanner-validation-expanded
make validate-scanner-static SCANNER_DATA=datasets/scanner-validation-expanded
```

Versions 0.8.20 and 0.4.24 must also be installed. `solc-select install` downloads compilers without switching the global version; evaluation projects use explicit binary paths. Existing Mac binaries for older versions require Rosetta. Reports record hashes of the actual compiler binaries used.

The prepared expanded set contains 27 distinct components: 3 unchecked-call positives, 5 reentrancy positives, 4 tx.origin positives, and 5 negatives for each property. All six label buckets are present, but this is not a fully balanced set and remains below the qualification sample threshold. It overlaps the original pilot, so these runs must not be pooled as independent observations.

The baseline and successive experimental versions completed all 27 cases on October 13, 2026:

| Profile | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Vanilla Slither | 5 | 2 | 7 | 13 | 71.43% | 41.67% | 52.63% |
| Slither + dead-result check (first version) | 6 | 2 | 6 | 13 | 75.00% | 50.00% | 60.00% |
| Slither + dead-result and origin-guard checks | 7 | 2 | 5 | 13 | 77.78% | 58.33% | 66.67% |

The first added detection is `Matthew`; the subsequent origin check adds `UnicornManagement` and changes no other case-level prediction. The extension introduces no new false positives on these cases. A fresh vanilla run reproduced the original baseline's predictions. All versions still fail qualification. Reentrancy retains 2 false positives out of 5 negatives; tx.origin recall improves from 1/4 to 2/4; unchecked-call recall with the extension remains 1/3. The remaining discrepancies are documented without suppressing warnings or changing original labels. These small, development-selected samples do not establish population accuracy or generalization. Baseline and extended reports and individual raw ledgers are retained under `reports/experiments/scanner-validation-expanded`, with implementation hashes identifying the experimental versions.

## Follow-Up Work

The next run uses the [frozen scanner replication protocol](SCANNER_REPLICATION.md), with explicit exclusions of fitted-model and prior scanner components. It does not replace the development results above or open the reserved model test split.

Obtain independent review of the recorded label/scope discrepancies and the two reentrancy warnings on negative assessments. Expand evaluation with independent positive and negative components in a new manifest and report all exclusions. Freeze the candidate detector and protocol before a separate validation run: repeating this development set is not independent evidence. Re-run the unchanged baseline before comparing any new model or detector. Keep the model test split sealed until the final experimental protocol and acceptance criteria are fixed.
