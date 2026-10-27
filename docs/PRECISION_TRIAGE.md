# Precision-First Triage

## Development Plan

The target is 99% precision with useful recall, not a cosmetic confidence score. This opt-in experiment is a **retrospective development analysis**, not a new independent benchmark or an achieved 99% claim. The 120-case inheritance development set and the 85-case follow-up have already informed development. Their original manifests, labels, reports, ledgers, and failed qualification outcomes must remain unchanged.

The first policy is deliberately narrow: prioritize an unchecked-call candidate only when Slither's `unchecked-send` or `unchecked-lowlevel` rule and Sentinel's SSA `unused-call-result` check identify the same compiler AST node. Require matching target file, execution/declaration contract, function signature, byte offset, length, and node text. Validate byte bounds and line mapping against the pinned source. Both findings need at least medium qualitative confidence and medium impact. Numeric `confidence_score` is not used as a probability.

This is structural corroboration, not two independent engines: both checks depend on Slither. An AST node may contain multiple operations, so matching it does not prove identical defect identity, exploitability, or intended failure-handling requirements. A source with an ignored result may deliberately accept failure. Human assessment still matters.

Reentrancy, origin authorization, unmatched call nodes, unsupported metadata, and one-check-only warnings remain in a review queue. This version does not automatically prioritize those properties. It must not describe deferred warnings as false alarms, discard them from the evaluation, or certify a contract as clean. Prioritized findings remain **candidates**, not confirmed vulnerabilities.

## Measurement Rules

- Process every case in the original manifest exactly once. Reject missing cases, failed coverage, unsupported labels, mixed provenance, changed target/dependency bytes, or ledger/report disagreement.
- Recompute the original candidate metrics before measuring the priority queue.
- Retain the entire labeled denominator. A vulnerable case with no prioritized finding counts as a false negative, including cases deferred to humans.
- Report candidate metrics, priority metrics, per-property results, deferred cases, unknown labels, and complete input ledger hashes. Keep out-of-scope findings referenced by ID in their original ledgers.
- Never infer external ground truth from candidate agreement. Unknown labels remain excluded from accuracy counts, but remain visible in the report.
- With no prioritized predictions, precision is unavailable, not 100%. Without negative controls it also remains unavailable, consistent with the existing experiment convention.
- Report a two-sided 95% Wilson interval for case-level precision. A tiny zero-error sample does not establish 99% population precision. The calculation follows [NIST's Wilson interval description](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm). Independence and representative-sampling assumptions are not established by these development corpora; the interval is descriptive, not release certification.
- Preserve the existing sample-count requirement of 20 positives and 20 negatives per property and recall target of 80%. Also show whether the precision interval's lower bound reaches 99%, overall and for every property. Meeting a point estimate alone is insufficient.
- `claim_supported` is intentionally false for this retrospective workflow. A future frozen, independently reviewed, representative benchmark is required to support a claim. Do not tune this policy against reserved model test data.

The new script reads saved reports only. It performs no compilation, scanner execution, LLM inference, RPC access, exploit execution, or repair execution. It does not alter the default product workflow or the frozen scanner implementation. New hashes bind the inputs at triage time; earlier reports did not cryptographically bind their original ledger bytes, so these hashes do not retroactively authenticate historical files.

## Run

From the repository directory, supply the exact saved `sentinel-static` experiment report, not a summary or a vanilla Slither run:

```bash
.venv/bin/python scripts/precision_triage.py \
  --manifest datasets/scanner-inheritance-fresh-v1/manifest.json \
  --report reports/experiments/scanner-inheritance-fresh-v1/sentinel-experiment-sentinel-static-20261014T030426959061Z.json \
  --output reports/experiments/precision-triage-v1/fresh-development.json
```

Existing output is never overwritten. Use a new output filename for a rerun. `--require-target` writes the evidence report and exits 2 because this development-only workflow cannot support an independently validated 99% claim. Ordinary report generation exits 0 on successful evaluation; that indicates a valid report, not qualified performance.

The same script accepts the original inheritance development manifest/report and the external v3 manifest/report. External labels stay unknown. No two-case accuracy claim is possible without positive/negative assessments, and two cases would still be insufficient for the desired precision claim.

There is also a Make target. An explicit input report and unused output path are required:

```bash
make precision-triage \
  PRECISION_SCANNER_REPORT=reports/experiments/scanner-inheritance-fresh-v1/sentinel-experiment-sentinel-static-20261014T030426959061Z.json \
  PRECISION_TRIAGE_OUTPUT=reports/experiments/precision-triage-v1/fresh-rerun.json
```

Set `PRECISION_MANIFEST` when using another cohort. The policy does not change between cohorts.

## Measured Results

Measured on October 22, 2026. These are case/property matches against preserved upstream labels, not human-adjudicated vulnerability counts. All 120 development cases, all 85 follow-up cases, and both unknown-label external cases were retained. No policy changes were made between the three analyses. The script used for the analyses is preserved at `reports/protocol-snapshots/precision-triage-v1/scripts/precision_triage.py`, with its hash in each output.

| Development cohort | Queue | TP | FP | FN | TN | Precision | Overall recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Earlier 120 cases | Original candidates | 43 | 5 | 17 | 55 | 89.58% | 71.67% |
| Earlier 120 cases | Prioritized candidates | 10 | 1 | 50 | 59 | 90.91% | 16.67% |
| Follow-up 85 cases | Original candidates | 18 | 9 | 7 | 51 | 66.67% | 72.00% |
| Follow-up 85 cases | Prioritized candidates | 9 | 0 | 16 | 60 | 100.00% | 36.00% |

The priority precision intervals are approximately 62.26%-98.38% for the earlier set and 70.09%-100% for the follow-up. Neither supports a 99% precision claim. The external cohort has two unknown reentrancy labels; both cases stay in the review queue and all accuracy metrics remain unavailable.

The higher aggregate precision is largely a change in reporting scope: the policy prioritizes only unchecked calls. It does **not** demonstrate improved unchecked-call detector accuracy. On that property alone, the earlier set changes from 91.67% precision / 55% recall to 90.91% / 50%; the follow-up changes from 100% / 66.67% to 100% / 60%. Corroboration loses one positive case in each cohort without removing the existing unchecked-call false positive. Retain this as an experimental evidence queue, not a replacement scanner or recommended 99% operating point.

The retained false-positive case is `cgt-92b0be45b9671a60`, `Sweeper`. Both checks identify the same ignored `b.send(0)` node at line 15 in `sol_clean(uint256,uint256)`. The original Zeus-derived `Unchkd_send` assessment is negative. Source comments describe state debloating, and the function also has an assembly counterpart. These observations do not settle whether an ignored zero-value send is a relevant defect under the original assessment's semantics. Do not suppress every zero-value call: calls can have non-value effects. The assessment remains negative, the false positive remains counted, and any changed label requires documented human review rather than a score-driven adjustment.

Outputs under `reports/experiments/precision-triage-v1`:

- `inheritance-development.json`: 120 cases, 11 prioritized, 37 candidate cases deferred, 72 without matching candidates.
- `fresh-development.json`: 85 cases, 9 prioritized, 18 candidate cases deferred, 58 without matching candidates.
- `external-unlabelled.json`: two cases, both deferred, both unknown.

The 99% claim flag remains false in all three reports. The default scanner and its broad candidate reporting remain unchanged. Full verification after adding the workflow passed 358 Python tests and five dashboard tests; this includes pre-existing reviewed local Forge fixture tests, not exploit execution against benchmark contracts. Targeted lint is clean. A broader `scripts/` lint run exposes three pre-existing issues in `scripts/benchmark_forge_artifacts.py`; that unrelated file was not modified.

## Next Evidence

Document the two human reviewers' actual decisions and source evidence. Review the deferred queue without treating agreement as ground truth. Improve detector logic using development data, then freeze a new protocol before evaluating on a separately selected, adequately sized external cohort with both positive and negative property assessments. Report recall and every deferred warning alongside precision.
