# Precision Target Audit

The requested target remains unmet. A separate audit prevents the older aggregate development gate from being confused with 99% precision or robust per-property detection. No original predictions, reports, labels, thresholds or product gates are rewritten.

## Requirements

For the overall cohort **and each property**, require observed precision at least 99%, recall at least 80%, specificity at least 80%, no invalid assessments, and a nominal two-sided 95% Wilson precision lower bound of at least 99%. Also retain at least 20 positive and 20 negative assessments per property. The interval requirement is more demanding than a 99% point estimate; zero positives produce unavailable precision, never 100%.

Independent external evaluation, reviewed labels and verified build context remain separate evidence requirements. These development runs do not meet them, regardless of numerical performance. Binomial intervals assume an appropriate sampling model and do not account for case correlation, annotation uncertainty, pretraining contamination or inspected validation data.

This is a research target audit, not a production certification tool. Its successful execution means the audit was written, not that a quality gate passed. Read `numerical_requirements_met` and `independent_99_percent_claim_supported` in the report.

## Run

```bash
.venv/bin/python training/precision_target.py \
  --output training/runs/mac-precision-target-v1.json
```

The script verifies frozen protocol/data/source-run pins, feature receipt, classifier and comparison hashes, every intended ID and upstream label, raw classifier margins, fixed-threshold decisions and complete recomputed metrics. It refuses existing output paths or writes within frozen experiments. It reports missing support and individual property failures rather than dropping them. It opens no reserved model test file.

Completed October 22, 2026. All four audited reports fail the numerical target: the 54-case frozen-Qwen readout, the original 54-case lexical control, the 821-case scaled lexical control, and its declared original 54-case subset. These overlapping reports are not independent confirmations.

The scaled lexical control's original aggregate development gate passes despite 0% reentrancy and origin-authorization recall. The stricter audit exposes those failures and retains all 52 missed positives and 17 false positives on the full cohort. No experimental model is promoted into the CLI or dashboard as a reliable detector.

## Verification And Next Gate

Saved JSON classifiers were independently replayed against all 508 train/validation predictions from the two original probe methods and all 821 full-scale validation predictions. Saved metrics and classifier margins matched. Runtime checks also confirm training-only lexical vocabulary fitting, full/subset coverage, JSON export, non-finite feature rejection and output immutability. Original scanner implementation pins and base model assets are unchanged; optional classifier dependencies stay in the isolated MLX environment.

Verification passed 484 Python tests and five dashboard tests. Three optional-dependency runtime checks are skipped in the main interpreter and passed separately in the isolated probe interpreter. Targeted lint and tracked whitespace checks pass. All 65 scanner implementation pins, ten archived implementation files, eight target-audit input hashes and the pinned base-model assets were verified unchanged. Source snapshots are retained under `reports/protocol-snapshots/model-readout-v1/`.

Before claiming further reliability improvements, complete the [independent label/context review](MODEL_LABEL_REVIEW.md), assemble a sufficiently supported external evaluation that has not guided training, and predeclare a new training-side procedure that addresses minority-property recall. Do not iterate against these validation scores until a flattering threshold appears, relabel errors automatically, hide unresolved cases or turn abstention into apparent safety. A 1.5B parameter count alone is not evidence that this target is attainable with the current labels and compute.
