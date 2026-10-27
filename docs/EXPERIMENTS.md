# Sentinel Experiments

Sentinel experiments produce reproducible execution records. They do not turn a project manifest or a fixture into a published performance claim by themselves.

## Experiment Manifest

Create a JSON manifest with a local Foundry project for each case:

```json
{
  "name": "held-out-evaluation",
  "cases": [{
    "id": "case-001",
    "project_path": "../projects/case-001",
    "group": "held_out",
    "vulnerability_class": "reentrancy",
    "ground_truth": "vulnerable"
  }]
}
```

`group` is one of `fixture`, `held_out`, `audit`, `clean`, or `development`. `ground_truth` is `vulnerable`, `clean`, or `unknown`. Unknown labels are preserved in the report but excluded from metric denominators. Failed, unavailable, timed-out, and otherwise incomplete analyzer cases are also excluded, with their count recorded in `metric_scope`. Precision, F1, and false-positive rate are withheld until at least one completed clean control is present, separately for aggregate and per-property metrics. Precision remains undefined when no positive predictions exist.

Optional `target_contract` and `target_file` constrain category matching to the assessed contract and file. Missing attribution on relevant findings makes the case incomplete rather than a true negative. Use `source_sha256` with `target_file` to pin the assessed source. A `provenance.compiler` object containing `path` and `sha256` pins the compiler binary and requires the project configuration to select that compiler. Changed pins and unexpected scan exceptions are retained as failed cases; other cases continue. Case IDs must be unique, filename-safe identifiers.

Reports include a manifest hash, dataset provenance, analyzer statuses, per-property confusion matrices, and a development qualification result. `--require-qualification` exits with status 2 after saving the report when coverage, sample counts, recall, or specificity are insufficient. The defaults require at least 20 positives and 20 negatives per measured property, recall >= 0.80, specificity >= 0.80, and all source hashes pinned. Passing these engineering thresholds is not production certification. See [scanner validation](SCANNER_VALIDATION.md) for the small CGT pilot and reproduction commands.

The checked-in example manifest uses the four reviewed fixtures only. It is an engineering check, not held-out evidence.

Only findings whose explicit Slither detector or Mythril SWC maps to the reviewed case category count as detections. The mapping is in `sentinel/detection.py`, based on [Slither detector definitions](https://github.com/crytic/slither/wiki/Detector-Documentation). Unrelated categories and maintenance warnings such as `solc-version` are not matches. Unsupported labels are recorded and excluded. Global clean controls cover only these explicitly mapped categories; matching is case-level, not precise defect localization. Skipped/bounded sources make full coverage incomplete. Mock runs never contribute empirical accuracy or repair-rate metrics.

Generated model PoCs remain unexecuted review drafts. A failed or inconclusive PoC does not clear a scanner warning. Automated repair is currently limited to reviewed fixture oracles, so generalized repair-rate claims are not supported.

## Baselines and Ablations

```bash
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile slither --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile mythril --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile scout-union --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile sentinel-no-red-team --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile sentinel-no-retry --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile sentinel-full --mock
```

Profiles are persisted in each report. `slither`, `mythril`, and `scout-union` collect candidates only. `sentinel-no-red-team` is an explicit confirmation ablation. `sentinel-no-retry` permits one repair attempt. `sentinel-full` uses both analyzers and the configured retry bound.

The opt-in `sentinel-static` profile combines vanilla Slither with Sentinel's experimental SSA dead-call-result and AST direct origin-authorization checks, collecting candidates only. It also evaluates compiled inherited entry points using those checks and Slither's existing reentrancy rules; see [inheritance context and development results](SCANNER_INHERITANCE.md) for override handling and attribution limits. Install `.[static]` and provide `STATIC_BINARY` or place `sentinel-static` on PATH. The origin check handles direct Boolean equality alternatives in `require`/`assert`, not arbitrary authorization flow. This profile is not the vanilla Slither baseline and does not promote these checks into default scans. Raw output records the implementation source hash, so successive versions of this development profile must not be treated as identical. See [discrepancy triage](SCANNER_TRIAGE.md).

The [scanner replication](SCANNER_REPLICATION.md) adds a frozen code/runtime protocol and disjoint-component exclusions. These opt-in manifests reject mocks, partial evaluations, undeclared profiles, and implementation/runtime drift; ordinary development manifests keep their existing behavior.

The [fresh inheritance follow-up](SCANNER_FRESH_VALIDATION.md) excludes all earlier scanner components and preserves the unchanged detector under a new frozen manifest. It adds a strict paired-report comparison and retains underfilled property buckets rather than reducing qualification requirements. This remains a same-corpus check, not external validation or independent label adjudication.

The [external pilot](EXTERNAL_BENCHMARK.md) pins dependency/configuration files and verifies them through its guarded runner. It retains unknown labels until [two human review submissions](LABEL_REVIEW.md) agree. Unlabelled cases are never converted to negative controls or scored as detection accuracy; incomplete builds remain visible in readiness evidence. Existing qualification thresholds are not changed.

Each report includes per-case outcome, coverage status, findings, confirmations, verified repairs, retries, duration, per-vulnerability-class counts, configured models, platform, and timeout. Model token or API costs must be added from the provider billing record before they are reported in a paper.

## Stronger Validator Oracles

Place an optional `sentinel-validation.yml` at a Foundry project root:

```yaml
positive_tests:
  - testDepositAndWithdraw
security_tests:
  - testAuthorizationInvariant
require_abi_compatibility: true
require_storage_declaration_compatibility: true
```

Configured test selectors must be Solidity identifiers. Positive and security tests run through Forge and become required Validator gates. The ABI and storage checks compare declared public/external function signatures and top-level storage declarations before and after a patch. They are conservative source checks, not compiler ABI or storage-layout proofs; use compiler-level upgrade checks for production upgradeable contracts.

## Publication Boundary

Do not report aggregate quality metrics until cases have reviewed ground truth, clean controls, comparable tool budgets, and preserved reports. Use fixtures for regression coverage only. Publish runtime, retry, tool availability, model configuration, raw ledgers, and failure categories with any reported result.
