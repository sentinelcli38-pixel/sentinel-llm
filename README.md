# Sentinel LLM

Sentinel LLM is a local smart-contract security research application with a CLI,
dashboard, a Qwen2.5-Coder-1.5B adaptation pipeline, and executable verification
checks. The foundation model is pretrained Qwen, not a model trained from scratch.
The command-line package remains `sentinel-cli`, with the `sentinel` command.

The latest experimental kernel classifier measured **48.54% precision and 55.25%
recall** on 821 development-validation properties. These are not 1.5B LLM results
or a product-wide accuracy claim. The local verification audit passed four
fixture workflows and 20 rejection controls; **99% detection precision has not
been established**. See [experiment results](docs/HELDOUT_KERNEL_EXPERIMENT.md)
and [verification evidence](docs/VERIFICATION_FIRST_AUDIT.md).

Local environments, downloaded datasets, model weights, training run directories
and private reviewer submissions are not bundled in this source repository.
Dataset acquisition and local model setup are documented below. The project
continues the [Sentinel CLI project](https://github.com/Chinmay2121/sentinel-cli).

## Local Security Model Fine-Tuning

Sentinel includes an Apple Silicon MLX training pipeline for a quantized 1.5-billion-parameter code model. It prepares annotation-free inputs, keeps source repositories in separate splits, records provenance and hashes, trains LoRA adapters, and compares base/adapted predictions by vulnerability category and source line. See [local model training](docs/MODEL_TRAINING.md) for setup and the pilot's research limits.

```bash
make model-prepare
make model-audit
make model-download
make model-train
```

The second experiment adds CGT's manually assessed positive and negative SWC
properties, lexical clone grouping, exclusions against the original corpus,
balanced training, and property-level false-positive metrics. It is a separate
classification task, not a line-localization model or a safety certificate. See
[property experiment setup](docs/MODEL_PROPERTY_EXPERIMENT.md).

Sentinel is a local, defensive research prototype for Foundry projects. It combines static and symbolic candidates with an isolated exploit, repair, and verification loop. It never deploys contracts, uses wallets, or sends transactions to a public network.

## Current implementation status

Slither and Mythril are connected to Scout with JSON parsing, candidate ranking, analyzer diagnostics and a persisted JSON ledger. Four deliberately vulnerable fixtures have executable proof-of-concepts, repairs, and Forge regression gates: reentrancy, missing access control, `tx.origin` authorization, and unchecked low-level calls. Every scan copies the project to an isolated temporary workspace, so Sentinel writes a patch diff without changing the source project.

General PoC generation, benchmark-scale evaluation, and distributed storage remain future work. Real analyzer candidates that do not match the four reviewed fixture templates stop for human review rather than receiving an unrelated patch.

`make verification-audit` runs a separate offline evidence audit of those four
fixtures: meaningful fund-transfer regressions, before/after security assertions,
and 20 invalid-evidence rejection controls. Sources, tools, commands and outcomes
are saved without overwriting earlier runs. This checks the verification workflow,
not detector precision or general vulnerability coverage. See
[verification-first audit](docs/VERIFICATION_FIRST_AUDIT.md).

See [Scout setup and limitations](docs/SCOUT_INTEGRATION.md), [implementation plan](docs/IMPLEMENTATION_PLAN.md), and [requirement matrix](docs/REQUIREMENT_TRACEABILITY.md).

## Architecture

```mermaid
flowchart LR
    A[Foundry project] --> B[Scout: Perceive]
    B --> C[Slither + Mythril + solc context]
    C --> D[Gemini 1.5 Flash candidate]
    D --> E[Red Team: GPT-4o PoC]
    E --> F[Forge exploit validation]
    F -->|confirmed| G[Blue Team: DeepSeek-Coder-7B via Ollama]
    G --> H[Minimal Invasive Change]
    H --> I[Judge: forge build]
    I --> J[Exploit defense]
    J --> K[Original regression tests]
    K -->|failure, max 5| G
    K -->|pass| L[Markdown audit report]
```

The cognitive flow is **Perceive -> Reason -> Act -> Observe**:

- **Scout** combines static evidence and semantic context. It produces candidates only.
- **Red Team** creates an executable Foundry test. A finding becomes confirmed only when Forge proves the exploit in the local EVM.
- **Blue Team** proposes a targeted patch under the Minimal Invasive Change constraint.
- **Judge** is deterministic and is never an LLM. It requires build success, exploit neutralization, and regression success.

## Model integrations

The project retains the MPP1 model assignments: Gemini for Scout, GPT-4o for future general PoC synthesis, and DeepSeek-Coder through Ollama for future repair synthesis. All three provider transports are implemented behind `LLMProvider`; missing credentials or unavailable local Ollama instances fail as recorded workflow evidence. The current validated repair path intentionally uses reviewed deterministic templates for the two supplied fixtures rather than an unbounded model-generated patch.

## Quick start

Python 3.11+ is required. For a real run, install Foundry, Slither, Mythril, and the optional model clients. Copy `.env.example` to `.env` and configure credentials only when needed.

```bash
git clone https://github.com/sentinelcli38-pixel/sentinel-llm.git
cd sentinel-llm
python3 -m venv .venv
source .venv/bin/activate
pip install '.[dev,llm]'
sentinel scan ./examples/vulnerable_reentrancy --mock
sentinel scan ./examples/vulnerable_access_control --mock
sentinel scan ./examples/vulnerable_tx_origin --mock
sentinel scan ./examples/vulnerable_unchecked_call --mock
```

The command writes Markdown and JSON reports under `reports/`. `--mock` selects the deterministic Scout provider and enables clearly labeled fixture heuristics when external analyzers are unavailable; it does not fabricate Forge results. The original target source remains unchanged.

Read the report's **Pipeline Timeline** first. A candidate is only an initial signal. A final `verified` result requires a reviewed, unchanged exploit test passing before the patch and failing afterward, plus the same nonempty regression suite passing on both versions. Missing tools, empty test selections, compiler errors, skipped analysis, and mock runs cannot establish full security coverage. This verifies one proposed repair, not the safety of the entire contract. See [reliability boundaries](docs/RELIABILITY.md).

Use `--scout-only` for evidence collection without PoC or repair. Start the local dashboard and API with `make serve`, then open `http://127.0.0.1:8000`.

## Modern Solidity 0.8.x challenge corpus

Fetch supported public corpora through the pinned dataset registry. It leaves data outside Git and refuses to overwrite an existing checkout:

```bash
make list-datasets
make fetch-smartbugs-curated
make fetch-damn-vulnerable-defi
```

See [dataset guidance](docs/DATASETS.md) for each corpus's role, licensing boundary, and evaluation caveats.

`datasets/damn-vulnerable-defi` contains Damn Vulnerable DeFi, a Foundry-based corpus of realistic intentionally vulnerable DeFi challenges. Its source contracts use Solidity `0.8.25`, so install that compiler before running it:

```bash
solc-select install 0.8.25
solc-select use 0.8.25
# Confirm Foundry, Slither, and Mythril are installed and on PATH.
forge --version
slither --version
myth version
make test-damn-vulnerable-defi
make scan-damn-vulnerable-defi
```

`make test-damn-vulnerable-defi` compiles the corpus and is the health check for this repository integration. `make scan-damn-vulnerable-defi` runs Slither over the complete project and Mythril over one bounded source sample, then writes the Markdown report, raw ledger, and readable summary JSON under `reports/damn-vulnerable-defi/`. It can take about a minute; wait until the CLI prints `Audit report:` before looking for the files. The corpus's default challenge tests intentionally fail until each attack is solved; run them only with `make test-damn-vulnerable-defi-challenges` when you want to see that baseline:

```bash
make test-damn-vulnerable-defi-challenges
```

The make target creates the local compiler shim used by Foundry and Mythril from the compiler installed by `solc-select`; set `DVD_SOLC=/absolute/path/to/solc` if yours is elsewhere. Slither analyzes the project sources and excludes vendored `lib/` code from the audit report; Mythril symbolically analyzes the bounded source sample selected by `MYTHRIL_MAX_SOURCES` (default `10`). These are realistic multi-contract scenarios for detection and analysis; the four `examples/` projects remain the reviewed end-to-end PoC → patch → Judge demonstrations.

`--scout-only` is evidence collection only. It intentionally does **not** create `.patched.sol` or exploit-test files, because it does not enter Red Team, Blue Team, or Judge. Use one of the four supported end-to-end examples to produce a verified patch artifact:

```bash
make scan-reentrancy
make scan-access-control
make scan-tx-origin
make scan-unchecked-call
```

Use Google AI Studio to create a Gemini key, then add it to `.env` and select Gemini:

```bash
GOOGLE_API_KEY=your_key_here
LLM_PROVIDER=gemini
GEMINI_MODEL=gemini-2.5-flash
```

Then use the real-data agentic run to take the highest-ranked scanner candidate through Red Team, Blue Team, and Judge:

```bash
make run-damn-vulnerable-defi-agentic
```

This command uses the configured provider to draft a PoC for one scanner candidate. Model-generated PoCs are saved without execution and stop at `human_review_required`: passing a model-written assertion is not sufficient security evidence. Automated repairs currently support only the four reviewed fixture oracles. Proposed patches are retained as unverified artifacts when validation fails. Set `LLM_PROVIDER=openai` to use an API-funded OpenAI account, or `LLM_PROVIDER=ollama` to use a local Ollama model.

## Large-scale detection benchmark

FORGE Artifacts is the large-scale audit-derived corpus. Its raw source remains in the ignored `datasets/forge-artifacts/` checkout; Sentinel stores only its compact Solidity-0.8 benchmark manifest in version control.

```bash
make prepare-forge-artifacts
make benchmark-forge-artifacts
```

The resulting `datasets/manifests/forge-artifacts.json` contains a deterministic 500-project Solidity-0.8 subset with source roots, declared compiler versions, audit-derived CWE labels, and locations for evaluation. It is for detection metrics, not automatic patch verification: these standalone projects do not share a uniform Foundry test oracle. Damn Vulnerable DeFi and DeFiVulnLabs supply the separate executable PoC/patch verification corpus.

`make benchmark-forge-artifacts` runs a bounded 10-case smoke benchmark. Use `make benchmark-forge-artifacts-full` for all 500 cases; it can take hours. Reports record completed, skipped, timed-out, and detected cases. Precision and F1 are intentionally withheld until labeled clean controls are added.

## State ledger and safety

`RuntimeState` is a Pydantic, JSON-serializable state ledger. It records source files, AST/context placeholders, analyzer execution evidence, exploit/compiler/regression traces, patch attempts, feedback, retry history, verification, and report path.

The controlled runner accepts only `solc`, `slither`, `myth`, `aderyn`, `forge`, `cast`, and explicitly managed Docker invocations. It uses argument arrays, timeouts, validated working directories, and no `shell=True`. Generated tests and repairs are written only inside an ephemeral workspace copy. No mainnet deployment, private-key loading, arbitrary RPC target, real wallet, or LLM-generated shell command is supported.

## Five operational phases

1. Environment orchestration and state initialization through LangGraph.
2. Hybrid Semantic Scouting and Vulnerability Isolation.
3. Adversarial Exploit Synthesis and Validation.
4. Autonomous Structural Patch Synthesis.
5. Closed-Loop Verification and Self-Correction.

The Judge routes compiler, exploit-defense, and regression failures back to Blue Team and stops after five attempts with `human_review_required`.

## Examples and testing

The repository includes deliberately vulnerable local examples for reentrancy, missing access control, `tx.origin` authorization, and unchecked low-level calls. They are research fixtures only. Run unit/integration tests with:

```bash
python -m pytest
```

The GitHub Actions workflow runs Python, dashboard, and real Forge repair tests, then requires the reviewed reentrancy fixture workflow to verify. It explicitly asserts that this mock demonstration **cannot** pass the separate release gate. Demo reports and SARIF are uploaded as engineering evidence, not production security alerts.

## Evaluation and limitations

Latency, false-positive reduction, gas comparison, and the MPP1 five-minute/30-50% targets are measurements to collect, not claims made by this repository. Gas metrics are reported unavailable when Foundry does not provide a reliable comparison. The current implementation demonstrates isolated single-project workflows and four reviewed vulnerability classes. Cross-contract reasoning, generalized PoC generation, and broad benchmark coverage remain research extensions.

## Reproducible experiments and stronger validation

The [local 1.5B model guide](docs/SENTINEL_1_5B.md) covers the restored pinned Qwen weights, integrity checks, and experimental inference. Local runtime verification confirms 1,543,714,304 base parameters; Sentinel's saved LoRA adapter trains only a small added subset. The adapter remains unqualified and does not replace scanner evidence or the Forge Judge.

A subsequent [Boolean-decision training experiment](docs/BINARY_MODEL_EXPERIMENT.md) uses unique training contrasts, two-label loss and train/validation-only access. Its 64-step run also fails: the selected adapter predicts every validation case negative, misses all 22 positives, and merely matches the always-negative baseline. Precision is unavailable, not 100%; no 99% claim is supported. All checkpoints and failed outcomes are retained, reserved model tests remain sealed, and the product workflow is unchanged.

The [binary-model diagnostics](docs/BINARY_MODEL_DIAGNOSTICS.md) audit all saved predictions and checkpoints and run a bounded source-removal experiment. Overall descriptive ROC AUC falls from 0.681 to 0.608 after adaptation. Source removal changes scores but not the hard decisions in 15 sampled cases. These results identify unresolved behavior, not a corrected detector or proof of semantic reasoning; no thresholds, weights or labels are changed.

The [model-label review stage](docs/MODEL_LABEL_REVIEW.md) prepares all 54 validation cases for blinded review and a separate 64-case unchecked-call training packet with 32 candidate contrast pairs. Historical labels and predictions stay outside the blind folders. No human review, training improvement or 99% precision claim is implied; compiler/dependency context must still be established.

A fixed [frozen-model readout experiment](docs/FROZEN_MODEL_PROBE.md) tests property-specific logistic classifiers on the 1.5B base model's representations, alongside a training-only lexical control. It uses the same 200 training and 54 development cases, updates no base weights and does not replace missing independent label review or external validation.

The readout reaches 57.69% precision/68.18% recall on those 54 cases; the lexical control reaches 80.77%/95.45%. A [larger lexical-only check](docs/LEXICAL_SCALE_CONTROL.md) uses all 3,766 training and 821 validation assessments: 88.36% precision/71.27% recall overall, but zero recall on reentrancy and origin authorization. Lexical scores are not LLM performance, and none of these results establishes production qualification. The [99%-target audit](docs/PRECISION_TARGET_AUDIT.md) rejects every tested candidate and preserves all failed property outcomes; the requested target remains unmet.

The [provisional review experiment](docs/PROVISIONAL_REVIEW_EXPERIMENT.md) records the user's reported professor/resource-person approval with written reports pending, preserves AI authorship, and uses matching training decisions in a separate copied overlay. It compares fixed class-balanced historical/provisional controls without changing validation labels or the independent-human consensus gate. Unresolved review cases remain unknown, and no base weights or live detector behavior are changed.

All six provisional-review comparisons completed. The review overlay did not improve agreement with historical validation labels: frozen-Qwen readout precision is 50% versus its 57.69% control, and matched lexical precision is 64.52% versus 80.77%. Full-pool class balancing improves minority-property recall but loses substantial arithmetic recall and precision. All six fail the unchanged 99%-target audit; the experiments are retained, not deployed or presented as verified human-consensus results.

The [grouped precision experiment](docs/GROUPED_PRECISION_EXPERIMENT.md) adds richer lexical n-grams and a fixed linear-SVM candidate catalog. It selects models and operating thresholds exclusively from source-family-grouped training folds, freezes JSON models before validation access, retains every candidate and failed target, and requires at least 80% recall. This is a lexical development control, not improved 1.5B LLM performance or independent certification.

All 48 grouped candidates completed, but none met the training selection target. The four explicitly marked diagnostic fallback heads reach 60.39% precision and 51.38% recall on all 821 validation cases. Arithmetic precision is 96.15% with only 39.68% recall; reentrancy recall is 100% with only 26.42% precision. Both point-target and stronger 99% audits fail. Earlier better aggregate controls remain documented, no model is promoted, and the live detector is unchanged.

The [contract-scoped structural experiment](docs/STRUCTURAL_PRECISION_EXPERIMENT.md) adds an isolated pinned Solidity AST parser, named-target/in-file-base scope, syntactic call-result, authorization, arithmetic and state-write features, and fixed structural/scoped-lexical/combined controls. Selection remains training-only on the same grouped folds, extraction failures stay visible, every validation case is retained, and no semantic-proof, LLM-training or production-quality claim follows merely from these features.

The structural run retains three stopped pre-validation attempts and completes a numerically stabilized fourth protocol with all 72 candidates. Full validation is worse than the previous grouped lexical result: 43.72% precision and 48.07% recall on all 821 cases. Of these, 719 parse directly and 102 use explicit fallback. Origin authorization has five correct flags and no false flags, but misses six positives; that is not an achieved 99% result. All quality gates still fail and no model is promoted.

The [heldout-threshold kernel experiment](docs/HELDOUT_KERNEL_EXPERIMENT.md) tests a different nonlinear similarity model and separates model fitting from final threshold choice. It freezes the selected model before scoring a distinct training threshold pool and never refits it afterward, retains every candidate and evaluation case, and audits the sample support needed for the existing 99% interval rule. It is a development control, not a guaranteed improvement, new LLM result or independent certification.

The kernel run completes all 16 candidates and reaches 48.54% precision/55.25% recall on all 821 validation cases, compared with the latest structural run's 43.72%/48.07%. This still fails the requested 99% point target. A separate support audit shows that even perfect detection of all 181 labelled positives could only yield a 97.92% nominal 95% lower precision bound; the existing stronger 99% evidence rule needs more independent positive support. Neither the target nor labels are changed, and no model is promoted.

`sentinel benchmark` runs a declared experiment manifest with baseline and ablation profiles. It records per-case outcomes, label-aware detection metrics, confirmation and validated-repair rates, retries, duration, coverage, and configuration metadata. The four checked-in fixtures are an engineering check only; do not use them as evidence of held-out generalization.

```bash
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile scout-union --mock
sentinel benchmark datasets/manifests/sentinel-evaluation.example.json --profile sentinel-full --mock
```

Projects can add `sentinel-validation.yml` to require positive and security Forge tests plus declared ABI and storage compatibility checks before the Validator accepts a repair. See [experiment workflow](docs/EXPERIMENTS.md) for the manifest format, profiles, metrics, and research-claim boundary.

The [scanner validation workflow](docs/SCANNER_VALIDATION.md) evaluates unused CGT validation components with frozen sources, pinned compilers, contract attribution, and explicit qualification thresholds. Its eight-case development pilot does **not** pass qualification; the model's reserved test set remains untouched.

An opt-in `sentinel-static` experiment adds Slither-based dead-call-result and direct origin-authorization checks. A 27-case expanded development comparison improves detected positives from 5/12 to 7/12, with the same 2/15 false positives. Neither profile is qualified; these cases were used for detector development, not held-out evaluation. See [discrepancy review](docs/SCANNER_TRIAGE.md); the standard Slither baseline and default scans are unchanged.

A [frozen, disjoint 120-case CGT replication](docs/SCANNER_REPLICATION.md) of the earlier extension showed identical baseline and extended predictions: precision 88.89%, recall 66.67%, and five false positives. That development-set improvement did not yield additional detections on this set. Both profiles failed qualification because reentrancy and unchecked-call recall fell below the required threshold. This is same-corpus scanner evidence, not a qualified model or a zero-day claim.

The subsequent [inheritance-aware extension](docs/SCANNER_INHERITANCE.md) preserves declaration locations while attributing effective inherited entry points to their compiled execution contracts. A separately frozen development reanalysis of the same 120 cases detects 43/60 labelled positives instead of 40/60, with the same 5/60 false-positive cases: precision 89.58%, recall 71.67%, F1 79.63%. All cases complete, but qualification still fails. Because these cases informed this change, they are development data for this version, not independent validation. The extension remains opt-in; default scans are unchanged.

A [fresh 85-case same-corpus follow-up](docs/SCANNER_FRESH_VALIDATION.md) excludes every earlier scanner component and keeps the detector fixed. The extension detects 18/25 labelled positives versus 17/25 for Slither, but adds a false-positive case (9/60 versus 8/60). Recall rises from 68% to 72%, while precision falls from 68% to 66.67%. The extra positive comes from the existing dead-result check; the new inherited case is a false positive under the preserved assessment. Both profiles fail qualification on underfilled positive buckets and accuracy requirements. This does not establish an inheritance-specific generalization benefit, external validation, or production readiness.

The [human label-review workflow](docs/LABEL_REVIEW.md) provides blinded forms, source evidence, and consensus acceptance into new manifests without rewriting original labels. Actual expert sign-off remains pending. The original [FORGE-Curated external pilot](docs/EXTERNAL_BENCHMARK.md) completed both profiles on one target, retaining two missing-dependency failures. The subsequent [locked dependency expansion](docs/LOCKED_EXTERNAL_BENCHMARK.md) verifies authoritative Morpheus dependency archives and completes both profiles on OracleLess and DepositPool. sBOLD remains blocked without verified historical dependency versions. External labels remain unknown, so no accuracy is claimed. Detector rules are unchanged.

An opt-in [precision-first evidence triage experiment](docs/PRECISION_TRIAGE.md) retrospectively prioritizes unchecked-call candidates corroborated at the same compiler node by the existing Slither and SSA checks. It preserves all warnings, labels and original metrics, and counts deferred positives as missed in priority recall. On the 85-case development follow-up, the queue has 9 true-positive cases and no labeled false positives (100% observed precision, 36% overall recall); on the earlier 120 cases it has 10 true positives and one false positive (90.91%, 16.67% recall). Within unchecked calls, corroboration does not improve precision or recall. These are correlated checks and small, reused datasets, not an achieved 99% claim. Confidence intervals, per-property denominators, review queues and reproducible input hashes are retained; default scans are unchanged.
