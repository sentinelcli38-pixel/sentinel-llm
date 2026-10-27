PYTHON ?= .venv/bin/python
MLX_PYTHON ?= .venv-mlx/bin/python
NODE ?= node
DVD_SOLC ?= $(HOME)/.solc-select/artifacts/solc-0.8.25/solc-0.8.25
FOUNDRY_BIN ?= $(HOME)/.foundry/bin
SECURITY_TOOLS_BIN ?= $(HOME)/.local/bin
SCANNER_SOLC_CURRENT ?= $(HOME)/.solc-select/artifacts/solc-0.8.20/solc-0.8.20
SCANNER_SOLC_LEGACY ?= $(HOME)/.solc-select/artifacts/solc-0.4.24/solc-0.4.24
SCANNER_DATA ?= datasets/scanner-validation
SCANNER_PER_BUCKET ?= 2
SCANNER_COMPILER_ROOT ?= $(HOME)/.solc-select/artifacts
SCANNER_EXPANDED_DATA ?= datasets/scanner-validation-expanded
SCANNER_STATIC_BINARY ?= $(CURDIR)/.venv/bin/sentinel-static
SCANNER_REPLICATION_DATA ?= datasets/scanner-replication-v1
SCANNER_REANALYSIS_DATA ?= datasets/scanner-inheritance-development
SCANNER_FRESH_DATA ?= datasets/scanner-inheritance-fresh-v1
SCANNER_FRESH_REPORTS ?= reports/experiments/scanner-inheritance-fresh-v1
EXTERNAL_PILOT_DATA ?= datasets/external-forge-curated-v2
EXTERNAL_PILOT_REPORTS ?= reports/experiments/external-forge-curated-v2
LOCKED_EXTERNAL_DATA ?= datasets/external-forge-curated-v3
LOCKED_EXTERNAL_REPORTS ?= reports/experiments/external-forge-curated-v3
PRECISION_MANIFEST ?= $(SCANNER_FRESH_DATA)/manifest.json
BINARY_RUN_OUTPUT ?= training/runs/mac-binary-v1
BINARY_DIAGNOSTIC_OUTPUT ?=
MODEL_REVIEW_OUTPUT ?= reports/label-review/binary-v1
FROZEN_PROBE_OUTPUT ?= training/runs/mac-frozen-probe-v1
LEXICAL_SCALE_OUTPUT ?= training/runs/mac-lexical-scale-v1
PRECISION_TARGET_OUTPUT ?=
PROVISIONAL_REVIEW_OUTPUT ?= training/runs/mac-provisional-review-v1
GROUPED_PRECISION_OUTPUT ?= training/runs/mac-grouped-precision-v1
STRUCTURAL_PRECISION_OUTPUT ?= training/runs/mac-structural-precision-v4
HELDOUT_KERNEL_OUTPUT ?= training/runs/mac-heldout-kernel-v1
VERIFICATION_AUDIT_OUTPUT ?= reports/verification/fixture-evidence-v3
VERIFICATION_EXTERNAL_REPORT ?=

install:
	$(PYTHON) -m pip install '.[dev,llm]'

.PHONY: verification-audit test-verification-audit
verification-audit:
	$(PYTHON) scripts/verification_audit.py --output "$(VERIFICATION_AUDIT_OUTPUT)" \
	  --forge "$(FOUNDRY_BIN)/forge" --solc "$(SCANNER_SOLC_CURRENT)" \
	  $(if $(VERIFICATION_EXTERNAL_REPORT),--external-report "$(VERIFICATION_EXTERNAL_REPORT)",)

test-verification-audit:
	$(PYTHON) -m pytest -q tests/unit/test_verification_audit.py tests/integration/test_offline_evidence_audit.py

test:
	$(PYTHON) -m pytest

test-dashboard:
	$(NODE) --test tests/frontend/dashboard.test.cjs

lint:
	$(PYTHON) -m ruff check sentinel tests

model-prepare:
	$(PYTHON) -m sentinel.cli model prepare

model-audit:
	$(PYTHON) -m sentinel.cli model audit datasets/model-training

model-download:
	$(MLX_PYTHON) training/run_mlx.py --prepare-only

model-local-status:
	$(PYTHON) training/local_model.py status

model-local-restore:
	$(MLX_PYTHON) training/local_model.py restore

model-local-smoke:
	$(MLX_PYTHON) training/local_model.py smoke --adapter training/runs/mac-properties/selected-adapter --experimental

model-train-binary:
	$(MLX_PYTHON) -u training/binary_mlx.py --output "$(BINARY_RUN_OUTPUT)"

model-diagnose-binary:
	@test -n "$(BINARY_DIAGNOSTIC_OUTPUT)" || (echo "Set BINARY_DIAGNOSTIC_OUTPUT to an unused JSON output path"; exit 1)
	$(PYTHON) training/diagnose_binary.py offline --run "$(BINARY_RUN_OUTPUT)" --output "$(BINARY_DIAGNOSTIC_OUTPUT)"

model-prepare-review:
	$(PYTHON) training/prepare_model_review.py --run "$(BINARY_RUN_OUTPUT)" --output "$(MODEL_REVIEW_OUTPUT)"

model-prepare-probe:
	$(PYTHON) training/frozen_probe.py prepare --run "$(BINARY_RUN_OUTPUT)" --output "$(FROZEN_PROBE_OUTPUT)"

model-extract-probe:
	$(MLX_PYTHON) -u training/frozen_probe.py extract --experimental --output "$(FROZEN_PROBE_OUTPUT)"

model-score-probe:
	$(MLX_PYTHON) training/frozen_probe.py score --experimental --output "$(FROZEN_PROBE_OUTPUT)"

model-prepare-lexical-scale:
	$(PYTHON) training/lexical_scale.py prepare --probe "$(FROZEN_PROBE_OUTPUT)" --output "$(LEXICAL_SCALE_OUTPUT)"

model-score-lexical-scale:
	$(MLX_PYTHON) -u training/lexical_scale.py score --experimental --output "$(LEXICAL_SCALE_OUTPUT)"

model-audit-precision-target:
	@test -n "$(PRECISION_TARGET_OUTPUT)" || (echo "Set PRECISION_TARGET_OUTPUT to an unused JSON output path"; exit 1)
	$(PYTHON) training/precision_target.py --probe "$(FROZEN_PROBE_OUTPUT)" --scale "$(LEXICAL_SCALE_OUTPUT)" --output "$(PRECISION_TARGET_OUTPUT)"

model-prepare-provisional-review:
	$(PYTHON) training/provisional_review.py prepare --experimental --probe "$(FROZEN_PROBE_OUTPUT)" --output "$(PROVISIONAL_REVIEW_OUTPUT)"

model-score-provisional-review:
	$(MLX_PYTHON) -u training/provisional_review.py score --experimental --output "$(PROVISIONAL_REVIEW_OUTPUT)"

model-prepare-grouped-precision:
	$(MLX_PYTHON) training/grouped_precision.py prepare --experimental --review "$(PROVISIONAL_REVIEW_OUTPUT)" --output "$(GROUPED_PRECISION_OUTPUT)"

model-fit-grouped-precision:
	$(MLX_PYTHON) -u training/grouped_precision.py fit --experimental --output "$(GROUPED_PRECISION_OUTPUT)"

model-evaluate-grouped-precision:
	$(MLX_PYTHON) training/grouped_precision.py evaluate --experimental --output "$(GROUPED_PRECISION_OUTPUT)"

test-grouped-precision-runtime:
	$(MLX_PYTHON) tests/model_runtime/test_grouped_precision_runtime.py -v

model-install-ast-parser:
	npm ci --prefix training/ast_features --ignore-scripts --no-audit --no-fund

model-prepare-structural-precision:
	$(MLX_PYTHON) training/structural_precision.py prepare --experimental --anchor "$(GROUPED_PRECISION_OUTPUT)" --output "$(STRUCTURAL_PRECISION_OUTPUT)"

model-fit-structural-precision:
	$(MLX_PYTHON) -u training/structural_precision.py fit --experimental --output "$(STRUCTURAL_PRECISION_OUTPUT)"

model-evaluate-structural-precision:
	$(MLX_PYTHON) training/structural_precision.py evaluate --experimental --output "$(STRUCTURAL_PRECISION_OUTPUT)"

test-structural-precision-runtime:
	$(MLX_PYTHON) tests/model_runtime/test_structural_precision_runtime.py -v

test-ast-features:
	$(NODE) --test tests/frontend/ast_features.test.cjs

model-prepare-heldout-kernel:
	$(MLX_PYTHON) training/heldout_kernel.py prepare --experimental --anchor "$(GROUPED_PRECISION_OUTPUT)" --output "$(HELDOUT_KERNEL_OUTPUT)"

model-fit-heldout-kernel:
	$(MLX_PYTHON) -u training/heldout_kernel.py fit --experimental --output "$(HELDOUT_KERNEL_OUTPUT)"

model-threshold-heldout-kernel:
	$(MLX_PYTHON) training/heldout_kernel.py threshold --experimental --output "$(HELDOUT_KERNEL_OUTPUT)"

model-evaluate-heldout-kernel:
	$(MLX_PYTHON) training/heldout_kernel.py evaluate --experimental --output "$(HELDOUT_KERNEL_OUTPUT)"

test-heldout-kernel-runtime:
	$(MLX_PYTHON) tests/model_runtime/test_heldout_kernel_runtime.py -v

model-train:
	$(MLX_PYTHON) -u training/run_mlx.py

model-evaluate-base:
	$(MLX_PYTHON) -u training/evaluate_mlx.py --output training/runs/base-predictions.jsonl

model-evaluate-adapter:
	$(MLX_PYTHON) -u training/evaluate_mlx.py --adapter training/runs/mac-pilot/adapter --output training/runs/adapter-predictions.jsonl

model-compare:
	$(PYTHON) training/compare_mlx.py

fetch-cgt:
	$(PYTHON) scripts/fetch_datasets.py cgt

model-prepare-properties:
	$(PYTHON) -m sentinel.cli model prepare-properties

model-audit-properties:
	$(PYTHON) -m sentinel.cli model audit datasets/model-properties

model-train-properties:
	$(MLX_PYTHON) -u training/run_mlx.py --config training/mac-properties.yaml --dataset datasets/model-properties

model-select-properties:
	$(PYTHON) training/select_checkpoint.py

model-validate-properties-base:
	$(MLX_PYTHON) -u training/evaluate_mlx.py --task swc_property --data datasets/model-properties-fit/valid.jsonl --output training/runs/mac-properties/base-valid.jsonl --max-tokens 64 --validation-gate

model-validate-properties-adapter:
	$(MLX_PYTHON) -u training/evaluate_mlx.py --task swc_property --data datasets/model-properties-fit/valid.jsonl --adapter training/runs/mac-properties/selected-adapter --output training/runs/mac-properties/adapter-valid.jsonl --max-tokens 64 --validation-gate

model-compare-properties:
	$(PYTHON) training/compare_mlx.py --task swc_property --split valid --data datasets/model-properties-fit --base training/runs/mac-properties/base-valid.jsonl --adapted training/runs/mac-properties/adapter-valid.jsonl --output training/runs/mac-properties/validation-comparison.json

prepare-scanner-validation:
	$(PYTHON) scripts/prepare_scanner_validation.py --compiler "$(SCANNER_SOLC_CURRENT)" --compiler "$(SCANNER_SOLC_LEGACY)" --output "$(SCANNER_DATA)" --per-bucket $(SCANNER_PER_BUCKET)

# A small pilot intentionally fails qualification; the complete report is retained.
validate-scanner:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_DATA)/manifest.json" --profile slither --output reports/experiments/scanner-validation --require-qualification

install-static:
	$(PYTHON) -m pip install -e '.[static]'

validate-scanner-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_DATA)/manifest.json" --profile sentinel-static --output reports/experiments/scanner-validation --require-qualification

prepare-scanner-expanded:
	$(PYTHON) scripts/prepare_scanner_validation.py --output "$(SCANNER_EXPANDED_DATA)" --per-bucket 5 --allow-multiple-contracts \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.8.20/solc-0.8.20" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.26/solc-0.4.26" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.24/solc-0.4.24" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.5.17/solc-0.5.17" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.6.12/solc-0.6.12" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.7.6/solc-0.7.6"

prepare-scanner-replication:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/prepare_scanner_validation.py \
	  --output "$(SCANNER_REPLICATION_DATA)" --candidate-split train --per-bucket 20 --seed 109 \
	  --exclude-manifest datasets/scanner-validation/manifest.json \
	  --exclude-manifest "$(SCANNER_EXPANDED_DATA)/manifest.json" \
	  --allow-multiple-contracts --freeze-protocol --static-binary "$(SCANNER_STATIC_BINARY)" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.8.20/solc-0.8.20" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.26/solc-0.4.26" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.24/solc-0.4.24" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.5.17/solc-0.5.17" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.6.12/solc-0.6.12" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.7.6/solc-0.7.6"

validate-scanner-replication:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_REPLICATION_DATA)/manifest.json" --profile slither --output reports/experiments/scanner-replication-v1 --require-qualification

validate-scanner-replication-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_REPLICATION_DATA)/manifest.json" --profile sentinel-static --output reports/experiments/scanner-replication-v1 --require-qualification

prepare-scanner-reanalysis:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/prepare_scanner_reanalysis.py "$(SCANNER_REPLICATION_DATA)/manifest.json" --output "$(SCANNER_REANALYSIS_DATA)" --static-binary "$(SCANNER_STATIC_BINARY)"

validate-scanner-reanalysis:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_REANALYSIS_DATA)/manifest.json" --profile slither --output reports/experiments/scanner-inheritance-development --require-qualification

validate-scanner-reanalysis-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_REANALYSIS_DATA)/manifest.json" --profile sentinel-static --output reports/experiments/scanner-inheritance-development --require-qualification

prepare-scanner-fresh:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/prepare_scanner_validation.py \
	  --output "$(SCANNER_FRESH_DATA)" --candidate-split train --per-bucket 20 --seed 211 \
	  --exclude-manifest "$(SCANNER_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_EXPANDED_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REPLICATION_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REANALYSIS_DATA)/manifest.json" \
	  --allow-multiple-contracts --freeze-protocol --static-binary "$(SCANNER_STATIC_BINARY)" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.8.20/solc-0.8.20" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.26/solc-0.4.26" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.4.24/solc-0.4.24" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.5.17/solc-0.5.17" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.6.12/solc-0.6.12" \
	  --compiler "$(SCANNER_COMPILER_ROOT)/solc-0.7.6/solc-0.7.6"

validate-scanner-fresh:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_FRESH_DATA)/manifest.json" --profile slither --output "$(SCANNER_FRESH_REPORTS)" --require-qualification

validate-scanner-fresh-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) -m sentinel.cli benchmark "$(SCANNER_FRESH_DATA)/manifest.json" --profile sentinel-static --output "$(SCANNER_FRESH_REPORTS)" --require-qualification

prepare-expert-review:
	$(PYTHON) scripts/label_review.py prepare "$(SCANNER_FRESH_DATA)/manifest.json" --output reports/label-review/fresh-v1

prepare-external-pilot:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/external_benchmark.py prepare \
	  --output "$(EXTERNAL_PILOT_DATA)" --compiler "$(SCANNER_SOLC_CURRENT)" --static-binary "$(SCANNER_STATIC_BINARY)" \
	  --exclude-manifest "$(SCANNER_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_EXPANDED_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REPLICATION_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REANALYSIS_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_FRESH_DATA)/manifest.json"

validate-external-pilot:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) scripts/external_benchmark.py run "$(EXTERNAL_PILOT_DATA)/manifest.json" --profile slither --output "$(EXTERNAL_PILOT_REPORTS)"

validate-external-pilot-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) scripts/external_benchmark.py run "$(EXTERNAL_PILOT_DATA)/manifest.json" --profile sentinel-static --output "$(EXTERNAL_PILOT_REPORTS)"

prepare-external-review:
	$(PYTHON) scripts/label_review.py prepare "$(EXTERNAL_PILOT_DATA)/manifest.json" --output reports/label-review/external-v2

stage-morpheus-dependencies:
	$(PYTHON) scripts/locked_solidity_deps.py

prepare-locked-external-pilot:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/prepare_locked_external.py \
	  --output "$(LOCKED_EXTERNAL_DATA)" --compiler "$(SCANNER_SOLC_CURRENT)" --static-binary "$(SCANNER_STATIC_BINARY)" \
	  --exclude-manifest "$(SCANNER_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_EXPANDED_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REPLICATION_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_REANALYSIS_DATA)/manifest.json" \
	  --exclude-manifest "$(SCANNER_FRESH_DATA)/manifest.json"

validate-locked-external-pilot:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) scripts/external_benchmark.py run "$(LOCKED_EXTERNAL_DATA)/manifest.json" --profile slither --output "$(LOCKED_EXTERNAL_REPORTS)"

validate-locked-external-pilot-static:
	PATH="$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" STATIC_BINARY="$(SCANNER_STATIC_BINARY)" COMMAND_TIMEOUT_SECONDS=30 $(PYTHON) scripts/external_benchmark.py run "$(LOCKED_EXTERNAL_DATA)/manifest.json" --profile sentinel-static --output "$(LOCKED_EXTERNAL_REPORTS)"

prepare-locked-external-review:
	$(PYTHON) scripts/label_review.py prepare "$(LOCKED_EXTERNAL_DATA)/manifest.json" --output reports/label-review/external-v3

precision-triage:
	@test -n "$(PRECISION_SCANNER_REPORT)" || (echo "Set PRECISION_SCANNER_REPORT to the saved sentinel-static experiment JSON"; exit 1)
	@test -n "$(PRECISION_TRIAGE_OUTPUT)" || (echo "Set PRECISION_TRIAGE_OUTPUT to an unused JSON output path"; exit 1)
	$(PYTHON) scripts/precision_triage.py --manifest "$(PRECISION_MANIFEST)" --report "$(PRECISION_SCANNER_REPORT)" --output "$(PRECISION_TRIAGE_OUTPUT)"

list-datasets:
	$(PYTHON) scripts/fetch_datasets.py --help

fetch-smartbugs-curated:
	$(PYTHON) scripts/fetch_datasets.py smartbugs-curated

fetch-damn-vulnerable-defi:
	$(PYTHON) scripts/fetch_datasets.py damn-vulnerable-defi

fetch-defi-vuln-labs:
	$(PYTHON) scripts/fetch_datasets.py defi-vuln-labs

fetch-forge-artifacts:
	$(PYTHON) scripts/fetch_datasets.py forge-artifacts

prepare-smartbugs-starter:
	$(PYTHON) scripts/prepare_smartbugs_cases.py

benchmark-smartbugs-starter: prepare-smartbugs-starter
	$(PYTHON) -m sentinel.cli benchmark datasets/manifests/smartbugs-curated-starter.local.json --profile slither --output reports/experiments/smartbugs-curated

serve:
	$(PYTHON) -m sentinel.api

scan-reentrancy:
	$(PYTHON) -m sentinel.cli scan ./examples/vulnerable_reentrancy --mock

scan-access-control:
	$(PYTHON) -m sentinel.cli scan ./examples/vulnerable_access_control --mock

scan-tx-origin:
	$(PYTHON) -m sentinel.cli scan ./examples/vulnerable_tx_origin --mock

scan-unchecked-call:
	$(PYTHON) -m sentinel.cli scan ./examples/vulnerable_unchecked_call --mock

prepare-damn-vulnerable-defi:
	@test -x "$(DVD_SOLC)" || (echo "Solidity 0.8.25 is required: run 'solc-select install 0.8.25 && solc-select use 0.8.25', or set DVD_SOLC=/path/to/solc"; exit 1)
	mkdir -p datasets/damn-vulnerable-defi/.sentinel-bin
	ln -sfn "$(DVD_SOLC)" datasets/damn-vulnerable-defi/.sentinel-bin/solc

test-damn-vulnerable-defi: prepare-damn-vulnerable-defi
	cd datasets/damn-vulnerable-defi && PATH="$$PWD/.sentinel-bin:$(FOUNDRY_BIN):$$PATH" forge build

# Damn Vulnerable DeFi intentionally ships unsolved challenge tests. This target
# demonstrates those expected failures; it is not a Sentinel health check.
test-damn-vulnerable-defi-challenges: prepare-damn-vulnerable-defi
	cd datasets/damn-vulnerable-defi && PATH="$$PWD/.sentinel-bin:$(FOUNDRY_BIN):$$PATH" forge test

scan-damn-vulnerable-defi: prepare-damn-vulnerable-defi
	PATH="$(CURDIR)/datasets/damn-vulnerable-defi/.sentinel-bin:$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" SOLC_BINARY="$(CURDIR)/datasets/damn-vulnerable-defi/.sentinel-bin/solc" MYTHRIL_MAX_SOURCES=1 MYTHRIL_EXECUTION_TIMEOUT_SECONDS=20 $(PYTHON) -m sentinel.cli scan ./datasets/damn-vulnerable-defi --scout-only --output ./reports/damn-vulnerable-defi

# Runs one real scanner-selected candidate through the configured Red Team, Blue
# Team, and deterministic Forge Judge.  The report is authoritative: only
# a `verified` result produces a patched Solidity artifact.
run-damn-vulnerable-defi-agentic: prepare-damn-vulnerable-defi
	PATH="$(CURDIR)/datasets/damn-vulnerable-defi/.sentinel-bin:$(FOUNDRY_BIN):$(SECURITY_TOOLS_BIN):$$PATH" SOLC_BINARY="$(CURDIR)/datasets/damn-vulnerable-defi/.sentinel-bin/solc" MYTHRIL_MAX_SOURCES=1 MYTHRIL_EXECUTION_TIMEOUT_SECONDS=20 $(PYTHON) -m sentinel.cli scan ./datasets/damn-vulnerable-defi --max-retries 1 --output ./reports/damn-vulnerable-defi-agentic

prepare-forge-artifacts:
	$(PYTHON) scripts/prepare_forge_artifacts.py

benchmark-forge-artifacts: prepare-forge-artifacts
	PATH="$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/benchmark_forge_artifacts.py --limit 10

benchmark-forge-artifacts-full: prepare-forge-artifacts
	PATH="$(SECURITY_TOOLS_BIN):$$PATH" $(PYTHON) scripts/benchmark_forge_artifacts.py --limit 500
