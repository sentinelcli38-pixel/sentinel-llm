# External Benchmark Pilot

Historical v2 status: one external target completes both candidate-only profiles. **Human property labels remain pending; precision, recall, and F1 are unmeasured.** This is build/analysis feasibility, not a completed expert-labelled accuracy benchmark or release qualification. No detector tuning occurred. The subsequent [locked expansion](LOCKED_EXTERNAL_BENCHMARK.md) enables Morpheus as a second target under a separate v3 manifest; the original v2 evidence below is preserved.

## Corpus And Scope

The source is [FORGE-Curated](https://github.com/shenyimings/FORGE-Curated), pinned at `31923807289517fc4a7dba40c24f6185692c6e7b`. Its documentation describes audit-derived findings, ongoing location verification, and possible differences between stored source and audited upstream commits. Consequently, neither CWE tags nor audit omission become accepted positive/negative SWC labels here. Compiler compatibility does not verify the audited revision.

The reviewed registry is `benchmarks/forge-curated-pilot.json`. Three candidate targets were selected for a bounded, compiler-compatible reentrancy pilot, not a representative sample. Their provided target bytes must equal both pinned Git objects and the flattened vulnerability-file pair. Metadata and annotations are retained verbatim in ignored artifacts; their interpretation needs human review. An unrelated ERC-20 return-value finding was not converted into a low-level-call label.

Lexical clone screening includes all original SmartBugs sources, all five earlier scanner manifests, and actual fitted CGT train/validation sources. It uses existing normalized five-token shingle connected components at Jaccard 0.85. The audit covered 521 source entries; none of the three candidate target files joined a prior component. This is target-file lexical screening, not proof of semantic independence, complete project novelty, or absence from pretraining. Reserved prepared model test files were not opened, and no model inference was performed.

## Local Results

| Target | Preparation Outcome |
| --- | --- |
| OracleLess, Oku order types | Runnable: 17 compiler-selected target/dependency files |
| DepositPool, Morpheus | Blocked: missing provided OpenZeppelin/Solarity dependencies |
| sBold, K3 | Blocked: missing provided OpenZeppelin dependencies |

The two blocked candidates and full compiler diagnostics remain in `datasets/external-forge-curated-v2/readiness.json`. They are not counted as clean cases, successful scans, or detection misses. No dependency stubs, guessed package versions, or rewritten contracts were introduced. Completing these projects requires authoritative audited dependency versions before a new frozen run.

The first v1 attempt copied all 33 Oku snapshot files after a successful target compile. Both scanner profiles failed because Forge also tried to compile an unrelated `Bracket` implementation that hit stack depth limits. Those failed manifests/reports are preserved in `datasets/external-forge-curated-v1` and `reports/experiments/external-forge-curated-v1`. The v1 workflow archive matches its original hash at `reports/protocol-snapshots/external-pilot-v1/scripts/external_benchmark.py`.

The v2 correction uses Solidity's native `sourceList` from target compilation with AST output, preserving exactly the 17-file transitive closure. The other 16 snapshot files remain untouched upstream and are explicitly listed as omitted non-dependencies. This is narrower target-context analysis, **not full DApp coverage**, and it does not establish safety of cross-project interactions.

Both profiles completed the one unlabelled target locally on October 14, 2026. Each recorded six mapped reentrancy candidates attributed to `OracleLess`; these are not accepted true positives, defect-localization successes, or exploit confirmations. No labelled cases were scored, so accuracy fields remain null and both qualification gates fail. There are no reviewed negative controls and far too few cases for the existing 20-positive/20-negative/property requirement even after a label is accepted.

Evidence under `reports/experiments/external-forge-curated-v2`:

- Baseline: `sentinel-experiment-slither-20261014T033831647442Z.json`.
- Extension: `sentinel-experiment-sentinel-static-20261014T033929559223Z.json`.
- Shared manifest SHA-256: `14fa3c050d1d752ab362f96a5dc7451db5574fca04a23c4961ffc0fc0afb92a1`.

Sentinel's 65 implementation-file hashes are unchanged from the inheritance development/fresh runs. This phase changes only external preparation and review tooling. No RPC, wallet, deployment, generated exploit, repair, or model training/evaluation was used.

## Reproduce

Obtain the pinned corpus in `datasets/forge-curated` with a sparse checkout of `dataset-curated/findings`, `models`, `flatten/vfp-vuln`, and the three `project_root` paths in the registry. Fetch and check out the exact revision above before preparing, rather than assuming the current default branch is identical. Existing datasets are not replaced. The sources retain individual licenses; the corpus license does not blanket-license every imported contract.

With the existing fitted/source exclusions and local compiler/tools available:

```bash
make prepare-external-pilot
make validate-external-pilot
make validate-external-pilot-static
make prepare-external-review
```

Run profiles separately: unsuccessful qualification saves evidence and exits 2. Preparation/review packets refuse to overwrite existing outputs. A new corpus, source, build-scope, workflow, or detector version needs a new output directory/protocol, not replacement of previous pins.

Use `scripts/external_benchmark.py run` (the Make targets do), not the plain benchmark CLI for this dataset: the wrapper rechecks **every dependency source and generated Foundry configuration** plus the exact source inventory before each scan. The ordinary runner still checks target source, compiler, Sentinel/runtime pins, and profile restrictions. Workflow source changes are also rejected. A dependency changed after preparation cannot silently enter an external score.

See [human review](LABEL_REVIEW.md) for the two blinded forms, full target/dependency context, unknown-label handling, and acceptance into a new manifest. The strict paired-accuracy checker intentionally rejects unlabelled cases; do not bypass that restriction to publish these pilot warnings as accuracy.
