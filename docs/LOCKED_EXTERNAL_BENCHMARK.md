# Locked External Expansion

Status: both candidate-only profiles now complete two external targets. The formerly blocked Morpheus build is resolved. **Human labels remain unknown; no accuracy or production qualification is claimed.** Neither detector rules nor default scans changed.

## Provenance

The Morpheus snapshot's 99 Solidity files exactly match the metadata-referenced upstream commit `091b6f7ecbb2933c9d1a805bd4e4c926a02f38a6`. Its `package-lock.json` and `hardhat.config.ts` also match pinned Git objects and reviewed SHA-256 values. This establishes correspondence to that commit, not independent confirmation that the extracted audit metadata names the correct audited revision; that still belongs in human reconciliation.

The audited-commit lock pins these dependency sources:

| Package | Locked Version |
| --- | --- |
| @openzeppelin/contracts | 4.9.2 |
| @openzeppelin/contracts-upgradeable | 4.9.2 |
| @solarity/solidity-lib | 2.5.9 |

The loader uses exact package records, archive URLs, and SHA-512 integrity strings, rather than resolving version ranges. These fields are defined in the [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/#packages). Integrity establishes agreement with the recorded archive, not the absence of dependency vulnerabilities or a recommendation to use historical versions in production.

Only Solidity files, package metadata, and license files are retained. No npm install, package script, Hardhat configuration execution, key loading, RPC, or deployment occurs. HTTPS registry targets and redirects are restricted; corrupted archives, path traversal, duplicate entries, links, devices, sparse entries, and excessive sizes are rejected. Failed staging leaves no partial final dependency directory.

The dependency receipt itself is pinned in `benchmarks/morpheus-locked-pilot.json`, and source/license inventories are rechecked before preparation. Source files from the FORGE snapshot and upstream commit must agree byte-for-byte. Compiler-derived `sourceList` selects the exact closure, rather than hand-written Solidity import parsing or dependency stubs.

Compiler settings were manually reviewed in the pinned upstream configuration: Solidity 0.8.20, optimizer enabled with 200 runs, and Paris EVM. The generated Foundry configuration declares those values and explicit import remappings, and is hash-checked by the existing external runner. These are target-analysis settings, not deployment instructions.

## Measurements

Both profiles completed locally on October 14, 2026, with no incomplete cases or analyzer failures:

| Target | Pinned Solidity Files | Mapped Reentrancy Candidates, Each Profile |
| --- | ---: | ---: |
| OracleLess | 17 | 6 |
| DepositPool | 26 | 22 |

OracleLess is reused unchanged from v2, with its original source/configuration pins and unknown label. This is one newly enabled case, not two new independent observations. The warning counts are not distinct confirmed vulnerabilities, accepted true positives, or exact matches to the audited issue. Both reports evaluate zero labelled cases; precision, recall, and F1 are null, and qualification fails. The set has no reviewed negative controls and is far below the existing minimum sample counts.

The sBOLD metadata-referenced commit `e52e34078faa2238846a637cbf6263396e7363e6` has no committed root lockfile and declares dependency ranges, including OpenZeppelin `^5.0.2`. We did not guess the installed historical versions or generate a replacement lock and call it authoritative. It remains blocked pending verified dependency evidence. Earlier failures, manifests, reports, and review packets remain preserved.

Evidence:

- Dependency receipt: `datasets/morpheus-locked-deps-v1/receipt.json`, SHA-256 `0cc28fbb5981ac948a6f858e8216af8c852639f82763d2cad41db4e7639663a9`.
- New manifest: `datasets/external-forge-curated-v3/manifest.json`, SHA-256 `3b4992ec94c1a6362a72c398a2ec4d735b6326fa95b3db716d9a66e76c60f9d9`.
- Baseline report: `reports/experiments/external-forge-curated-v3/sentinel-experiment-slither-20261014T041458042890Z.json`.
- Extension report: `reports/experiments/external-forge-curated-v3/sentinel-experiment-sentinel-static-20261014T041629048651Z.json`.
- Updated blinded forms and dependency context: `reports/label-review/external-v3/blind`.

The Sentinel runtime hashes and external run workflow remain unchanged. The new preparation recipe and receipt record their own workflow hashes. Lexical exclusions remain in place; no reserved prepared model test files or model inference were used. Benchmark runs did not enter exploitation or repair stages; the verification suite still exercises pre-existing reviewed local fixtures.

## Reproduce

First obtain the upstream Morpheus checkout at the exact metadata-referenced commit, including root lock/config files and `contracts/`. Preserve the pinned FORGE corpus, fitted-source metadata, and prior scanner exclusions. Then:

```bash
make stage-morpheus-dependencies
make prepare-locked-external-pilot
make validate-locked-external-pilot
make validate-locked-external-pilot-static
make prepare-locked-external-review
```

Run profiles separately: unsuccessful qualification saves reports and exits 2. Staging, preparation, and review packets refuse to overwrite existing artifacts. A changed recipe, dependency archive, receipt, configuration, or source requires a new reviewed pin and output directory. The guarded runner rechecks the exact source inventory and every dependency/configuration hash before scanning.

Use the [human review workflow](LABEL_REVIEW.md) to obtain genuine independent decisions and preserve disagreements as unknown. Two declarations in JSON are not authenticated expert credentials. Until the human forms are actually completed and enough positive/negative cases are available, further detector tuning or a qualified external accuracy claim would be premature.
