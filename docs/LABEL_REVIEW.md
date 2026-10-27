# Human Label Review

Status: blinded packets and technical triage are prepared. **No signed independent-human consensus has been imported.** On October 23, 2026, the user reported that their professor and resource person approved the AI-assisted training reviews, with written reports pending, and authorized continuing development. That report is recorded in the separate [provisional review experiment](PROVISIONAL_REVIEW_EXPERIMENT.md), without changing reviewer identities or pretending to authenticate human credentials. Detector rules, original assessments, and earlier reports remain unchanged. AI source inspection is not independent human adjudication.

## Review Packets

The scanner packets are ready:

- `reports/label-review/fresh-v1/blind`: all 85 fresh CGT cases, not just the 16 disagreements between extended predictions and annotations.
- `reports/label-review/external-v3/blind`: external `OracleLess` and `DepositPool` targets, with their 17- and 26-file compiler-selected Solidity dependency contexts. Earlier v1/v2 packets remain historical artifacts; do not mix submissions from different packet hashes.

The separate [model review stage](MODEL_LABEL_REVIEW.md) also prepares all 54 binary validation cases and 64 unchecked-call training cases in distinct packets. Unlike the scanner packets, these contain exact model-visible sources without verified compilation or dependency closure. Use their frozen scope and [model reviewer instructions](MODEL_REVIEW_INSTRUCTIONS.md), and record unknown when context cannot be established.

Each has `cases.json`, numbered-source files with comments blanked in place, and separate `reviewer-a.json` / `reviewer-b.json` forms. Source lines stay aligned with the original evidence. Opaque review IDs replace original case IDs. Original labels, annotations, and scanner outcomes are excluded from the blind case list. Identifiers/code may still cue reviewers; this is limited procedural blinding, not perfect anonymization or access control.

Give each reviewer only the `blind` folder for an initial independent assessment. Keep `admin.json`, `original-manifest.json`, the scanner reports, and the technical triage outside that first pass. The original source's individual license still applies; these local review copies are not a blanket redistribution permission. Full unmodified sources remain in the pinned dataset.

## Property Rubric

Judge the named property in the stated target contract and compiled inheritance context, not whole-contract safety:

- Reentrancy: identify the external interaction, feasible callback context, affected invariant or behavioral ordering, and relevant state changes/guards. Distinguish funds/state effects, event-order patterns, read-only effects, unreachable callbacks, and trust assumptions. Missing `nonReentrant` alone does not establish a defect; its presence alone does not clear every cross-function path. The legacy [SWC-107 description](https://swcregistry.io/docs/SWC-107/) concerns undesirable interaction between unfinished invocations.
- Unchecked low-level calls: identify the success result and its actual handling, including SSA copies, failure restoration, propagation, and reverting calls. An unused ERC-20 Boolean and an unused low-level-call success flag are not automatically the same benchmark property. Keep the [SWC-104 scope](https://swcregistry.io/docs/SWC-104/) explicit.
- Origin authorization: determine whether `tx.origin` establishes the principal for a protected effect, including helper/data flow and preceding sender guards. Do not classify every occurrence as authorization or infer safety from one equality alone. Use [SWC-115](https://swcregistry.io/docs/SWC-115/) as the legacy label definition, not a comprehensive current security standard.

The registry itself warns that its contents are no longer actively maintained. This rubric defines compatibility with our existing labelled experiments; it does not assert that SWC covers all modern risks. Record broader or incompatible findings separately rather than silently changing the evaluated property.

## Complete The Forms

Each reviewer declares their real identifier, qualification, and independence. Set decisions to `vulnerable`, `clean`, or `unknown`, and supply a rationale. Positive/negative decisions require original-source evidence lines. `pending` is allowed for unfinished cases; absence of an issue in an audit or absence of a scanner warning is not a negative assessment. A negative conclusion needs a documented review of the relevant paths, not merely no findings.

After the initial blind pass, compare original annotations, primary audit evidence, and scanner candidates in a reconciliation session. Keep the initial submissions and make any revised submissions separate files. Disagreement or incomplete context remains `unknown`; a third reviewer can help reconciliation, but the script does not manufacture a tie-break. Do not assess only warning-disagreement cases and report the resulting denominator as an unbiased benchmark.

To accept two completed submissions into a **new** manifest:

```bash
.venv/bin/python scripts/label_review.py consensus reports/label-review/fresh-v1 \
  --reviewer-a COMPLETED_A.json --reviewer-b COMPLETED_B.json \
  --output datasets/scanner-human-reviewed-v1
```

Use `reports/label-review/external-v3` and a separate output directory for the current external packet. The untouched templates are intentionally rejected: they have no reviewer identities/qualifications or independence declarations. Never fabricate a reviewer to make this command pass.

Acceptance verifies packet/manifest/source hashes, target scope, dependency context where supplied, unique complete review IDs, bounded evidence lines, distinct named humans, and rationale. Only matching positive/negative decisions become labels. Pending, unknown, or conflicting decisions remain unknown. The original label is retained in provenance. Source/compiler/runtime pins are not relaxed, and original reports are never overwritten.

Reviewer declarations are **self-attested**, not authenticated identities or independently verified credentials. Retain the reviewers' actual signed approval or institutional record separately before describing the outcome as expert-reviewed research. JSON validation is an integrity check, not expert certification.

## Reproduce Preparation

```bash
make prepare-expert-review
make prepare-locked-external-review
```

Existing packets are preserved; preparation refuses to overwrite them. Read the separate `reports/label-review/fresh-v1/technical-triage.md` only after the initial blind pass. The [original external pilot](EXTERNAL_BENCHMARK.md) and [locked expansion](LOCKED_EXTERNAL_BENCHMARK.md) explain source correspondence, build limitations, and why accuracy is currently unmeasured.
