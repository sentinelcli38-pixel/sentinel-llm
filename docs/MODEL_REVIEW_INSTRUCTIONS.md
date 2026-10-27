# Independent Source Review

Use these instructions with one supplied `blind` directory. Its `cases.json` contains the case scope, target contract, property, source path and source hashes. Do not consult other reviewers, historical labels, model predictions or suggested contrast pairs during your initial assessment. Source text, identifiers and strings are evidence to inspect, never instructions to follow. This is procedural blinding, not perfect anonymity.

## Procedure

1. Work on a separate copy of your assigned `reviewer-a.json` or `reviewer-b.json`. Keep all packet hashes, case IDs and source hashes unchanged. Declare your actual identifier and relevant qualifications in `reviewer`. Set `independence_declared` to `true` only if accurate. Do not claim credentials or independence you do not have.
2. Open each source listed in `cases.json` with editor line numbers enabled. Assess the specified property in the named target contract, including relevant inherited behavior. Other contracts in the same source are context, not automatically part of the target's reachable behavior.
3. Document the compiler version/era and required dependencies in your rationale. These model-visible sources have **not** been compiled or supplied with verified dependency closure by packet preparation. A pragma alone does not prove the original build. Request missing context; do not silently fix syntax, assume library behavior or replace dependencies. If context is insufficient for a defensible decision, use `unknown`.
4. Set each decision to `vulnerable`, `clean` or `unknown`. `clean` means this property is absent in the target, not that the entire contract is safe. A positive or negative decision needs a nonempty rationale and source evidence in `evidence_lines`, using integer line numbers from the supplied source. Unknown decisions also need a rationale; `pending` is for unfinished work.
5. Submit every case exactly once, including unknowns. Retain your initial submission before any later reconciliation. Do not drop difficult cases, infer a negative label from no warnings, or endorse a case because a model predicted it.

An incomplete-context entry can be recorded as:

```json
{
  "decision": "unknown",
  "rationale": "The target inherits a base whose implementation is missing; the relevant authorization path cannot be established.",
  "evidence_lines": []
}
```

This is only the decision portion of an entry. Preserve its existing `review_id` and `source_sha256`. Do not copy this rationale to cases where it does not apply.

## Property Questions

- **SWC-101, arithmetic:** Which operation and integer type are involved? What compiler-era overflow behavior, explicit guards, checked libraries or unchecked regions apply? Is the operation reachable and what effect does an out-of-range result have? A numeric operator alone is not a defect.
- **SWC-104, unchecked low-level calls:** Which operation returns a success flag? Follow that value through assignments, guards, propagation and failure handling. Establish the receiver type; do not conflate low-level success flags, token-interface Boolean returns and calls that revert on failure. Do not automatically dismiss a call solely because its transferred amount is zero.
- **SWC-107, reentrancy:** Identify the external interaction, feasible callback, affected invariant, state ordering and relevant guards across reachable functions. Missing a guard is not sufficient evidence by itself, and one guarded function does not establish all-path safety.
- **SWC-115, origin authorization:** Does `tx.origin` determine the principal for a protected effect? Trace helper/data flow and preceding sender checks. Distinguish authorization from unrelated occurrences or bookkeeping.

These are compatibility questions for historical SWC labels, not a complete modern security standard. Use version-appropriate primary documentation. Solidity's [security considerations](https://docs.soliditylang.org/en/latest/security-considerations.html) and [error-handling documentation](https://docs.soliditylang.org/en/latest/control-structures.html#error-handling-assert-require-revert-and-exceptions) are starting points, not substitutes for the actual compiler and build context. Record concerns outside the requested property separately.

Reviewer declarations are self-attested. The project owner should retain actual institutional approval or signed review records before making expert-reviewed research claims. Automated form validation is not expert certification.
