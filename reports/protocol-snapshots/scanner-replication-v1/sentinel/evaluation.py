"""Bounded development evaluation using frozen, property-specific CGT labels."""

import hashlib
import json
import random
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from sentinel.modeling.data import strip_comments
from sentinel.modeling.properties import CGT_REVISION
from sentinel.runner import ControlledRunner

SCANNER_PROPERTIES = {"104": "unchecked_low_level_calls", "107": "reentrancy", "115": "tx_origin"}


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def prepare_scanner_validation(
    corpus: Path, prepared: Path, fitted: Path, output: Path, compilers: list[Path],
    *, per_bucket: int = 2, seed: int = 83, max_bytes: int = 32_000,
    allow_multiple_contracts: bool = False,
    candidate_split: Literal["train", "valid"] = "valid",
    exclude_manifests: list[Path] | None = None,
    frozen_protocol: dict | None = None,
    runner: ControlledRunner | None = None,
) -> Path:
    """Never open test.jsonl; exclude fitted and declared prior scanner components."""
    if output.exists():
        raise ValueError("Output already exists; preserve the frozen evaluation and choose a new directory")
    if per_bucket < 1 or max_bytes < 1 or not compilers:
        raise ValueError("Positive sampling bounds and installed compilers are required")
    if candidate_split not in {"train", "valid"}:
        raise ValueError("Only train/valid candidate pools are allowed; reserved test is sealed")
    if frozen_protocol is not None and not exclude_manifests:
        raise ValueError("Frozen replication requires prior evaluation exclusions")
    manifest = json.loads((prepared / "manifest.json").read_text())
    valid_path = prepared / f"{candidate_split}.jsonl"
    valid_sha = hashlib.sha256(valid_path.read_bytes()).hexdigest()
    if manifest["source_revision"] != CGT_REVISION or manifest["split_sha256"][candidate_split] != valid_sha:
        raise ValueError("Prepared candidate data differs from the pinned CGT experiment")
    revision = subprocess.run(["git", "-C", str(corpus), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if revision != CGT_REVISION:
        raise ValueError("CGT checkout revision differs from the reviewed data")
    seen = set()
    fitted_sources = set()
    fitted_sha = {}
    for name in ("train", "valid"):
        path = fitted / f"{name}.jsonl"
        fitted_sha[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        fitted_rows = read_rows(path)
        seen.update(row["project_group"] for row in fitted_rows)
        fitted_sources.update(row["source_hash"] for row in fitted_rows if row.get("source_hash"))
    excluded_groups, excluded_sources, exclusion_records = set(), set(), []
    for path in exclude_manifests or []:
        raw_manifest = path.read_bytes()
        previous = json.loads(raw_manifest)
        if not previous.get("cases"):
            raise ValueError("Exclusion manifest must contain assessed cases")
        for case in previous["cases"]:
            component = case.get("provenance", {}).get("clone_component")
            source_hash = case.get("source_sha256")
            if (not isinstance(component, str) or not component or not isinstance(source_hash, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", source_hash)):
                raise ValueError("Exclusion case requires a clone component and source hash")
            excluded_groups.add(component)
            excluded_sources.add(source_hash)
        exclusion_records.append({"path": str(path.resolve()), "sha256": hashlib.sha256(raw_manifest).hexdigest(),
                                  "cases": len(previous["cases"])})
    rows = read_rows(valid_path)
    buckets = defaultdict(list)
    skipped = Counter()
    for row in rows:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,76}", row["id"]):
            raise ValueError("Dataset case ID is not a safe identifier")
        if row["project_group"] in seen or row.get("source_hash") in fitted_sources:
            skipped["model_training_or_validation_component"] += 1
            continue
        if row["project_group"] in excluded_groups:
            skipped["prior_scanner_evaluation_component"] += 1
            continue
        if row["swc"] not in SCANNER_PROPERTIES:
            skipped["property_not_supported_by_slither_mapping"] += 1
            continue
        target = json.loads(row["messages"][-1]["content"])
        if target.get("swc") != row["swc"] or type(target.get("vulnerable")) is not bool:
            raise ValueError("Malformed property label")
        buckets[f"{row['swc']}:{str(target['vulnerable']).lower()}"].append(row)
    controlled = runner or ControlledRunner(timeout_seconds=10)
    compiler_records = []
    for compiler in compilers:
        compiler = compiler.resolve()
        version = controlled.run([str(compiler), "--version"], corpus)
        if not version.success:
            raise ValueError(f"Compiler unavailable: {compiler}")
        compiler_records.append({"path": str(compiler), "sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(), "version": version.stdout.strip()})
    rng = random.Random(seed)
    selected, selected_groups = [], set()
    selected_sources = set()
    for bucket in sorted(buckets, key=lambda key: (len(buckets[key]), key)):
        candidates = sorted(buckets[bucket], key=lambda row: row["id"])
        rng.shuffle(candidates)
        count = 0
        for row in candidates:
            if count >= per_bucket:
                break
            if row["project_group"] in selected_groups:
                skipped["duplicate_evaluation_component"] += 1
                continue
            source_path = (corpus / row["source_path"]).resolve()
            if not source_path.is_relative_to(corpus.resolve()):
                raise ValueError("CGT source escapes dataset")
            raw = source_path.read_bytes()
            raw_sha = hashlib.sha256(raw).hexdigest()
            if raw_sha in excluded_sources:
                skipped["prior_scanner_evaluation_source"] += 1
                continue
            if raw_sha in selected_sources:
                skipped["duplicate_evaluation_source"] += 1
                continue
            source = strip_comments(raw.decode("utf-8"))
            if hashlib.sha256(source.encode()).hexdigest() != row["source_hash"]:
                raise ValueError("CGT source differs from its frozen assessed source")
            if len(raw) > max_bytes or re.search(r"\bimport\b", source) or not re.search(r"\bpragma\s+solidity\b", source):
                skipped["large_imported_or_unversioned_source"] += 1
                continue
            chosen = None
            with tempfile.TemporaryDirectory(prefix="sentinel-case-build-") as directory:
                root = Path(directory)
                (root / "Case.sol").write_bytes(raw)
                for compiler in compiler_records:
                    result = controlled.run([compiler["path"], "--combined-json", "abi,bin", "Case.sol"], root)
                    if not result.success or result.timed_out:
                        continue
                    try:
                        contracts = json.loads(result.stdout)["contracts"]
                        deployable = {name.rsplit(":", 1)[-1] for name, item in contracts.items() if item.get("bin")}
                    except (ValueError, TypeError, KeyError, AttributeError):
                        continue
                    # Expanded runs may include other contracts, but scoring must
                    # still match the explicit assessed contract and file.
                    if row["contract"] in deployable and (allow_multiple_contracts or deployable == {row["contract"]}):
                        chosen = compiler
                        break
            if chosen is None:
                skipped["no_compatible_single_target_build"] += 1
                continue
            selected.append((row, bucket, raw, chosen))
            selected_groups.add(row["project_group"])
            selected_sources.add(raw_sha)
            count += 1
    if not selected:
        raise ValueError(f"No eligible cases: {dict(skipped)}")
    output.mkdir(parents=True)
    cases = []
    for row, bucket, raw, compiler in selected:
        case_id = f"cgt-{row['id']}"
        project = output / "projects" / case_id
        (project / "src").mkdir(parents=True)
        (project / "src/Case.sol").write_bytes(raw)
        (project / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nlibs = []\n'
            f'solc = {json.dumps(compiler["path"])}\n', encoding="utf-8")
        cases.append({
            "id": case_id, "project_path": f"projects/{case_id}", "group": "development",
            "vulnerability_class": SCANNER_PROPERTIES[row["swc"]],
            "ground_truth": "vulnerable" if bucket.endswith(":true") else "clean",
            "target_contract": row["contract"], "target_file": "src/Case.sol",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "provenance": {"dataset": "CGT", "revision": revision, "source_url": row["source_url"],
                           "swc": row["swc"], "clone_component": row["project_group"],
                           "assessments": row["assessments"], "compiler": compiler,
                           "negative_scope": "Only the assessed weakness is absent; not a globally safe contract."},
        })
    required = {f"{swc}:{value}" for swc in SCANNER_PROPERTIES for value in ("true", "false")}
    counts = Counter(bucket for _, bucket, _, _ in selected)
    document = {
        "name": "cgt-disjoint-scanner-replication" if frozen_protocol is not None else "cgt-unused-validation-scanner-pilot", "cases": cases,
        "provenance": {"dataset": "CGT", "revision": revision,
                       "candidate_split": candidate_split, "candidate_split_sha256": valid_sha,
                       **({"validation_sha256": valid_sha} if candidate_split == "valid" else {}),
                       "fitted_split_sha256": fitted_sha, "seed": seed, "requested_per_bucket": per_bucket,
                       "selected_per_bucket": dict(counts), "missing_buckets": sorted(required - set(counts)),
                       "allow_multiple_contracts": allow_multiple_contracts, "max_source_bytes": max_bytes,
                       "skipped": dict(skipped), "reserved_test_accessed": False,
                       "excluded_evaluations": exclusion_records,
                       "scope": "Scanner evaluation of unused CGT train/validation components; not a final held-out model result. Cases are distinct lexical components, not proven semantically independent.",
                       **({"scanner_protocol": frozen_protocol} if frozen_protocol is not None else {}),
                       "compilers": compiler_records},
    }
    path = output / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def qualification_gate(report: dict, *, minimum_per_label: int = 20, minimum_recall: float = 0.8, minimum_specificity: float = 0.8) -> dict:
    """Development thresholds only; a passing score is not release certification."""
    if minimum_per_label < 1 or not 0 <= minimum_recall <= 1 or not 0 <= minimum_specificity <= 1:
        raise ValueError("Invalid qualification thresholds")
    reasons = []
    if not report.get("cases") or any(not row.get("source_sha256") for row in report.get("cases", [])):
        reasons.append("Case sources are not all frozen with content hashes")
    if report["metric_scope"]["incomplete_labeled_cases"]:
        reasons.append("Some labeled cases have incomplete coverage or attribution")
    if report["metric_scope"]["unsupported_labeled_cases"]:
        reasons.append("Some labels are unsupported by the selected scanner profile")
    if report.get("dataset_provenance", {}).get("missing_buckets"):
        reasons.append("The dataset is missing required positive/negative property buckets")
    by_class = report["by_vulnerability_class"]
    if not by_class:
        reasons.append("No measured property classes")
    for category, item in by_class.items():
        metrics = item["metrics"]
        positives = metrics["true_positives"] + metrics["false_negatives"]
        negatives = metrics["true_negatives"] + metrics["false_positives"]
        specificity = metrics["true_negatives"] / negatives if negatives else None
        if positives < minimum_per_label or negatives < minimum_per_label:
            reasons.append(f"{category}: insufficient positive or negative cases")
        if metrics["recall"] is None or metrics["recall"] < minimum_recall:
            reasons.append(f"{category}: recall below threshold or unavailable")
        if specificity is None or specificity < minimum_specificity:
            reasons.append(f"{category}: specificity below threshold or unavailable")
    return {"passed": not reasons, "reasons": reasons,
            "thresholds": {"minimum_per_label_per_property": minimum_per_label, "minimum_recall": minimum_recall, "minimum_specificity": minimum_specificity},
            "scope": "Engineering development gate only; not an independent production or security certification."}
