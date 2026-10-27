"""Prepare and run a source-pinned external pilot with pending human assessments."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.evaluation import read_rows
from sentinel.experiments import ExperimentManifest, run_experiment
from sentinel.modeling.clones import clone_components
from sentinel.modeling.data import strip_comments
from sentinel.runner import ControlledRunner
from sentinel.scanner_protocol import scanner_protocol
from sentinel.service import run_scan


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError("Dataset path escapes its root")
    return path


def git_bytes(corpus: Path, revision: str, relative: str) -> bytes:
    return subprocess.run(["git", "-C", str(corpus), "show", f"{revision}:{relative}"],
                          check=True, capture_output=True).stdout


def known_sources(smartbugs: Path, fitted: Path, cgt: Path, exclusions: list[Path]) -> tuple[dict, list]:
    known, records = {}, []
    for path in sorted((smartbugs / "dataset").rglob("*.sol")):
        known[f"smartbugs:{path.relative_to(smartbugs)}"] = path.read_text()
    if not known:
        raise ValueError("Prior SmartBugs sources are required for overlap screening")
    for split in ("train", "valid"):
        path = fitted / f"{split}.jsonl"
        raw = path.read_bytes()
        records.append({"path": str(path.resolve()), "sha256": sha(raw), "scope": "actual fitted subset"})
        for row in read_rows(path):
            source = inside(cgt, row["source_path"]).read_text()
            if sha(strip_comments(source).encode()) != row["source_hash"]:
                raise ValueError("Fitted source differs from its frozen metadata")
            known[f"fitted:{row['source_path']}"] = source
    if not exclusions:
        raise ValueError("Prior scanner manifests are required")
    for path in exclusions:
        raw = path.read_bytes()
        manifest = ExperimentManifest.model_validate_json(raw)
        records.append({"path": str(path.resolve()), "sha256": sha(raw), "scope": "prior scanner cases"})
        for case in manifest.cases:
            if not case.target_file or not case.source_sha256:
                raise ValueError("Exclusion cases require source pins")
            project = (path.parent / case.project_path).resolve()
            source_path = inside(project, case.target_file)
            content = source_path.read_bytes()
            if sha(content) != case.source_sha256:
                raise ValueError("Prior scanner source pin differs")
            known[f"scanner:{sha(content)}"] = content.decode()
    return known, records


def verify_project(project: Path, pins: dict) -> None:
    if not pins or "foundry.toml" not in pins:
        raise ValueError("External projects require source and configuration pins")
    actual = {str(path.relative_to(project)) for path in project.rglob("*.sol") if path.is_file()}
    if actual != {name for name in pins if name.endswith(".sol")}:
        raise ValueError("External Solidity source inventory changed")
    for name, digest in pins.items():
        if sha(inside(project, name).read_bytes()) != digest:
            raise ValueError(f"External source/configuration pin differs: {name}")


def prepare(registry: Path, corpus: Path, output: Path, compilers: list[Path], *, smartbugs: Path,
            fitted: Path, cgt: Path, exclusions: list[Path], protocol: dict, runner=None) -> Path:
    if output.exists():
        raise ValueError("External pilot already exists; preserve the frozen artifacts")
    corpus = corpus.resolve()
    raw_registry = registry.read_bytes()
    selection = json.loads(raw_registry)
    revision = subprocess.run(["git", "-C", str(corpus), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    if revision != selection["revision"]:
        raise ValueError("External corpus revision differs from reviewed registry")
    known, exclusions_record = known_sources(smartbugs, fitted, cgt, exclusions)
    targets = {}
    metadata = {}
    for case in selection["cases"]:
        project = inside(corpus, case["project_root"])
        target = inside(project, case["target_file"])
        vfp_bytes = inside(corpus, case["vfp"]).read_bytes()
        metadata_bytes = inside(corpus, case["metadata"]).read_bytes()
        for name, raw in ((str(target.relative_to(corpus)), target.read_bytes()),
                          (case["vfp"], vfp_bytes), (case["metadata"], metadata_bytes)):
            if raw != git_bytes(corpus, revision, name):
                raise ValueError("External source/annotation differs from pinned Git object")
        vfp, audit = json.loads(vfp_bytes), json.loads(metadata_bytes)
        finding = next(item for item in vfp["findings"] if item["id"] == case["finding_id"])
        if not any(Path(name).name == target.name for name in finding["files"]):
            raise ValueError("Selected finding does not identify the target source")
        if vfp["affected_files"].get(target.name) != target.read_text():
            raise ValueError("External snapshot does not match the annotated VFP source")
        targets[case["id"]] = target.read_text()
        metadata[case["id"]] = {"finding": finding, "project_info": audit["project_info"],
                                 "audit_report": audit["path"], "vfp_sha256": sha(vfp_bytes),
                                 "audit_metadata_sha256": sha(metadata_bytes)}
    components, audit = clone_components({**known, **targets}, {})
    prior_components = {components[key] for key in known}
    controlled = runner or ControlledRunner(timeout_seconds=30)
    compiler_pins = []
    for path in compilers:
        path = path.resolve()
        result = controlled.run([str(path), "--version"], corpus)
        if not result.success:
            raise ValueError("Installed compiler is unavailable")
        compiler_pins.append({"path": str(path), "sha256": sha(path.read_bytes()), "version": result.stdout.strip()})
    output.mkdir(parents=True)
    cases, readiness = [], []
    for item in selection["cases"]:
        record = {"case_id": item["id"], "target_contract": item["target_contract"], "status": "blocked", "attempts": []}
        readiness.append(record)
        if components[item["id"]] in prior_components:
            record["reason"] = "Target belongs to a prior lexical clone component"
            continue
        original_project = inside(corpus, item["project_root"])
        paths = sorted(inside(original_project, item["source_root"]).rglob("*.sol"))
        if not paths or len(paths) > 256 or sum(path.stat().st_size for path in paths) > 3_000_000:
            record["reason"] = "Solidity source tree outside bounded pilot budget"
            continue
        originals = {}
        for path in paths:
            relative = str(path.relative_to(original_project))
            if path.is_symlink() or not path.resolve().is_relative_to(original_project):
                raise ValueError("External dependency escapes source tree")
            raw = path.read_bytes()
            if raw != git_bytes(corpus, revision, str(path.relative_to(corpus))):
                raise ValueError("External dependency differs from pinned Git object")
            originals[relative] = raw
        chosen = None
        with tempfile.TemporaryDirectory(prefix="sentinel-external-") as directory:
            root = Path(directory)
            for name, raw in originals.items():
                path = inside(root, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            for compiler in compiler_pins:
                result = controlled.run([compiler["path"], "--base-path", ".", "--combined-json", "abi,bin", item["target_file"]], root)
                record["attempts"].append({"compiler": compiler["path"], "success": result.success,
                                           "timed_out": result.timed_out, "stderr": result.stderr})
                if not result.success:
                    continue
                try:
                    compiled = json.loads(result.stdout)["contracts"]
                except (ValueError, KeyError, TypeError) as error:
                    record["attempts"][-1]["parse_error"] = str(error)
                    continue
                if not compiled.get(f"{item['target_file']}:{item['target_contract']}", {}).get("bin"):
                    continue
                chosen = compiler
                break
        if chosen is None:
            record["reason"] = "No compatible complete dependency build; no stubs or invented dependency versions"
            continue
        project = output / "projects" / item["id"]
        for name, raw in originals.items():
            path = inside(project, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        (project / "foundry.toml").write_text('[profile.default]\n'
            f'src = {json.dumps(item["source_root"])}\nlibs = []\nsolc = {json.dumps(chosen["path"])}\n', encoding="utf-8")
        pins = {name: sha(raw) for name, raw in originals.items()}
        pins["foundry.toml"] = sha((project / "foundry.toml").read_bytes())
        record.update(status="ready", reason="Ground truth remains unknown pending human review", source_files=len(originals))
        cases.append({"id": item["id"], "project_path": f"projects/{item['id']}", "group": "audit",
                      "vulnerability_class": item["vulnerability_class"], "ground_truth": "unknown",
                      "target_file": item["target_file"], "target_contract": item["target_contract"],
                      "source_sha256": sha(targets[item["id"]].encode()),
                      "provenance": {"dataset": "FORGE-Curated", "revision": revision, "compiler": chosen,
                                     "source_url": f"{selection['repository']}/blob/{revision}/{item['project_root']}/{item['target_file']}",
                                     "clone_component": components[item["id"]], "project_files_sha256": pins,
                                     "annotation": metadata[item["id"]], "label_status": "pending_human_review",
                                     "negative_scope": "No absent-audit-finding or CWE-derived negative labels."}})
    provenance = {"dataset": "FORGE-Curated", "revision": revision, "repository": selection["repository"],
                  "registry_sha256": sha(raw_registry), "workflow_sha256": sha(Path(__file__).read_bytes()),
                  "excluded_evaluations": exclusions_record, "clone_audit": audit, "reserved_test_accessed": False,
                  "scanner_protocol": protocol, "compilers": compiler_pins,
                  "scope": "External source/build pilot with unknown labels, not detection-accuracy validation. "
                           "Target-file lexical screening, not semantic independence or pretraining proof. "
                           "Audited upstream commit correspondence and positive/negative properties require human review."}
    (output / "readiness.json").write_text(json.dumps({"provenance": provenance, "candidates": readiness}, indent=2) + "\n", encoding="utf-8")
    if not cases:
        raise ValueError("No runnable external cases; readiness failures have been preserved")
    document = {"name": "forge-curated-external-readiness-pilot", "cases": cases, "provenance": provenance}
    ExperimentManifest.model_validate(document)
    path = output / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def run(manifest_path: Path, output: Path, profile: str, scan=run_scan) -> dict:
    manifest = ExperimentManifest.model_validate_json(manifest_path.read_bytes())
    if manifest.provenance.get("workflow_sha256") != sha(Path(__file__).read_bytes()):
        raise ValueError("External benchmark workflow differs from the frozen protocol")
    projects = {(manifest_path.parent / case.project_path).resolve(): case.provenance["project_files_sha256"]
                for case in manifest.cases}

    def guarded(project, **kwargs):
        verify_project(project, projects[project.resolve()])
        return scan(project, **kwargs)

    return run_experiment(manifest_path, output, profile, scan=guarded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--registry", type=Path, default=Path("benchmarks/forge-curated-pilot.json"))
    prep.add_argument("--corpus", type=Path, default=Path("datasets/forge-curated"))
    prep.add_argument("--output", type=Path, default=Path("datasets/external-forge-curated-v1"))
    prep.add_argument("--compiler", type=Path, required=True, action="append")
    prep.add_argument("--smartbugs", type=Path, default=Path("datasets/smartbugs-curated"))
    prep.add_argument("--fitted", type=Path, default=Path("datasets/model-properties-fit"))
    prep.add_argument("--cgt", type=Path, default=Path("datasets/cgt"))
    prep.add_argument("--exclude-manifest", type=Path, required=True, action="append")
    prep.add_argument("--static-binary", type=Path, default=Path(".venv/bin/sentinel-static"))
    execute = sub.add_parser("run")
    execute.add_argument("manifest", type=Path)
    execute.add_argument("--profile", choices=("slither", "sentinel-static"), required=True)
    execute.add_argument("--output", type=Path, default=Path("reports/experiments/external-forge-curated-v1"))
    args = parser.parse_args()
    if args.action == "prepare":
        path = prepare(args.registry, args.corpus, args.output, args.compiler, smartbugs=args.smartbugs,
                       fitted=args.fitted, cgt=args.cgt, exclusions=args.exclude_manifest,
                       protocol=scanner_protocol(args.static_binary.resolve(), 30))
        print(f"External pilot manifest: {path}")
    else:
        report = run(args.manifest, args.output, args.profile)
        print(f"Complete cases: {report['coverage_complete_cases']}; unlabelled cases: {report['unlabeled_cases']}")
        print("Qualification:", "passed" if report["qualification"]["passed"] else "not passed")
        if not report["qualification"]["passed"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
