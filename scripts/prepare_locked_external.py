"""Extend the external feasibility pilot with one audited, locked dependency build."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.external_benchmark import (
    git_bytes,
    inside,
    known_sources,
    sha,
    verify_project,
)
from sentinel.experiments import ExperimentManifest
from sentinel.modeling.clones import clone_components
from sentinel.runner import ControlledRunner
from sentinel.scanner_protocol import scanner_protocol


def verified_dependencies(stage: Path, expected_sha: str, spec: dict, upstream: Path) -> tuple[dict, dict]:
    receipt_raw = (stage / "receipt.json").read_bytes()
    if sha(receipt_raw) != expected_sha:
        raise ValueError("Dependency receipt differs from the reviewed receipt pin")
    receipt = json.loads(receipt_raw)
    lock_raw = inside(upstream, spec["lockfile"]).read_bytes()
    config_raw = inside(upstream, spec["build_config"]).read_bytes()
    for key, raw in (("lockfile", lock_raw), ("build_config", config_raw)):
        if sha(raw) != spec[f"{key}_sha256"] or raw != git_bytes(upstream, spec["revision"], spec[key]):
            raise ValueError("Authoritative upstream input differs from its audited pin")
    if (receipt["revision"] != spec["revision"] or receipt["repository"] != spec["repository"]
            or receipt["build_settings"] != spec["build_settings"]
            or receipt["lockfile_sha256"] != spec["lockfile_sha256"]
            or receipt["build_config_sha256"] != spec["build_config_sha256"]):
        raise ValueError("Dependency receipt is not for the audited project settings")
    lock = json.loads(lock_raw)
    packages = receipt["packages"]
    if len(packages) != len(spec["packages"]) or {p["name"] for p in packages} != set(spec["packages"]):
        raise ValueError("Dependency package selection differs")
    pins, sources = {}, {}
    for package in packages:
        locked = lock["packages"][f"node_modules/{package['name']}"]
        for key in ("version", "resolved", "integrity"):
            if package[key] != locked[key]:
                raise ValueError("Dependency package differs from authoritative lock")
        for name, digest in package["files_sha256"].items():
            if not name.startswith(f"npm/{package['name']}/") or name in pins:
                raise ValueError("Dependency file is outside its package or duplicated")
            raw = inside(stage, name).read_bytes()
            if sha(raw) != digest:
                raise ValueError("Staged dependency source/license changed")
            pins[name] = digest
            sources[f"lib/{name}"] = raw
    actual = {str(path.relative_to(stage)) for path in stage.rglob("*") if path.is_file()}
    if actual != {*pins, "receipt.json"}:
        raise ValueError("Dependency stage file inventory changed")
    return sources, receipt


def prepare(pilot: Path, corpus: Path, upstream: Path, stage: Path, output: Path, compiler: Path,
            static_binary: Path, *, smartbugs: Path, fitted: Path, cgt: Path, exclusions: list[Path], runner=None) -> Path:
    if output.exists():
        raise ValueError("Locked external pilot already exists; preserve earlier versions")
    options_raw = pilot.read_bytes()
    options = json.loads(options_raw)
    spec_path = Path(options["dependency_spec"])
    spec_raw = spec_path.read_bytes()
    spec = json.loads(spec_raw)
    upstream, corpus, compiler = upstream.resolve(), corpus.resolve(), compiler.resolve()
    revision = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    if revision != spec["revision"]:
        raise ValueError("Upstream checkout is not the audited commit")
    dependencies, receipt = verified_dependencies(stage, options["dependency_receipt_sha256"], spec, upstream)
    if receipt["spec_sha256"] != sha(spec_raw):
        raise ValueError("Dependency specification changed since staging")
    previous_path = Path(options["previous_manifest"])
    previous_raw = previous_path.read_bytes()
    previous = ExperimentManifest.model_validate_json(previous_raw)
    protocol = scanner_protocol(static_binary.resolve(), 30)
    if previous.provenance["scanner_protocol"] != protocol:
        raise ValueError("Detector/runtime changed since the previous external pilot")
    selection = json.loads(Path("benchmarks/forge-curated-pilot.json").read_text())
    if subprocess.run(["git", "-C", str(corpus), "rev-parse", "HEAD"], check=True,
                      capture_output=True, text=True).stdout.strip() != selection["revision"]:
        raise ValueError("FORGE corpus is not at its pinned revision")
    item = next(case for case in selection["cases"] if case["id"] == options["case_id"])
    source_root = inside(corpus, item["project_root"])
    originals = {}
    for path in sorted(inside(source_root, item["source_root"]).rglob("*.sol")):
        relative = str(path.relative_to(source_root))
        raw = path.read_bytes()
        if (raw != git_bytes(corpus, selection["revision"], str(path.relative_to(corpus)))
                or raw != git_bytes(upstream, revision, relative) or raw != inside(upstream, relative).read_bytes()):
            raise ValueError("FORGE/upstream Solidity snapshots do not match the audited commit")
        originals[relative] = raw
    target = originals[item["target_file"]]
    vfp_raw, metadata_raw = (inside(corpus, item[key]).read_bytes() for key in ("vfp", "metadata"))
    for key, raw in (("vfp", vfp_raw), ("metadata", metadata_raw)):
        if raw != git_bytes(corpus, selection["revision"], item[key]):
            raise ValueError("External annotation differs from pinned corpus")
    vfp, metadata = json.loads(vfp_raw), json.loads(metadata_raw)
    finding = next(f for f in vfp["findings"] if f["id"] == item["finding_id"])
    if (vfp["affected_files"].get(Path(item["target_file"]).name) != target.decode()
            or not any(Path(name).name == Path(item["target_file"]).name for name in finding["files"])):
        raise ValueError("Annotated source/finding does not match target")
    known, exclusion_records = known_sources(smartbugs, fitted, cgt, [*exclusions, previous_path])
    components, audit = clone_components({**known, item["id"]: target.decode()}, {})
    if components[item["id"]] in {components[key] for key in known}:
        raise ValueError("New target belongs to a prior lexical component")
    snapshot_count = len(originals)
    originals.update(dependencies)
    remappings = [f"{name}/=lib/npm/{name}/" for name in spec["packages"]]
    settings = spec["build_settings"]
    controlled = runner or ControlledRunner(timeout_seconds=30)
    result = controlled.run([str(compiler), "--version"], upstream)
    if not result.success:
        raise ValueError("Installed compiler is unavailable")
    compiler_pin = {"path": str(compiler), "sha256": sha(compiler.read_bytes()), "version": result.stdout.strip()}
    with tempfile.TemporaryDirectory(prefix="sentinel-locked-build-") as directory:
        root = Path(directory)
        for name, raw in originals.items():
            path = inside(root, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        command = [str(compiler), "--base-path", ".", "--combined-json", "abi,bin,ast", "--optimize",
                   "--optimize-runs", str(settings["optimizer_runs"]), "--evm-version", settings["evm_version"],
                   *remappings, item["target_file"]]
        compiled = controlled.run(command, root)
        if not compiled.success:
            output.mkdir(parents=True)
            (output / "readiness.json").write_text(json.dumps({"status": "blocked", "stderr": compiled.stderr,
                "timed_out": compiled.timed_out, "dependency_receipt_sha256": options["dependency_receipt_sha256"]}, indent=2) + "\n")
            raise ValueError("Locked dependency build failed; diagnostics preserved")
        data = json.loads(compiled.stdout)
        closure = data["sourceList"]
        if (not data["version"].startswith(settings["solc_version"] + "+")
                or not data["contracts"].get(f"{item['target_file']}:{item['target_contract']}", {}).get("bin")
                or item["target_file"] not in closure or any(name not in originals for name in closure)):
            raise ValueError("Compiler version, target, or dependency closure differs")
    cases = []
    for case in previous.cases:
        copied = case.model_dump(mode="json")
        project = (previous_path.parent / case.project_path).resolve()
        verify_project(project, case.provenance["project_files_sha256"])
        copied["project_path"] = str(project)
        cases.append(copied)
    project = output / "projects" / item["id"]
    for name in closure:
        path = inside(project, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(originals[name])
    config = (f'[profile.default]\nsrc = {json.dumps(item["source_root"])}\nlibs = ["lib"]\n'
              f'solc = {json.dumps(str(compiler))}\noptimizer = true\noptimizer_runs = {settings["optimizer_runs"]}\n'
              f'evm_version = {json.dumps(settings["evm_version"])}\nremappings = {json.dumps(remappings)}\n')
    (project / "foundry.toml").write_text(config, encoding="utf-8")
    pins = {name: sha(originals[name]) for name in closure}
    pins["foundry.toml"] = sha(config.encode())
    cases.append({"id": item["id"], "project_path": f"projects/{item['id']}", "group": "audit",
        "vulnerability_class": item["vulnerability_class"], "ground_truth": "unknown",
        "target_contract": item["target_contract"], "target_file": item["target_file"], "source_sha256": sha(target),
        "provenance": {"dataset": "FORGE-Curated", "revision": selection["revision"], "compiler": compiler_pin,
            "clone_component": components[item["id"]], "project_files_sha256": pins, "label_status": "pending_human_review",
            "audited_upstream": {"repository": spec["repository"], "revision": revision, "snapshot_files_matched": snapshot_count},
            "dependency_receipt_sha256": options["dependency_receipt_sha256"], "build_settings": settings,
            "compilation_scope": "Compiler-derived target/dependency closure with audited locked npm sources",
            "annotation": {"finding": finding, "project_info": metadata["project_info"], "audit_report": metadata["path"],
                           "vfp_sha256": sha(vfp_raw), "audit_metadata_sha256": sha(metadata_raw)},
            "negative_scope": "Unknown pending human review; not inferred from missing audit findings."}})
    provenance = {"dataset": "FORGE-Curated", "revision": selection["revision"], "scanner_protocol": protocol,
        "workflow_sha256": sha(Path("scripts/external_benchmark.py").read_bytes()),
        "preparation_workflow_sha256": sha(Path(__file__).read_bytes()), "pilot_sha256": sha(options_raw),
        "dependency_receipt_sha256": options["dependency_receipt_sha256"], "dependency_provenance": receipt,
        "previous_manifest_sha256": sha(previous_raw), "previous_provenance": previous.provenance,
        "clone_audit": audit, "excluded_evaluations": exclusion_records, "reserved_test_accessed": False,
        "scope": "Two-case external feasibility set, reusing OracleLess unchanged. No accepted human labels, "
                 "negative controls, accuracy validation, exploitation, model use, or production qualification."}
    document = {"name": "forge-curated-locked-external-pilot", "cases": cases, "provenance": provenance}
    ExperimentManifest.model_validate(document)
    path = output / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    (output / "readiness.json").write_text(json.dumps({"status": "ready_for_candidate_scans", "cases": len(cases),
        "new_target_sources": len(closure), "remaining_blocker": "sBOLD has no authoritative lockfile at audited commit",
        "human_label_status": "pending"}, indent=2) + "\n", encoding="utf-8")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot", type=Path, default=Path("benchmarks/morpheus-locked-pilot.json"))
    parser.add_argument("--corpus", type=Path, default=Path("datasets/forge-curated"))
    parser.add_argument("--upstream", type=Path, default=Path("datasets/upstream-morpheus"))
    parser.add_argument("--dependencies", type=Path, default=Path("datasets/morpheus-locked-deps-v1"))
    parser.add_argument("--output", type=Path, default=Path("datasets/external-forge-curated-v3"))
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--static-binary", type=Path, default=Path(".venv/bin/sentinel-static"))
    parser.add_argument("--smartbugs", type=Path, default=Path("datasets/smartbugs-curated"))
    parser.add_argument("--fitted", type=Path, default=Path("datasets/model-properties-fit"))
    parser.add_argument("--cgt", type=Path, default=Path("datasets/cgt"))
    parser.add_argument("--exclude-manifest", type=Path, required=True, action="append")
    args = parser.parse_args()
    path = prepare(args.pilot, args.corpus, args.upstream, args.dependencies, args.output, args.compiler, args.static_binary,
                   smartbugs=args.smartbugs, fitted=args.fitted, cgt=args.cgt, exclusions=args.exclude_manifest)
    print(f"Locked external manifest: {path}")


if __name__ == "__main__":
    main()
