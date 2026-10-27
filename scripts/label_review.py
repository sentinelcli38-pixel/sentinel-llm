"""Prepare blinded review forms and preserve human consensus in a new manifest."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.experiments import ExperimentManifest
from sentinel.modeling.data import strip_comments

DEFAULT_SCOPE = (
    "Review the specified property in the compiled target context, not whole-contract safety. "
    "Comments are blanked without moving code lines. Request full dependencies if needed; "
    "unknown is preferable to assuming safety. Do not inspect labels or tool output before first review."
)


def review_scope(manifest: ExperimentManifest) -> str:
    scope = manifest.provenance.get("review_scope", DEFAULT_SCOPE)
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("Review scope must be nonempty text")
    return scope


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sources(manifest_path: Path, manifest: ExperimentManifest) -> dict:
    result = {}
    for case in manifest.cases:
        if not case.source_sha256 or not case.target_file or not case.target_contract:
            raise ValueError("Review requires a pinned source, assessed contract, and file")
        project = (manifest_path.parent / case.project_path).resolve()
        path = (project / case.target_file).resolve()
        if not path.is_relative_to(project):
            raise ValueError("Review source escapes its project")
        raw = path.read_bytes()
        if digest(raw) != case.source_sha256:
            raise ValueError(f"Review source differs from frozen assessment: {case.id}")
        for name, pin in case.provenance.get("project_files_sha256", {}).items():
            dependency = (project / name).resolve()
            if Path(name).is_absolute() or not dependency.is_relative_to(project) or digest(dependency.read_bytes()) != pin:
                raise ValueError("Review dependency/configuration differs from frozen context")
        result[case.id] = (project, raw)
    return result


def prepare(manifest_path: Path, output: Path) -> Path:
    if output.exists():
        raise ValueError("Review packet already exists; choose a new directory")
    original = manifest_path.read_bytes()
    manifest = ExperimentManifest.model_validate_json(original)
    scope = review_scope(manifest)
    frozen_sources = sources(manifest_path, manifest)
    packet_cases, mapping, contexts = [], {}, {}
    for case in sorted(manifest.cases, key=lambda case: digest(f"{digest(original)}:{case.id}".encode())):
        review_id = "review-" + digest(f"{digest(original)}:{case.id}".encode())[:16]
        blind = strip_comments(frozen_sources[case.id][1].decode("utf-8")).encode()
        context_files = []
        project = frozen_sources[case.id][0]
        for name, pin in sorted(case.provenance.get("project_files_sha256", {}).items()):
            if not name.endswith(".sol"):
                continue
            source = f"contexts/{review_id}/{name}"
            content = strip_comments((project / name).read_text()).encode()
            contexts[source] = content
            context_files.append({"source": source, "source_sha256": pin, "blind_source_sha256": digest(content)})
        packet_cases.append({"review_id": review_id, "target_contract": case.target_contract,
                             "vulnerability_class": case.vulnerability_class,
                             "source_sha256": case.source_sha256, "blind_source_sha256": digest(blind),
                             "source": f"sources/{review_id}.sol", "line_count": len(blind.decode().splitlines()),
                             "context_files": context_files})
        mapping[review_id] = case.id
    packet = {"schema_version": 1, "manifest_sha256": digest(original), "cases": packet_cases,
              "scope": scope}
    packet_raw = (json.dumps(packet, indent=2) + "\n").encode()
    (output / "blind/sources").mkdir(parents=True)
    for row in packet_cases:
        raw = frozen_sources[mapping[row["review_id"]]][1]
        (output / "blind" / row["source"]).write_text(strip_comments(raw.decode()), encoding="utf-8")
    for relative, content in contexts.items():
        path = output / "blind" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (output / "blind/cases.json").write_bytes(packet_raw)
    template = {"packet_sha256": digest(packet_raw), "manifest_sha256": digest(original),
                "reviewer": {"id": "", "kind": "human", "qualification": "", "independence_declared": False},
                "reviews": [{"review_id": row["review_id"], "source_sha256": row["source_sha256"],
                             "decision": "pending", "rationale": "", "evidence_lines": []} for row in packet_cases]}
    for name in ("reviewer-a", "reviewer-b"):
        (output / "blind" / f"{name}.json").write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    (output / "original-manifest.json").write_bytes(original)
    (output / "admin.json").write_text(json.dumps({"original_path": str(manifest_path.resolve()),
                                                 "case_mapping": mapping}, indent=2) + "\n", encoding="utf-8")
    return output / "blind/cases.json"


def validate_submission(submission: dict, packet: dict, packet_sha: str) -> dict:
    if submission.get("packet_sha256") != packet_sha or submission.get("manifest_sha256") != packet["manifest_sha256"]:
        raise ValueError("Submission does not match this frozen packet")
    reviewer = submission.get("reviewer", {})
    if (reviewer.get("kind") != "human" or reviewer.get("independence_declared") is not True
            or not isinstance(reviewer.get("id"), str) or not reviewer["id"].strip()
            or not isinstance(reviewer.get("qualification"), str) or not reviewer["qualification"].strip()):
        raise ValueError("A named human reviewer must declare qualifications and independence")
    rows = submission.get("reviews", [])
    decisions = {row["review_id"]: row for row in rows}
    expected = {row["review_id"]: row for row in packet["cases"]}
    if len(rows) != len(decisions) or decisions.keys() != expected.keys():
        raise ValueError("Submission must contain every review ID exactly once")
    for review_id, row in decisions.items():
        case = expected[review_id]
        if row.get("source_sha256") != case["source_sha256"]:
            raise ValueError("Review source pin differs")
        if row.get("decision") not in {"pending", "unknown", "vulnerable", "clean"}:
            raise ValueError("Invalid property decision")
        lines = row.get("evidence_lines")
        if not isinstance(lines, list) or any(type(line) is not int or not 1 <= line <= case["line_count"] for line in lines):
            raise ValueError("Evidence lines must refer to the frozen source")
        if row["decision"] != "pending":
            if not isinstance(row.get("rationale"), str) or not row["rationale"].strip():
                raise ValueError("Reviewed decisions require a rationale")
            if row["decision"] in {"vulnerable", "clean"} and not lines:
                raise ValueError("Positive and negative decisions require source evidence")
    return decisions


def consensus(packet_dir: Path, reviewer_a: Path, reviewer_b: Path, output: Path) -> Path:
    if output.exists():
        raise ValueError("Consensus output already exists; never replace original assessments")
    original = (packet_dir / "original-manifest.json").read_bytes()
    manifest = ExperimentManifest.model_validate_json(original)
    packet_raw = (packet_dir / "blind/cases.json").read_bytes()
    packet = json.loads(packet_raw)
    if packet["manifest_sha256"] != digest(original):
        raise ValueError("Packet manifest hash differs")
    if packet.get("scope") != review_scope(manifest):
        raise ValueError("Review instructions differ from the frozen scope")
    admin = json.loads((packet_dir / "admin.json").read_text())
    frozen_sources = sources(Path(admin["original_path"]), manifest)
    mapping = admin["case_mapping"]
    if set(mapping.values()) != {case.id for case in manifest.cases} or len(mapping) != len(manifest.cases):
        raise ValueError("Review mapping must match all original cases")
    original_cases = {case.id: case for case in manifest.cases}
    for row in packet["cases"]:
        case = original_cases[mapping[row["review_id"]]]
        if row["review_id"] != "review-" + digest(f"{digest(original)}:{case.id}".encode())[:16]:
            raise ValueError("Review ID does not match the original case")
        raw = strip_comments(frozen_sources[case.id][1].decode()).encode()
        if (row["target_contract"] != case.target_contract or row["vulnerability_class"] != case.vulnerability_class
                or row["source_sha256"] != case.source_sha256 or row["blind_source_sha256"] != digest(raw)
                or row["line_count"] != len(raw.decode().splitlines())):
            raise ValueError("Blinded scope differs from the original assessment")
        path = (packet_dir / "blind" / row["source"]).resolve()
        if not path.is_relative_to((packet_dir / "blind/sources").resolve()) or path.read_bytes() != raw:
            raise ValueError("Blinded source differs from the frozen packet")
        expected_context = []
        project = frozen_sources[case.id][0]
        for name, pin in sorted(case.provenance.get("project_files_sha256", {}).items()):
            if not name.endswith(".sol"):
                continue
            source = f"contexts/{row['review_id']}/{name}"
            content = strip_comments((project / name).read_text()).encode()
            expected_context.append({"source": source, "source_sha256": pin, "blind_source_sha256": digest(content)})
            context_path = (packet_dir / "blind" / source).resolve()
            if not context_path.is_relative_to((packet_dir / "blind/contexts").resolve()) or context_path.read_bytes() != content:
                raise ValueError("Blinded dependency differs from the frozen context")
        if row.get("context_files", []) != expected_context:
            raise ValueError("Blinded context inventory differs")
    a_raw, b_raw = reviewer_a.read_bytes(), reviewer_b.read_bytes()
    a, b = json.loads(a_raw), json.loads(b_raw)
    a_rows, b_rows = validate_submission(a, packet, digest(packet_raw)), validate_submission(b, packet, digest(packet_raw))
    if a["reviewer"]["id"].strip().casefold() == b["reviewer"]["id"].strip().casefold():
        raise ValueError("Two distinct human reviewers are required")
    document = manifest.model_dump(mode="json")
    document["name"] += "-human-review-consensus"
    statuses = {}
    reverse = {case_id: review_id for review_id, case_id in mapping.items()}
    for case in document["cases"]:
        review_id = reverse[case["id"]]
        left, right = a_rows[review_id], b_rows[review_id]
        agreed = left["decision"] == right["decision"] and left["decision"] in {"vulnerable", "clean"}
        status = "agreed" if agreed else "pending" if "pending" in (left["decision"], right["decision"]) else "unresolved"
        statuses[case["id"]] = status
        case["provenance"]["human_review"] = {"review_id": review_id, "status": status,
                                               "prior_ground_truth": case["ground_truth"], "reviews": [left, right]}
        case["ground_truth"] = left["decision"] if agreed else "unknown"
        case["project_path"] = str(frozen_sources[case["id"]][0])
    document["provenance"]["human_review"] = {"original_manifest_sha256": digest(original),
        "packet_sha256": digest(packet_raw), "reviewer_a_sha256": digest(a_raw), "reviewer_b_sha256": digest(b_raw),
        "reviewers": [a["reviewer"], b["reviewer"]], "statuses": statuses,
        "scope": "Human declarations are self-attested, not authenticated credentials. "
                 "Unresolved/pending cases remain unknown; original assessments and reports are preserved."}
    ExperimentManifest.model_validate(document)
    output.mkdir(parents=True)
    path = output / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("manifest", type=Path)
    prep.add_argument("--output", type=Path, required=True)
    accept = sub.add_parser("consensus")
    accept.add_argument("packet", type=Path)
    accept.add_argument("--reviewer-a", type=Path, required=True)
    accept.add_argument("--reviewer-b", type=Path, required=True)
    accept.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = prepare(args.manifest, args.output) if args.action == "prepare" else consensus(
        args.packet, args.reviewer_a, args.reviewer_b, args.output)
    print(f"Review artifact: {path}")


if __name__ == "__main__":
    main()
