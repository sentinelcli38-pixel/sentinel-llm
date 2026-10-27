"""Verify locked npm archives and retain Solidity/license files without running code."""

import argparse
import base64
import hashlib
import hmac
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.external_benchmark import git_bytes, inside, sha

MAX_ARCHIVE = 20_000_000
MAX_UNPACKED = 50_000_000
PACKAGE_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")


def registry_url(url: str) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname != "registry.npmjs.org"
            or parts.username or parts.password or parts.port not in (None, 443)
            or parts.query or parts.fragment or not parts.path.endswith(".tgz")):
        raise ValueError("Only credential-free HTTPS npm registry archives are allowed")
    return url


class RegistryRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        registry_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_archive(url: str) -> bytes:
    with build_opener(RegistryRedirects()).open(registry_url(url), timeout=30) as response:
        registry_url(response.geturl())
        raw = response.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Archive exceeds the compressed size budget")
    return raw


def solidity_files(raw: bytes, integrity: str) -> dict[str, bytes]:
    if len(raw) > MAX_ARCHIVE or not integrity.startswith("sha512-"):
        raise ValueError("A bounded archive and SHA-512 lock integrity are required")
    expected = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
    if len(expected) != 64 or not hmac.compare_digest(hashlib.sha512(raw).digest(), expected):
        raise ValueError("Archive does not match the authoritative lockfile integrity")
    selected, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= 5_000:
                raise ValueError("Archive contains too many entries")
            name = member.name.rstrip("/")
            if (not name or name.startswith("/") or "\\" in name or "\x00" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))):
                raise ValueError("Unsafe archive path")
            path = PurePosixPath(name)
            if path.parts[0] != "package" or name in seen:
                raise ValueError("Unexpected package root or duplicate archive path")
            seen.add(name)
            if (not member.isdir() and not member.isfile()) or member.issparse():
                raise ValueError("Links, devices, and sparse archive entries are forbidden")
            total += member.size
            if member.size > 2_000_000 or total > MAX_UNPACKED:
                raise ValueError("Archive exceeds the unpacked size budget")
            if member.isdir():
                continue
            relative = str(path.relative_to("package"))
            if not relative.endswith(".sol") and relative not in {"LICENSE", "LICENSE.md", "LICENSE.txt", "package.json"}:
                continue
            with archive.extractfile(member) as handle:
                selected[relative] = handle.read(member.size + 1)
            if len(selected[relative]) != member.size:
                raise ValueError("Truncated archive member")
    if not any(name.endswith(".sol") for name in selected):
        raise ValueError("Package has no Solidity sources")
    return selected


def stage(spec_path: Path, upstream: Path, output: Path, fetch=fetch_archive) -> Path:
    if output.exists():
        raise ValueError("Dependency stage already exists; preserve prior receipts")
    spec_raw = spec_path.read_bytes()
    spec = json.loads(spec_raw)
    upstream = upstream.resolve()
    revision = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    if revision != spec["revision"]:
        raise ValueError("Upstream is not at the audited commit")
    for field in ("lockfile", "build_config"):
        raw = inside(upstream, spec[field]).read_bytes()
        if sha(raw) != spec[f"{field}_sha256"] or raw != git_bytes(upstream, revision, spec[field]):
            raise ValueError("Audited lockfile/build configuration pin differs")
    lock = json.loads(inside(upstream, spec["lockfile"]).read_bytes())
    if lock.get("lockfileVersion") not in (2, 3):
        raise ValueError("An npm package lock with exact package records is required")
    names = spec["packages"]
    if not names or len(names) > 16 or len(set(names)) != len(names):
        raise ValueError("A small unique package selection is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with tempfile.TemporaryDirectory(prefix=".locked-solidity-", dir=output.parent) as directory:
        root = Path(directory)
        for name in names:
            if not PACKAGE_NAME.fullmatch(name):
                raise ValueError("Invalid npm package name")
            item = lock["packages"][f"node_modules/{name}"]
            url = registry_url(item["resolved"])
            raw = fetch(url)
            files = solidity_files(raw, item["integrity"])
            package = json.loads(files["package.json"])
            if package.get("name") != name or package.get("version") != item["version"]:
                raise ValueError("Package identity/version differs from locked entry")
            pins = {}
            for relative, content in files.items():
                destination = inside(root, f"npm/{name}/{relative}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                pins[f"npm/{name}/{relative}"] = sha(content)
            records.append({"name": name, "version": item["version"], "resolved": url,
                            "integrity": item["integrity"], "archive_sha256": sha(raw), "files_sha256": pins,
                            "license": package.get("license", item.get("license", "unknown"))})
        receipt = {"repository": spec["repository"], "revision": revision, "spec_sha256": sha(spec_raw),
                   "lockfile_sha256": spec["lockfile_sha256"], "build_config_sha256": spec["build_config_sha256"],
                   "build_settings": spec["build_settings"], "packages": records,
                   "workflow_sha256": sha(Path(__file__).read_bytes()),
                   "scope": "Integrity-verified Solidity/license files only. No package scripts, JS configuration, "
                            "npm installation, credentials, RPC, or deployments executed. Integrity is not a safety assessment."}
        (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        root.rename(output)
    return output / "receipt.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=Path("benchmarks/morpheus-locked-deps.json"))
    parser.add_argument("--upstream", type=Path, default=Path("datasets/upstream-morpheus"))
    parser.add_argument("--output", type=Path, default=Path("datasets/morpheus-locked-deps-v1"))
    args = parser.parse_args()
    print(f"Dependency receipt: {stage(args.spec, args.upstream, args.output)}")


if __name__ == "__main__":
    main()
