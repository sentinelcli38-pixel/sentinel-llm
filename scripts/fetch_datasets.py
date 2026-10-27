"""Fetch pinned public Solidity benchmark datasets into the ignored datasets directory."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Dataset:
    name: str
    url: str
    revision: str
    directory: str
    purpose: str
    recurse_submodules: bool = False
    sparse_paths: tuple[str, ...] = ()


DATASETS = {
    "cgt": Dataset(
        name="Consolidated Ground Truth",
        url="https://github.com/gsalzer/cgt.git",
        revision="f8cd72cf7fbbfebc809c454667eee271706a4b2b",
        directory="cgt",
        purpose="Manually assessed positive and negative properties, not whole-contract safety labels.",
        sparse_paths=("/source/", "/consolidated.csv", "/construction/sql/02_mapping.csv"),
    ),
    "smartbugs-curated": Dataset(
        name="SmartBugs Curated",
        url="https://github.com/smartbugs/smartbugs-curated.git",
        revision="230e649123477eff332742a59a1c7cc6dc286cab",
        directory="smartbugs-curated",
        purpose="Annotated vulnerable Solidity contracts for detection evaluation.",
    ),
    "damn-vulnerable-defi": Dataset(
        name="Damn Vulnerable DeFi",
        url="https://github.com/tinchoabbate/damn-vulnerable-defi.git",
        revision="64fddf9f96de2782f8868898d68673acb295119c",
        directory="damn-vulnerable-defi",
        purpose="Executable intentionally vulnerable DeFi scenarios.",
    ),
    "defi-vuln-labs": Dataset(
        name="DeFiVulnLabs",
        url="https://github.com/SunWeb3Sec/DeFiVulnLabs.git",
        revision="f61f6ee5c3f89eb7685030647f8df19997596f8b",
        directory="defi-vuln-labs",
        purpose="Foundry-oriented Solidity security exercises and exploit examples.",
    ),
    "forge-artifacts": Dataset(
        name="FORGE Artifacts",
        url="https://github.com/shenyimings/FORGE-Artifacts.git",
        revision="28f3d9cac3e0860cac84fdb63435b4a88257611f",
        directory="forge-artifacts",
        purpose="Audit-derived large-scale vulnerability corpus.",
        recurse_submodules=True,
    ),
}


def checkout_revision(directory: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def fetch(dataset: Dataset, root: Path) -> Path:
    target = root / dataset.directory
    if target.exists():
        if (target / ".git").exists() and checkout_revision(target) == dataset.revision:
            print(f"Already present at pinned revision: {target}")
            return target
        raise FileExistsError(f"Refusing to replace existing dataset directory: {target}")

    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root, prefix=f".{dataset.directory}-") as temp:
        clone_target = Path(temp) / dataset.directory
        command = ["git", "clone", "--depth", "1"]
        if dataset.sparse_paths:
            command.extend(["--filter=blob:none", "--sparse"])
        if dataset.recurse_submodules:
            command.append("--recurse-submodules")
        command.extend([dataset.url, str(clone_target)])
        subprocess.run(command, check=True)
        revision = checkout_revision(clone_target)
        if revision != dataset.revision:
            raise RuntimeError(
                f"Upstream revision changed for {dataset.name}: expected {dataset.revision}, got {revision}. "
                "Update this registry intentionally after reviewing the new dataset."
            )
        if dataset.sparse_paths:
            subprocess.run(["git", "-C", str(clone_target), "sparse-checkout", "set", "--no-cone", *dataset.sparse_paths], check=True)
        clone_target.rename(target)
    print(f"Fetched {dataset.name} at {dataset.revision[:12]} into {target}")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=[*DATASETS, "all"], help="Dataset to fetch")
    parser.add_argument("--root", type=Path, default=Path("datasets"), help="Local dataset directory")
    args = parser.parse_args()
    selected = DATASETS.values() if args.dataset == "all" else [DATASETS[args.dataset]]
    for dataset in selected:
        fetch(dataset, args.root)


if __name__ == "__main__":
    main()
