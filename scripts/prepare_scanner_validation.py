"""Freeze unused CGT validation cases using only installed local compilers."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.evaluation import prepare_scanner_validation
from sentinel.scanner_protocol import scanner_protocol


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("datasets/cgt"))
    parser.add_argument("--prepared", type=Path, default=Path("datasets/model-properties"))
    parser.add_argument("--fitted", type=Path, default=Path("datasets/model-properties-fit"))
    parser.add_argument("--output", type=Path, default=Path("datasets/scanner-validation"))
    parser.add_argument("--compiler", type=Path, action="append", required=True)
    parser.add_argument("--per-bucket", type=int, default=2)
    parser.add_argument("--candidate-split", choices=("train", "valid"), default="valid")
    parser.add_argument("--exclude-manifest", type=Path, action="append")
    parser.add_argument("--seed", type=int, default=83)
    parser.add_argument("--freeze-protocol", action="store_true")
    parser.add_argument("--static-binary", type=Path, default=Path(".venv/bin/sentinel-static"))
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--allow-multiple-contracts", action="store_true", help="Permit companion contracts; retain assessed-contract scoring.")
    args = parser.parse_args()
    protocol = scanner_protocol(args.static_binary, args.timeout_seconds) if args.freeze_protocol else None
    path = prepare_scanner_validation(args.corpus, args.prepared, args.fitted, args.output, args.compiler,
                                      per_bucket=args.per_bucket, seed=args.seed, candidate_split=args.candidate_split,
                                      exclude_manifests=args.exclude_manifest, frozen_protocol=protocol,
                                      allow_multiple_contracts=args.allow_multiple_contracts)
    print(f"Frozen scanner validation manifest: {path}")


if __name__ == "__main__":
    main()
