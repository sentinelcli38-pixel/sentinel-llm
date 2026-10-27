"""CPU-only optional-dependency checks; fixtures are not security benchmarks."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.properties import PROPERTIES, property_messages
from training import frozen_probe, lexical_scale, provisional_review


@unittest.skipUnless(importlib.util.find_spec("sklearn") and importlib.util.find_spec("numpy"),
                     "Run separately with the optional MLX/probe interpreter")
class ProbeRuntimeTest(unittest.TestCase):
    def fixture(self, output):
        import numpy as np

        rows, arrays = {}, {}
        for split, repeats in (("train", 2), ("valid", 1)):
            rows[split], vectors = [], []
            for swc in PROPERTIES:
                for truth in (False, True):
                    for index in range(repeats):
                        key = f"{split}_{swc}_{truth}_{index}"
                        source = f"contract Case_{key} {{ function value() public pure returns(uint) {{return 1;}} }}"
                        if split == "valid":
                            source += '\ncontract Context { string public memo = "heldout-only"; }'
                        rows[split].append({"id": key, "task": "swc_property", "contract": f"Case_{key}", "swc": swc,
                            "source_hash": hashlib.sha256(source.encode()).hexdigest(),
                            "messages": [*property_messages(source, swc, f"Case_{key}"),
                                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]})
                        vector = np.zeros(1536, dtype=np.float32)
                        vector[0], vector[1] = (1 if truth else -1), 0.1
                        vectors.append(vector)
            arrays[split] = np.stack(vectors)
        (output / "protocol.json").write_text("{}")
        np.savez_compressed(output / "features.npz", **arrays)
        receipt = {"protocol_sha256": frozen_probe.file_hash(output / "protocol.json"),
                   "features_sha256": frozen_probe.file_hash(output / "features.npz"),
                   "ids": {split: [r["id"] for r in items] for split, items in rows.items()},
                   "shapes": {split: list(matrix.shape) for split, matrix in arrays.items()},
                   "token_lengths": {split: [100] * len(items) for split, items in rows.items()},
                   "base_parameter_count": 1543714304, "base_weights_updated": False, "reserved_test_accessed": False,
                   "validation_logit_reproduction": {"passed": True, "atol": 0.05, "rtol": 0.01}}
        (output / "features.json").write_text(json.dumps(receipt))
        return rows, arrays, receipt

    def test_sklearn_heads_preserve_full_denominator_and_export_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rows, _, _ = self.fixture(output)
            with patch.object(frozen_probe, "load_protocol", return_value=({}, rows)):
                result = frozen_probe.score(output)
                self.assertEqual(result["results"]["frozen_qwen"]["cases"], 8)
                self.assertEqual(result["results"]["frozen_qwen"]["tp"], 4)
                self.assertEqual(result["results"]["frozen_qwen"]["tn"], 4)
                self.assertFalse(result["independent_99_percent_claim_supported"])
                with self.assertRaises(FileExistsError):
                    frozen_probe.score(output)
            coefficients = json.loads((output / "classifiers.json").read_text())
            self.assertEqual(set(coefficients), {"frozen_qwen", "lexical_control"})
            self.assertEqual(set(coefficients["frozen_qwen"]), set(PROPERTIES))
            for model in coefficients["lexical_control"].values():
                self.assertNotIn("STR", model["preprocessing"]["vocabulary"])
            saved = json.loads((output / "comparison.json").read_text())
            for method in saved["results"].values():
                self.assertEqual(len(method["valid"]["predictions"]), 8)

    def test_nonfinite_matrix_is_rejected_even_with_updated_integrity_receipt(self):
        import numpy as np

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rows, arrays, receipt = self.fixture(output)
            arrays["train"][0, 0] = np.nan
            np.savez_compressed(output / "features.npz", **arrays)
            receipt["features_sha256"] = frozen_probe.file_hash(output / "features.npz")
            (output / "features.json").write_text(json.dumps(receipt))
            with patch.object(frozen_probe, "load_protocol", return_value=({}, rows)), self.assertRaises(ValueError):
                frozen_probe.score(output)

    def test_larger_lexical_control_retains_full_and_original_subset_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rows, _, _ = self.fixture(output)
            original_ids = [row["id"] for row in rows["valid"][:4]]
            with patch.object(lexical_scale, "load", return_value=({"original_valid_ids": original_ids}, rows)):
                lexical_scale.score(output)
                with self.assertRaises(FileExistsError):
                    lexical_scale.score(output)
            comparison = json.loads((output / "comparison.json").read_text())
            full = comparison["full_validation"]["predictions"]
            subset = comparison["original_validation_subset"]["predictions"]
            self.assertEqual(len(full), 8)
            self.assertEqual(len(subset), 4)
            self.assertEqual(subset, [row for row in full if row["id"] in original_ids])
            self.assertFalse(comparison["llm_weights_updated"])
            self.assertFalse(comparison["independent_99_percent_claim_supported"])

    def test_provisional_review_fits_all_six_arms_without_changing_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe, output = root / "probe", root / "review-experiment"
            probe.mkdir()
            output.mkdir()
            rows, _, _ = self.fixture(probe)
            reviewed = [r for r in rows["train"] if r["swc"] == "104"]
            cases = [{"id": r["id"], "source_sha256": r["source_hash"], "target_contract": r["contract"],
                      "group": "development", "provenance": {"role": "training"},
                      "vulnerability_class": f"SWC-104: {PROPERTIES['104']}"} for r in reviewed]
            manifest = json.dumps({"cases": cases}).encode()
            manifest_sha = provisional_review.sha(manifest)
            mapping, blind = {}, []
            for r in reviewed:
                review_id = "review-" + provisional_review.sha(f"{manifest_sha}:{r['id']}".encode())[:16]
                mapping[review_id] = r["id"]
                blind.append({"review_id": review_id, "target_contract": r["contract"],
                              "source_sha256": r["source_hash"], "blind_source_sha256": r["source_hash"],
                              "line_count": 1, "context_files": [], "vulnerability_class": f"SWC-104: {PROPERTIES['104']}"})
            packet = json.dumps({"manifest_sha256": manifest_sha, "cases": blind}).encode()
            raws = {"packet": packet, "manifest": manifest, "mapping": json.dumps({"case_mapping": mapping}).encode()}
            for name, decisions in (("a", ["clean", "unknown", "vulnerable", "vulnerable"]),
                                    ("b", ["clean", "unknown", "vulnerable", "unknown"])):
                raws[name] = json.dumps({"reviewer": {"id": f"fixture-ai-{name}", "kind": "ai"},
                    "packet_sha256": provisional_review.sha(packet), "manifest_sha256": manifest_sha,
                    "reviews": [{"review_id": c["review_id"], "source_sha256": c["source_sha256"],
                                 "decision": decision, "rationale": "Synthetic runtime fixture, not human adjudication.",
                                 "evidence_lines": [1]} for c, decision in zip(blind, decisions, strict=True)]}).encode()
            ledger = provisional_review.reconcile(raws, rows)
            (output / "protocol.json").write_text("{}")
            (output / "review-decisions.json").write_text(json.dumps(ledger))
            before = json.dumps(rows, sort_keys=True)
            with patch.object(provisional_review, "load", return_value=({"probe": str(probe)}, rows, rows, ledger)):
                result = provisional_review.score(output)
                with self.assertRaises(FileExistsError):
                    provisional_review.score(output)
            self.assertEqual(json.dumps(rows, sort_keys=True), before)
            comparison = json.loads((output / "comparison.json").read_text())
            self.assertEqual(set(result), {"frozen_qwen", "lexical_matched", "lexical_full"})
            for family in comparison["results"].values():
                self.assertEqual(set(family), {"historical", "provisional"})
                self.assertEqual(family["historical"]["training_cases"], 16)
                self.assertEqual(family["provisional"]["training_cases"], 14)
                for report in family.values():
                    self.assertEqual(len(report["predictions"]), 8)
                    self.assertFalse(report["target_audit"]["independent_99_percent_claim_supported"])
            self.assertFalse(comparison["signed_human_consensus"])
            self.assertFalse(comparison["validation_labels_changed"])
            self.assertEqual(comparison["unresolved_training_cases"], 2)
            self.assertEqual(json.loads((output / "execution.json").read_text())["status"], "completed")


if __name__ == "__main__":
    unittest.main()
