"""Optional parser/sklearn checks; synthetic fixture scores are not security evidence."""

import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from training import structural_precision as sp


@unittest.skipUnless(importlib.util.find_spec("sklearn") and importlib.util.find_spec("numpy")
                     and (ROOT / "training/ast_features/node_modules/@solidity-parser/parser/package.json").exists(),
                     "Requires isolated optional probe dependencies and pinned parser")
class StructuralPrecisionRuntimeTest(unittest.TestCase):
    def fixture(self, root):
        spec = importlib.util.spec_from_file_location("grouped_fixture", Path(__file__).with_name("test_grouped_precision_runtime.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous, rows = module.GroupedPrecisionRuntimeTest().fixture(root)
        anchor, output = root / "anchor", root / "structural"
        sp.gp.prepare(previous, anchor)
        sp.prepare(anchor, output)
        return output, rows

    def fit_quietly(self, output):
        with contextlib.redirect_stdout(io.StringIO()):
            return sp.fit(output)

    def test_end_to_end_selection_is_training_only_and_evaluates_every_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_open = Path.open

            def guard(path, *args, **kwargs):
                if "r" in (args[0] if args else kwargs.get("mode", "r")):
                    self.assertNotIn(path.name, {"valid.jsonl", "test.jsonl", "features.npz", "comparison.json"})
                return original_open(path, *args, **kwargs)

            # Synthetic input creation is outside the access guard; actual stages are inside it.
            output, rows = self.fixture(root)
            with patch.object(Path, "open", guard), patch.object(sp.gp, "read_development", side_effect=AssertionError("Premature validation")):
                selected = self.fit_quietly(output)
            self.assertEqual(set(selected), set(sp.gp.PROPERTIES))
            for swc in sp.gp.PROPERTIES:
                evidence = json.loads((output / f"oof-{swc}.json").read_text())
                self.assertEqual(len(evidence["candidates"]), 18)
                self.assertEqual(len(evidence["ids"]), 16)
                for candidate in evidence["candidates"]:
                    self.assertEqual(candidate["selection"], sp.gp.choose_threshold(evidence["labels"], candidate["margins"]))
            self.assertFalse(json.loads((output / "fit.json").read_text())["validation_accessed"])
            result = sp.evaluate_frozen(output)
            self.assertEqual(result["cases"], 8)
            comparison = json.loads((output / "comparison.json").read_text())
            sp.gp.verify_report(comparison["full_validation"], rows["valid"])
            self.assertFalse(comparison["llm_weights_updated"])
            self.assertFalse(comparison["validation_labels_changed"])
            self.assertFalse(comparison["target_audit"]["independent_99_percent_claim_supported"])
            with self.assertRaises(FileExistsError):
                sp.fit(output)
            with self.assertRaises(FileExistsError):
                sp.evaluate_frozen(output)

    def test_json_tree_and_linear_exports_reproduce_sklearn_scores(self):
        import numpy as np

        with tempfile.TemporaryDirectory() as directory:
            _, rows = self.fixture(Path(directory))
            subset = [r for r in rows["train"] if r["swc"] == "104"]
            cache = sp.extract(subset)
            records = sp.records_for(subset, cache)
            labels = [int(sp.gp.source_and_target(r)[1]["vulnerable"]) for r in subset]
            for representation in sp.PLAN["representations"]:
                candidate = next(c for c in sp.catalog() if c["representation"] == representation)
                x, preprocessing = sp.fit_features(records, representation)
                model = sp.classifier(candidate).fit(x, labels)
                exported = json.loads(json.dumps(sp.export_model(candidate, {"threshold": 0.5}, preprocessing, model)))
                np.testing.assert_allclose(sp.replay(exported, records), model.predict_proba(x)[:, 1], atol=1e-10, rtol=1e-10)
                if representation == "ast_tree":
                    cyclic = copy.deepcopy(exported)
                    cyclic["trees"][0]["left"][0] = cyclic["trees"][0]["right"][0] = 0
                    with self.assertRaisesRegex(ValueError, "cycle"):
                        sp.replay(cyclic, records)
                exported["threshold"] = float("nan")
                with self.assertRaises(ValueError):
                    sp.replay(exported, records)

    def test_unseen_structural_and_lexical_features_are_not_fitted_on_held_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            _, rows = self.fixture(Path(directory))
            subset = [r for r in rows["train"] if r["swc"] == "104"]
            records = sp.records_for(subset, sp.extract(subset))
            held = copy.deepcopy(records[:1])
            held[0]["features"]["HELD_ONLY_AST"] = 999
            held[0]["scoped_source"] = "contract Held { function fail() public { selfdestruct(msg.sender); } }"
            for representation in sp.PLAN["representations"]:
                x_train, preprocessing = sp.fit_features(records, representation)
                before = json.dumps(preprocessing, sort_keys=True)
                x_held = sp.transform_features(held, preprocessing)
                self.assertEqual(x_held.shape[1], x_train.shape[1])
                self.assertEqual(before, json.dumps(preprocessing, sort_keys=True))
                self.assertNotIn("HELD_ONLY_AST", preprocessing.get("ast_vocabulary", {}))
                self.assertNotIn("selfdestruct", preprocessing.get("token_vocabulary", {}))

    def test_extraction_failure_is_retained_with_explicit_fallback_and_no_labels_in_worker(self):
        from sentinel.modeling.properties import property_messages

        with tempfile.TemporaryDirectory() as directory:
            _, rows = self.fixture(Path(directory))
            row = copy.deepcopy(rows["train"][0])
            source = "contract Broken { function syntax("
            row.update(contract="Broken", source_hash=sp.gp.sha(source.encode()))
            row["messages"] = [*property_messages(source, row["swc"], "Broken"), row["messages"][-1]]
            cache = sp.extract([row])
            self.assertEqual(cache["status_counts"], {"parse_error": 1})
            result = sp.records_for([row], cache)[0]
            self.assertEqual(result["scoped_source"], source)
            self.assertNotIn("vulnerable", result)

    def test_tampered_model_blocks_validation_access(self):
        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.fixture(Path(directory))
            self.fit_quietly(output)
            with (output / "models.json").open("a") as handle:
                handle.write(" ")
            with (patch.object(sp.gp, "read_development", side_effect=AssertionError("Premature validation")),
                  self.assertRaisesRegex(ValueError, "Frozen classifier")):
                sp.evaluate_frozen(output)
            self.assertFalse((output / "evaluation-started.json").exists())

    def test_failed_fit_receipt_is_preserved_and_cannot_be_retried_in_place(self):
        from sklearn.exceptions import ConvergenceWarning

        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.fixture(Path(directory))
            with (patch.object(sp, "classifier", side_effect=ConvergenceWarning("Synthetic failure")),
                  self.assertRaises(ConvergenceWarning)):
                sp.fit(output)
            self.assertEqual(json.loads((output / "fit-failure.json").read_text())["status"], "failed")
            self.assertFalse((output / "fit.json").exists())
            with self.assertRaises(FileExistsError):
                sp.fit(output)

    def test_source_only_feature_cache_reuse_is_pinned_and_does_not_rerun_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, rows = self.fixture(root)
            cache = sp.extract(rows["train"])
            sp.gp.write_json(source / "training-features.json", cache)
            anchor = Path(json.loads((source / "protocol.json").read_text())["anchor"])
            output = root / "reused"
            sp.prepare(anchor, output, source)
            with patch.object(sp, "extract", side_effect=AssertionError("Cache was not reused")):
                self.fit_quietly(output)
            self.assertEqual(json.loads((output / "training-features.json").read_text()), cache)
            with (source / "training-features.json").open("a") as handle:
                handle.write(" ")
            with self.assertRaisesRegex(ValueError, "cache changed"):
                sp.load_training(output)


if __name__ == "__main__":
    unittest.main()
