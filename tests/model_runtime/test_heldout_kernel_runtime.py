"""CPU-only synthetic checks; passing fixtures do not establish security precision."""

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
from training import heldout_kernel as hk


@unittest.skipUnless(importlib.util.find_spec("sklearn") and importlib.util.find_spec("numpy"),
                     "Requires isolated optional probe dependencies")
class HeldoutKernelRuntimeTest(unittest.TestCase):
    def fixture(self, root):
        spec = importlib.util.spec_from_file_location("grouped_fixture", Path(__file__).with_name("test_grouped_precision_runtime.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous, rows = module.GroupedPrecisionRuntimeTest().fixture(root)
        anchor, output = root / "anchor", root / "kernel"
        hk.gp.prepare(previous, anchor)
        hk.prepare(anchor, output)
        return output, rows

    def fit_quietly(self, output):
        with contextlib.redirect_stdout(io.StringIO()):
            return hk.fit(output)

    def test_full_flow_separates_model_fit_threshold_selection_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            output, rows = self.fixture(Path(directory))
            protocol, proper, threshold = hk.load_training(output)
            allowed = {hk.gp.source_and_target(r)[0] for r in proper}
            original_vectorizer = hk.vectorizer

            def guarded_vectorizer(*args, **kwargs):
                vec = original_vectorizer(*args, **kwargs)
                original_fit, original_transform = vec.fit_transform, vec.transform

                def fit_transform(documents, *args, **kwargs):
                    self.assertTrue(set(documents) <= allowed)
                    return original_fit(documents, *args, **kwargs)

                def transform(documents, *args, **kwargs):
                    self.assertTrue(set(documents) <= allowed)
                    return original_transform(documents, *args, **kwargs)

                vec.fit_transform, vec.transform = fit_transform, transform
                return vec

            with (patch.object(hk, "vectorizer", side_effect=guarded_vectorizer),
                  patch.object(hk.gp, "read_development", side_effect=AssertionError("Premature validation"))):
                self.fit_quietly(output)
            for swc in hk.gp.PROPERTIES:
                evidence = json.loads((output / f"oof-{swc}.json").read_text())
                self.assertEqual(evidence["ids"], [r["id"] for r in proper if r["swc"] == swc])
                self.assertEqual(len(evidence["candidates"]), 4)
                self.assertTrue(set(evidence["ids"]).isdisjoint(protocol["threshold_ids"]))
            with (patch.object(hk.gp, "read_development", side_effect=AssertionError("Premature validation")),
                  self.assertRaises(FileNotFoundError)):
                hk.evaluate_frozen(output)
            self.assertFalse((output / "evaluation-started.json").exists())
            pin = hk.gp.file_hash(output / "models.json.gz")
            with (patch.object(hk, "estimator", side_effect=AssertionError("Threshold stage refitted model")),
                  patch.object(hk.gp, "read_development", side_effect=AssertionError("Threshold stage read validation"))):
                hk.choose_thresholds(output)
            self.assertEqual(pin, hk.gp.file_hash(output / "models.json.gz"))
            thresholds = json.loads((output / "thresholds.json").read_text())
            self.assertEqual({key for v in thresholds["results"].values() for key in v["ids"]}, {r["id"] for r in threshold})
            with patch.object(hk, "estimator", side_effect=AssertionError("Evaluation refitted model")):
                result = hk.evaluate_frozen(output)
            self.assertEqual(result["cases"], 8)
            report = json.loads((output / "comparison.json").read_text())
            hk.gp.verify_report(report["full_validation"], rows["valid"])
            self.assertFalse(report["model_refitted_after_threshold"])
            self.assertFalse(report["target_audit"]["independent_99_percent_claim_supported"])
            self.assertFalse(report["target_audit"]["numerical_requirements_met"])
            for stage in (hk.fit, hk.choose_thresholds, hk.evaluate_frozen):
                with self.assertRaises(FileExistsError):
                    stage(output)

    def test_json_support_vectors_reproduce_precomputed_svc_on_held_inputs(self):
        import numpy as np

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, rows = self.fixture(root)
            _, proper, threshold = hk.load_training(output)
            training = [r for r in proper if r["swc"] == "104"]
            held = [r for r in threshold + rows["valid"] if r["swc"] == "104"]
            sources = [hk.gp.source_and_target(r)[0] for r in training]
            held_sources = [hk.gp.source_and_target(r)[0] for r in held]
            labels = [int(hk.gp.source_and_target(r)[1]["vulnerable"]) for r in training]
            for candidate in hk.catalog():
                vec = hk.vectorizer(candidate["representation"])
                x = vec.fit_transform(sources)
                fitted = hk.estimator(candidate).fit(hk.kernel(x, x), labels)
                model = hk.export_model(candidate, vec, fitted, x)
                expected = fitted.decision_function(hk.kernel(vec.transform(held_sources), x))
                np.testing.assert_allclose(hk.replay_margins(model, held_sources), expected, atol=1e-10, rtol=1e-10)
                a, b = root / f"{candidate['id']}-a.json.gz", root / f"{candidate['id']}-b.json.gz"
                hk.save_models(a, model)
                hk.save_models(b, model)
                self.assertEqual(a.read_bytes(), b.read_bytes())
                self.assertEqual(hk.read_models(a), model)
                invalid = copy.deepcopy(model)
                invalid["support"]["indices"][0] = invalid["support"]["shape"][1]
                with self.assertRaisesRegex(ValueError, "Malformed"):
                    hk.replay_margins(invalid, held_sources)

    def test_tampered_kernel_model_prevents_threshold_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.fixture(Path(directory))
            self.fit_quietly(output)
            with (output / "models.json.gz").open("ab") as handle:
                handle.write(b"tampered")
            with self.assertRaisesRegex(ValueError, "Frozen model"):
                hk.choose_thresholds(output)
            self.assertFalse((output / "threshold-started.json").exists())

    def test_tampered_threshold_is_rejected_before_validation_access(self):
        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.fixture(Path(directory))
            self.fit_quietly(output)
            hk.choose_thresholds(output)
            path = output / "thresholds.json"
            document = json.loads(path.read_text())
            document["results"]["101"]["selected"]["threshold"] += 0.01
            path.write_text(json.dumps(document))
            with (patch.object(hk.gp, "read_development", side_effect=AssertionError("Premature validation")),
                  self.assertRaisesRegex(ValueError, "Threshold evidence")):
                hk.evaluate_frozen(output)

    def test_solver_failure_is_preserved_without_silently_removing_candidate(self):
        from sklearn.exceptions import ConvergenceWarning

        with tempfile.TemporaryDirectory() as directory:
            output, _ = self.fixture(Path(directory))
            with (patch.object(hk, "estimator", side_effect=ConvergenceWarning("Synthetic failure")),
                  self.assertRaises(ConvergenceWarning)):
                self.fit_quietly(output)
            self.assertTrue((output / "fit-failure.json").exists())
            self.assertFalse((output / "fitted.json").exists())
            with self.assertRaises(FileExistsError):
                hk.fit(output)


if __name__ == "__main__":
    unittest.main()
