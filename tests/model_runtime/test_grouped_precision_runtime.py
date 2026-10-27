"""Optional CPU dependency checks using synthetic fixtures, not security benchmarks."""

import contextlib
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
from sentinel.modeling.properties import CGT_REVISION, PROPERTIES, property_messages
from training import grouped_precision as gp
from training import provisional_review as review


@unittest.skipUnless(importlib.util.find_spec("sklearn") and importlib.util.find_spec("numpy"),
                     "Run with the isolated optional probe interpreter")
class GroupedPrecisionRuntimeTest(unittest.TestCase):
    def fixture(self, root):
        dataset, probe, previous = (root / name for name in ("dataset", "probe", "previous"))
        for directory in (dataset, probe, previous / "review-inputs"):
            directory.mkdir(parents=True)
        rows = {}
        for split, groups in (("train", 8), ("valid", 1)):
            rows[split] = []
            for group in range(groups):
                for truth in (False, True):
                    contract = f"Case_{split}_{group}_{truth}"
                    body = "msg.sender.call.value(1)();" if truth else "require(msg.sender == owner);"
                    source = f"contract {contract} {{ address owner; function act() public {{ {body} }} }}"
                    if split == "valid":
                        source += "\n// UNSEENVALUEQX reserved fixture marker"
                    for swc in PROPERTIES:
                        key = f"{split}_{group}_{truth}_{swc}"
                        rows[split].append({"id": key, "task": "swc_property", "swc": swc, "contract": contract,
                            "source_hash": gp.sha(source.encode()), "project_group": f"{split}-group-{group}",
                            "lexical_fingerprint": f"synthetic-{split}-{group}-{truth}",
                            "messages": [*property_messages(source, swc, contract),
                                {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]})
            (dataset / f"{split}.jsonl").write_text("\n".join(json.dumps(r) for r in rows[split]) + "\n")
        manifest = {"source_revision": CGT_REVISION, "task": "swc_property",
                    "split_counts": {k: len(v) for k, v in rows.items()},
                    "split_sha256": {k: gp.file_hash(dataset / f"{k}.jsonl") for k in rows}}
        (dataset / "manifest.json").write_text(json.dumps(manifest))
        _, pins = gp.read_training(dataset)
        original = {"input_pins": pins, "selection": {"train_ids": [r["id"] for r in rows["train"]]}}
        gp.write_json(probe / "protocol.json", original)
        reviewed = [r for r in rows["train"] if r["swc"] == "104"]
        cases = [{"id": r["id"], "target_contract": r["contract"], "source_sha256": r["source_hash"],
                  "group": "development", "provenance": {"role": "training"},
                  "vulnerability_class": f"SWC-104: {PROPERTIES['104']}"} for r in reviewed]
        raw_manifest = json.dumps({"cases": cases}).encode()
        mapping, blind = {}, []
        for r in reviewed:
            rid = "review-" + gp.sha(f"{gp.sha(raw_manifest)}:{r['id']}".encode())[:16]
            mapping[rid] = r["id"]
            blind.append({"review_id": rid, "target_contract": r["contract"], "source_sha256": r["source_hash"],
                          "blind_source_sha256": r["source_hash"], "line_count": 1, "context_files": [],
                          "vulnerability_class": f"SWC-104: {PROPERTIES['104']}"})
        packet = json.dumps({"manifest_sha256": gp.sha(raw_manifest), "cases": blind}).encode()
        raws = {"packet": packet, "manifest": raw_manifest, "mapping": json.dumps({"case_mapping": mapping}).encode()}
        for name in ("a", "b"):
            raws[name] = json.dumps({"packet_sha256": gp.sha(packet), "manifest_sha256": gp.sha(raw_manifest),
                "reviewer": {"id": f"synthetic-ai-{name}", "kind": "ai"},
                "reviews": [{"review_id": c["review_id"], "source_sha256": c["source_sha256"],
                             "decision": "vulnerable" if gp.source_and_target(r)[1]["vulnerable"] else "clean",
                             "evidence_lines": [1], "rationale": "Synthetic fixture, not human review."}
                            for c, r in zip(blind, reviewed, strict=True)]}).encode()
        ledger = review.reconcile(raws, rows)
        for name, raw in raws.items():
            (previous / "review-inputs" / review.INPUTS[name]).write_bytes(raw)
        gp.write_json(previous / "review-decisions.json", ledger)
        gp.write_json(previous / "protocol.json", {"implementation_sha256": {}, "dataset": str(dataset),
            "input_pins": pins, "probe": str(probe), "probe_pins": {str((probe / "protocol.json").resolve()): gp.file_hash(probe / "protocol.json")},
            "review_input_sha256": {k: gp.sha(v) for k, v in raws.items()},
            "ledger_sha256": gp.file_hash(previous / "review-decisions.json")})
        return previous, rows

    def test_end_to_end_training_only_selection_frozen_json_replay_and_full_evaluation(self):
        import numpy as np

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, rows = self.fixture(root)
            output = root / "run"
            original_open = Path.open

            def guard(path, *args, **kwargs):
                self.assertNotIn(path.name, {"valid.jsonl", "test.jsonl", "features.npz", "comparison.json"})
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", guard), patch.object(gp, "read_development", side_effect=AssertionError("Validation during selection")):
                prepared = gp.prepare(previous, output)
                self.assertEqual(prepared["training_cases"], 64)
                with contextlib.redirect_stdout(io.StringIO()):
                    selected = gp.fit(output)
            self.assertEqual(set(selected), set(PROPERTIES))
            models = json.loads((output / "models.json").read_text())
            receipt = json.loads((output / "fit.json").read_text())
            self.assertFalse(receipt["validation_accessed"])
            for swc in PROPERTIES:
                evidence = json.loads((output / f"oof-{swc}.json").read_text())
                self.assertEqual(len(evidence["candidates"]), 12)
                self.assertEqual(len(evidence["ids"]), 16)
                for candidate in evidence["candidates"]:
                    self.assertEqual(len(candidate["margins"]), 16)
                    self.assertTrue(all(v is not None for v in candidate["margins"]))
                    self.assertEqual(candidate["selection"], gp.choose_threshold(evidence["labels"], candidate["margins"]))
                self.assertNotIn("UNS", models[swc]["vocabulary"])
                subset = [r for r in rows["valid"] if r["swc"] == swc]
                sources = [gp.source_and_target(r)[0] for r in subset]
                first = gp.replay(models[swc], sources)
                second = gp.replay(json.loads(json.dumps(models[swc])), sources)
                np.testing.assert_allclose(first, second, atol=1e-12)
            with self.assertRaises(FileExistsError):
                gp.fit(output)
            with self.assertRaises(FileExistsError):
                gp.prepare(previous, output)
            result = gp.evaluate_frozen(output)
            self.assertEqual(result["scores"]["cases"], 8)
            comparison = json.loads((output / "comparison.json").read_text())
            gp.verify_report(comparison["full_validation"], rows["valid"])
            self.assertFalse(comparison["llm_weights_updated"])
            self.assertFalse(comparison["validation_labels_changed"])
            self.assertFalse(comparison["target_audit"]["independent_99_percent_claim_supported"])
            with self.assertRaises(FileExistsError):
                gp.evaluate_frozen(output)

    def test_tampered_frozen_model_prevents_any_validation_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, _ = self.fixture(root)
            output = root / "run"
            gp.prepare(previous, output)
            with contextlib.redirect_stdout(io.StringIO()):
                gp.fit(output)
            with (output / "models.json").open("a") as handle:
                handle.write(" ")
            with (patch.object(gp, "read_development", side_effect=AssertionError("Premature validation")),
                  self.assertRaisesRegex(ValueError, "Frozen selected")):
                gp.evaluate_frozen(output)
            self.assertFalse((output / "evaluation-started.json").exists())

    def test_convergence_warning_is_preserved_as_failed_attempt(self):
        from sklearn.exceptions import ConvergenceWarning

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, _ = self.fixture(root)
            output = root / "run"
            gp.prepare(previous, output)
            with (patch.object(gp, "classifier", side_effect=ConvergenceWarning("Synthetic failed candidate")),
                  self.assertRaises(ConvergenceWarning)):
                gp.fit(output)
            self.assertEqual(json.loads((output / "fit-failure.json").read_text())["status"], "failed")
            self.assertFalse((output / "fit.json").exists())
            with self.assertRaises(FileExistsError):
                gp.fit(output)

    def test_word_tokenizer_actually_produces_ngrams_and_character_model_preserves_raw_cues(self):
        tokens = gp.vectorizer("tokens_1_3")
        tokens.fit_transform(["contract Example { uint balance; function withdraw() public {} }"])
        self.assertTrue(any(len(term.split()) == 3 for term in tokens.vocabulary_))
        chars = gp.vectorizer("characters_3_5")
        chars.fit_transform(["pragma solidity ^0.4.26; contract Example {}"])
        self.assertIn("0.4", chars.vocabulary_)
        self.assertTrue(all(3 <= len(term) <= 5 for term in chars.vocabulary_))
        with self.assertRaises(ValueError):
            gp.vectorizer("unregistered")


if __name__ == "__main__":
    unittest.main()
