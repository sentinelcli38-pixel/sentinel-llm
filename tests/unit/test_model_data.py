import json
from pathlib import Path

import pytest

from sentinel.modeling.data import audit_dataset, prepare_dataset, strip_comments


def test_comments_do_not_leak_annotations_or_shift_lines() -> None:
    source = '/* @vulnerable_at_lines: 3\nREENTRANCY */\nstring x = "https://a/*b*/"; // vulnerable\n'
    cleaned = strip_comments(source)
    assert cleaned.count("\n") == source.count("\n")
    assert "@vulnerable" not in cleaned
    assert "REENTRANCY" not in cleaned
    assert '"https://a/*b*/"' in cleaned


def test_repository_splits_stay_together_and_tampering_is_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    annotations = []
    for index in range(12):
        filename = f"Case{index}.sol"
        (corpus / filename).write_text(f"contract C{index} {{}} // <yes> REENTRANCY\n")
        annotations.append({"path": filename, "source": f"https://github.com/a/project{index // 2}/blob/main/{filename}",
                            "vulnerabilities": [{"category": "reentrancy", "lines": [1]}]})
    (corpus / "vulnerabilities.json").write_text(json.dumps(annotations))
    output = tmp_path / "data"
    prepare_dataset(corpus, output)
    assert audit_dataset(output)["status"] == "passed"
    with (output / "train.jsonl").open("a") as handle:
        handle.write("{}\n")
    with pytest.raises(ValueError, match="Dataset changed"):
        audit_dataset(output)
