"""Local human-review records for candidates that must not be auto-remediated."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field


class ReviewRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    finding_id: str
    ledger_name: str
    decision: str = "pending"
    rationale: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def review_directory(output: Path) -> Path:
    return output / "reviews"


def save_review(output: Path, record: ReviewRecord) -> ReviewRecord:
    directory = review_directory(output)
    directory.mkdir(parents=True, exist_ok=True)
    record.updated_at = datetime.now(UTC)
    (directory / f"{record.id}.json").write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return record


def list_reviews(output: Path) -> list[ReviewRecord]:
    records = []
    for path in review_directory(output).glob("*.json") if review_directory(output).is_dir() else []:
        try:
            records.append(ReviewRecord.model_validate_json(path.read_text(encoding="utf-8")))
        except ValueError:
            continue
    return sorted(records, key=lambda item: item.updated_at, reverse=True)


def export_review_summary(records: list[ReviewRecord]) -> str:
    return json.dumps({"reviews": [item.model_dump(mode="json") for item in records]}, indent=2) + "\n"
