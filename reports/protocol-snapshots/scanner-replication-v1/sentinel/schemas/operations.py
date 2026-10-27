from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class MonitorRule(BaseModel):
    id: str
    kind: Literal["coverage", "confirmed_finding", "verification", "novelty_review"]
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    enabled: bool = True


class AlertRecord(BaseModel):
    id: str
    rule_id: str
    severity: str
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime


class SimulationRecord(BaseModel):
    scenario: str
    adapter: str
    status: Literal["queued", "unavailable", "completed", "failed"]
    evidence: str = ""


class BenchmarkSummary(BaseModel):
    evaluated: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    false_positive_rate: float | None = None
