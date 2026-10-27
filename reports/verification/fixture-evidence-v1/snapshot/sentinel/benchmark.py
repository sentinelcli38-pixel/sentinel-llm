"""Metric helpers that require caller-supplied ground truth."""
from sentinel.schemas.operations import BenchmarkSummary


def benchmark_record(name: str, summary: BenchmarkSummary, duration_seconds: float, coverage_complete: bool) -> dict[str, object]:
    return {"name": name, "duration_seconds": duration_seconds, "coverage_complete": coverage_complete, **summary.model_dump(mode="json")}


def summarize_benchmark(true_positives: int, false_positives: int, false_negatives: int, true_negatives: int = 0) -> BenchmarkSummary:
    predicted = true_positives + false_positives
    actual = true_positives + false_negatives
    precision = true_positives / predicted if predicted else None
    recall = true_positives / actual if actual else None
    return BenchmarkSummary(
        evaluated=true_positives + false_positives + false_negatives + true_negatives,
        true_positives=true_positives, false_positives=false_positives,
        false_negatives=false_negatives, true_negatives=true_negatives,
        precision=precision, recall=recall,
        f1_score=(2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None,
        false_positive_rate=false_positives / (false_positives + true_negatives) if false_positives + true_negatives else None,
    )
