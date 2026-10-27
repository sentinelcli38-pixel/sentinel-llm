"""Evidence requirements for future generalized PoC and patch generation."""
from sentinel.schemas.state import RuntimeState


def requires_human_review(state: RuntimeState) -> bool:
    candidate = next((item for item in state.findings if item.id == state.candidate_id), None)
    return candidate is None or not candidate.evidence or candidate.source != "local-heuristic"
