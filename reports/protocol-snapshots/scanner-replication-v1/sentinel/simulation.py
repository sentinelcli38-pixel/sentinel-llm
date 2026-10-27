"""Simulation boundary: adapters record intent and must not submit transactions."""
from sentinel.schemas.operations import SimulationRecord


def prepare_incident_replay(scenario: str, adapter: str = "local-foundry") -> SimulationRecord:
    return SimulationRecord(scenario=scenario, adapter=adapter, status="queued", evidence="Simulation intent recorded. No RPC call or transaction is performed by this adapter.")
