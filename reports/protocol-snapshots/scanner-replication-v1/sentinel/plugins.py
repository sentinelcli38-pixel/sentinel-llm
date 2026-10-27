"""Configuration-only integration plugins; no network actions occur here."""
from pydantic import BaseModel, Field


class MonitorPluginConfig(BaseModel):
    target_chain: str = Field(min_length=1, max_length=64)
    rpc_endpoint: str = Field(min_length=1, max_length=500)
    contract_addresses: list[str] = Field(default_factory=list, max_length=100)
    alert_destination: str = ""
    enabled: bool = False


def plugin_catalog() -> list[dict[str, object]]:
    return [{
        "id": "onchain-monitor",
        "name": "On-chain monitor",
        "status": "configuration_required",
        "required_fields": ["target_chain", "rpc_endpoint", "contract_addresses"],
        "note": "Configuration is local only. Enabling does not connect to an RPC endpoint in this release.",
    }]
