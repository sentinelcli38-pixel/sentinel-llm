"""Conservative, explicit scanner category mapping for labeled experiments."""

from sentinel.schemas.vulnerability import VulnerabilityFinding

SLITHER_CLASSES = {
    "reentrancy-eth": "reentrancy", "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy", "reentrancy-events": "reentrancy",
    "arbitrary-send-eth": "access_control", "suicidal": "access_control",
    "tx-origin": "tx_origin", "unchecked-lowlevel": "unchecked_low_level_calls",
    "unchecked-send": "unchecked_low_level_calls", "timestamp": "time_manipulation",
    "controlled-delegatecall": "access_control",
}
MYTHRIL_CLASSES = {
    "SWC-101": "arithmetic", "SWC-104": "unchecked_low_level_calls",
    "SWC-105": "access_control", "SWC-106": "access_control",
    "SWC-107": "reentrancy", "SWC-115": "tx_origin",
    "SWC-116": "time_manipulation", "SWC-112": "access_control",
}
STATIC_CLASSES = {"unused-call-result": "unchecked_low_level_calls", "origin-auth-alternative": "tx_origin"}
STATIC_CLASSES.update({f"inherited-{name}": "reentrancy" for name in
                       ("reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign", "reentrancy-events")})
ALIASES = {"tx-origin": "tx_origin", "unchecked_call": "unchecked_low_level_calls", "unchecked-call": "unchecked_low_level_calls", "access-control": "access_control"}
SUPPORTED_CLASSES = set(SLITHER_CLASSES.values()) | set(MYTHRIL_CLASSES.values())


def normalized_class(label: str) -> str:
    return ALIASES.get(label, label)


def finding_class(finding: VulnerabilityFinding) -> str | None:
    mapping = {"slither": SLITHER_CLASSES, "mythril": MYTHRIL_CLASSES, "sentinel-static": STATIC_CLASSES}.get(finding.source, {})
    return mapping.get(finding.detector)


def supported_classes(tools: list[str]) -> set[str]:
    mappings = {"slither": SLITHER_CLASSES, "mythril": MYTHRIL_CLASSES, "sentinel-static": STATIC_CLASSES}
    return {category for tool in tools for category in mappings.get(tool, {}).values()}
