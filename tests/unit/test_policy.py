from sentinel.policy import evaluate_policy
from sentinel.protocol import build_protocol_map
from sentinel.reporting.sarif import render_sarif
from sentinel.risk import assess_protocol_risk
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import FindingStatus, VulnerabilityFinding


def finding(status: FindingStatus = FindingStatus.CANDIDATE) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        id="issue", source="test", detector="unchecked-call", severity="high",
        file="src/Vault.sol", line=10, description="unchecked call", status=status,
    )


def test_policy_blocks_high_unverified_findings() -> None:
    decision = evaluate_policy(RuntimeState(project_path="/project", findings=[finding()]), {"block_severity": "high"})
    assert decision.status == "blocked"


def test_policy_does_not_clear_warnings_after_a_failed_poc() -> None:
    state = RuntimeState(project_path="/project", findings=[finding(FindingStatus.DISCARDED)])
    assert evaluate_policy(state, {"block_severity": "high"}).status == "blocked"


def test_sarif_and_protocol_map_preserve_source_evidence() -> None:
    state = RuntimeState(project_path="/project", findings=[finding()])
    sarif = render_sarif(state)
    protocol = build_protocol_map({"src/Proxy.sol": 'contract Proxy { function x() external { a.delegatecall(""); } }'})
    assert sarif["runs"][0]["results"][0]["ruleId"] == "unchecked-call"
    assert protocol["contracts"][0]["upgrade_signals"] == ["delegatecall"]


def test_protocol_risk_marks_compound_signals_for_review() -> None:
    risk = assess_protocol_risk(
        {"contracts": [{"name": "Vault", "file": "src/Vault.sol", "external_call_sites": 1, "upgrade_signals": ["delegatecall"]}], "relationships": []},
        [finding()],
    )
    assert risk["assessments"][0]["priority"] == "elevated"
