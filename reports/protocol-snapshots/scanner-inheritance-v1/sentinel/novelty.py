"""Conservative source-level signals for unknown smart-contract risk.

These rules identify unusual capability combinations, not exploitability. Every
result is a human-review candidate and is deliberately excluded from automated
PoC generation and remediation.
"""
from __future__ import annotations

import hashlib
import re

from sentinel.schemas.vulnerability import FindingStatus, VulnerabilityFinding


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _functions(source: str) -> list[tuple[str, str, int, int]]:
    """Return named Solidity functions with their header/body using balanced braces."""
    results: list[tuple[str, str, int, int]] = []
    for match in re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{", source):
        depth, cursor = 1, match.end()
        while cursor < len(source) and depth:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth == 0:
            results.append((match.group(1), source[match.start():cursor], match.start(), cursor))
    return results


def _candidate(path: str, detector: str, function: str, offset: int, description: str, evidence: list[str]) -> VulnerabilityFinding:
    digest = hashlib.sha256(f"{path}|{detector}|{function}|{offset}".encode()).hexdigest()[:16]
    return VulnerabilityFinding(
        id=f"novelty-{digest}", source="novelty-heuristic", sources=["novelty-heuristic"],
        detector=detector, severity="medium", confidence="low", confidence_score=0.3,
        file=path, line=offset, function=function, description=description, evidence=evidence,
        status=FindingStatus.HUMAN_REVIEW_REQUIRED,
    )


def detect_novelty_signals(sources: dict[str, str]) -> tuple[dict[str, object], list[VulnerabilityFinding]]:
    """Find high-signal execution combinations that merit adversarial review.

    This is intentionally source-only and deterministic. It does not connect to
    a chain, execute a transaction, or assign a confirmed-vulnerability label.
    """
    findings: list[VulnerabilityFinding] = []
    signal_counts: dict[str, int] = {}
    for path, source in sorted(sources.items()):
        for name, block, start, _ in _functions(source):
            line = _line_number(source, start)
            header = block.split("{", 1)[0]
            has_address_input = bool(re.search(r"\baddress(?:\s+payable)?\s+\w+", header))
            has_bytes_input = bool(re.search(r"\bbytes(?:\s+calldata|\s+memory)?\s+\w+", header))
            if ".delegatecall" in block and has_address_input:
                detector = "parameterized-delegatecall"
                findings.append(_candidate(
                    path, detector, name, line,
                    "A function combines an address input with delegatecall; review whether caller-controlled data can select code executed in this contract's storage context.",
                    ["delegatecall appears in the same function as an address input", "Source heuristic only; no execution path was proven."],
                ))
                signal_counts[detector] = signal_counts.get(detector, 0) + 1
            if ".call(" in block and has_bytes_input:
                detector = "opaque-call-forwarding"
                findings.append(_candidate(
                    path, detector, name, line,
                    "A function accepts bytes and forwards a low-level call; review destination controls, selector allowlists, and post-call state handling.",
                    ["low-level call and bytes input appear in the same function", "Source heuristic only; calldata reachability was not proven."],
                ))
                signal_counts[detector] = signal_counts.get(detector, 0) + 1
            if "assembly" in block and "sstore" in block and re.search(r"\b(?:call|delegatecall|selfdestruct)\b", block):
                detector = "opaque-execution-corridor"
                findings.append(_candidate(
                    path, detector, name, line,
                    "Inline assembly changes storage alongside a low-level execution primitive; review invariants and access boundaries that static analyzers may not model.",
                    ["assembly storage write (sstore) and low-level execution primitive share a function", "Source heuristic only; no invariant violation was proven."],
                ))
                signal_counts[detector] = signal_counts.get(detector, 0) + 1
        privileged = bool(re.search(r"\b(?:onlyOwner|onlyRole|_checkRole|require\s*\([^)]*owner)", source))
        if privileged:
            for name, block, start, _ in _functions(source):
                header = block.split("{", 1)[0]
                mutates_state = bool(re.search(r"(?<![=!<>])=(?!=)|\b(?:transfer|send)\s*\(", block))
                public_surface = bool(re.search(r"\b(?:public|external)\b", header))
                guarded = bool(re.search(r"\b(?:onlyOwner|onlyRole|nonReentrant)\b", header))
                if public_surface and mutates_state and not guarded:
                    detector = "privilege-boundary-outlier"
                    findings.append(_candidate(
                        path, detector, name, _line_number(source, start),
                        "This public state-changing function sits beside privileged controls but declares no recognizable access modifier; review the intended authorization model.",
                        ["Privileged-control indicators exist in the contract source", "Public/external function has a state-change signal without a recognized modifier", "Source heuristic only; authorization may be enforced internally."],
                    ))
                    signal_counts[detector] = signal_counts.get(detector, 0) + 1
    return {
        "method": "deterministic-source-heuristics",
        "candidate_count": len(findings),
        "signal_counts": signal_counts,
        "review_required": bool(findings),
        "scope": "Unknown-risk triage only; no exploitability or safety conclusion.",
    }, findings
