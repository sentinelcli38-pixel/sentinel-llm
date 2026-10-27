import difflib
import json
from pathlib import Path

from sentinel.llm.base import LLMProvider
from sentinel.patching.applier import apply_replacement
from sentinel.schemas.artifacts import PatchArtifact
from sentinel.schemas.state import RuntimeState


class BlueTeam:
    """Layer 3: Minimal Invasive Change patch synthesis for the MVP demonstrations."""

    def __init__(self, provider: LLMProvider[str] | None = None) -> None:
        self.provider = provider

    def generate_and_apply(self, state: RuntimeState) -> RuntimeState:
        finding = next((item for item in state.findings if item.id == state.candidate_id), None)
        if finding is None or not state.exploit_confirmed:
            return state
        relative = finding.file
        workspace = Path(state.workspace_path or state.project_path)
        path = workspace / relative
        original = path.read_text(encoding="utf-8")
        if finding.id == "heuristic-reentrancy":
            old = '''        uint256 amount = balances[msg.sender];
        (bool sent,) = msg.sender.call{value: amount}(""); // reentrancy demo
        require(sent, "send failed");
        balances[msg.sender] = 0;'''
            new = '''        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool sent,) = msg.sender.call{value: amount}(""); // reentrancy demo
        require(sent, "send failed");'''
        elif finding.id == "heuristic-access-control":
            old = "function sweep(address payable recipient) external {"
            new = "function sweep(address payable recipient) external {\n        require(msg.sender == owner, \"not owner\");"
        elif finding.id == "heuristic-tx-origin":
            old = "require(tx.origin == owner, \"not owner\");"
            new = "require(msg.sender == owner, \"not owner\");"
        elif finding.id == "heuristic-unchecked-call":
            old = "        recipient.call{value: amount}(\"\"); // unchecked low-level call"
            new = "        (bool sent,) = recipient.call{value: amount}(\"\");\n        require(sent, \"send failed\");"
        else:
            if self.provider is None:
                state.feedback.append("Blue Team has no provider for this candidate.")
                state.final_verification_state = "human_review_required"
                return state
            prompt = (
                "Generate a minimal security patch as a unified diff. Modify only the supplied existing Solidity "
                "file, preserve its public ABI, and return only a diff with --- a/ and +++ b/ headers. "
                "Do not add, delete, rename, or modify test files.\n"
                + json.dumps({"finding": finding.model_dump(mode="json"), "file": relative, "source": original})
            )
            try:
                patch = self._extract_diff(self.provider.generate(prompt))
                if f"+++ b/{relative}" not in patch:
                    raise ValueError("response targets a different file")
                original_copy = original
                from sentinel.patching.applier import apply_unified_diff
                targets = apply_unified_diff(workspace, patch, set(state.original_source))
                if targets != [relative]:
                    raise ValueError("response must modify only the candidate file")
                if path.read_text(encoding="utf-8") == original_copy:
                    raise ValueError("response did not change the target file")
                old = new = None
            except (RuntimeError, ValueError) as exc:
                path.write_text(original, encoding="utf-8")
                state.feedback.append(f"Blue Team provider could not apply a patch: {exc}")
                state.final_verification_state = "human_review_required"
                return state
        if old is None:
            patched = path.read_text(encoding="utf-8")
        elif old not in original:
            state.feedback.append("Blue Team could not locate a minimal patch anchor")
            state.final_verification_state = "human_review_required"
            return state
        else:
            apply_replacement(workspace, relative, old, new, set(state.original_source))
            patched = path.read_text(encoding="utf-8")
        state.patched_source[relative] = patched
        state.patch_diff = "".join(difflib.unified_diff(original.splitlines(True), patched.splitlines(True), fromfile=relative, tofile=relative))
        state.patch_artifact = PatchArtifact(
            vulnerability_id=finding.id, original_file=relative, patch=state.patch_diff,
            rationale="Only the vulnerable state-update/authorization region was changed.",
            attempt=state.retry_count + 1,
        )
        return state

    @staticmethod
    def _extract_diff(response: str) -> str:
        blocks = response.split("```diff", 1)
        if len(blocks) == 2:
            response = blocks[1].split("```", 1)[0]
        patch = response.strip() + "\n"
        if "--- a/" not in patch or "+++ b/" not in patch or "@@" not in patch:
            raise ValueError("response must contain a unified diff")
        return patch
