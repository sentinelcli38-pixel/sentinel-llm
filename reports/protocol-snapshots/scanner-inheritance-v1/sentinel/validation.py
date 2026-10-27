"""Project-declared validation oracles for evidence-based repair acceptance."""
from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class ValidationProfile(BaseModel):
    """Optional checks stored beside a Foundry project in sentinel-validation.yml."""

    positive_tests: list[str] = Field(default_factory=list)
    security_tests: list[str] = Field(default_factory=list)
    require_abi_compatibility: bool = False
    require_storage_declaration_compatibility: bool = False

    @field_validator("positive_tests", "security_tests")
    @classmethod
    def valid_test_selectors(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) for item in values):
            raise ValueError("Validation test selectors must be Solidity test identifiers")
        return values


def load_validation_profile(project: Path) -> ValidationProfile:
    path = project / "sentinel-validation.yml"
    if not path.is_file():
        return ValidationProfile()
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise TypeError("sentinel-validation.yml must be a mapping")
    return ValidationProfile.model_validate(document)


def declared_public_api(sources: dict[str, str]) -> set[str]:
    """Return declared public/external function headers, not a full compiler ABI."""
    result: set[str] = set()
    for path, source in sources.items():
        for match in re.finditer(r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\b(?:public|external)\b[^\{;]*", source):
            result.add(f"{path}:{' '.join(match.group(0).split())}")
    return result


def declared_storage(sources: dict[str, str]) -> set[str]:
    """Conservative source declaration fingerprint; not a compiler storage-layout proof."""
    result: set[str] = set()
    for path, source in sources.items():
        depth, buffer = 0, ""
        for character in source:
            buffer += character
            if character == "{":
                depth += 1
                buffer = ""
            elif character == "}":
                depth -= 1
                buffer = ""
            elif character == ";":
                declaration = " ".join(buffer[:-1].split())
                if depth == 1 and "(" not in declaration and not declaration.startswith(("//", "using ", "event ", "error ", "modifier ")):
                    result.add(f"{path}:{declaration}")
                buffer = ""
    return result
