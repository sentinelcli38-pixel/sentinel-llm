import re
from pathlib import Path


def apply_unified_diff(project: Path, patch: str, allowed_files: set[str]) -> list[str]:
    """Apply only existing, context-checked unified-diff hunks.

    Sentinel never permits creation, deletion, rename metadata, or a partial patch.
    """
    root = project.resolve()
    lines = patch.splitlines(keepends=True)
    targets: list[tuple[str, list[str]]] = []
    index = 0
    while index < len(lines):
        if lines[index].startswith(("diff --git", "index ", "--- ")):
            index += 1
            continue
        if not lines[index].startswith("+++ b/"):
            index += 1
            continue
        relative = lines[index].removeprefix("+++ b/").strip()
        _validate_target(root, relative, allowed_files)
        index += 1
        hunks: list[str] = []
        while index < len(lines) and not lines[index].startswith("+++ b/"):
            if lines[index].startswith("--- "):
                break
            hunks.append(lines[index])
            index += 1
        targets.append((relative, hunks))
    if not targets:
        raise ValueError("Patch contains no controlled target file")
    if len({relative for relative, _ in targets}) != len(targets):
        raise ValueError("Patch modifies the same file more than once")
    for relative, hunks in targets:
        _apply_hunks(root / relative, hunks)
    return [relative for relative, _ in targets]


def _validate_target(root: Path, relative_file: str, allowed_files: set[str]) -> None:
    relative = Path(relative_file)
    if relative_file not in allowed_files or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Patch targets an unauthorized file: {relative_file}")
    path = (root / relative).resolve()
    if root not in path.parents or not path.is_file():
        raise ValueError(f"Patch target does not exist inside project: {relative_file}")


def _apply_hunks(path: Path, hunks: list[str]) -> None:
    original = path.read_text(encoding="utf-8").splitlines(keepends=True)
    output = list(original)
    offset = 0
    index = 0
    header = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    while index < len(hunks):
        match = header.match(hunks[index])
        if not match:
            if hunks[index].startswith("\\ No newline"):
                index += 1
                continue
            raise ValueError("Patch contains content outside a hunk")
        start = int(match.group(1)) - 1 + offset
        index += 1
        old: list[str] = []
        new: list[str] = []
        while index < len(hunks) and not hunks[index].startswith("@@"):
            line = hunks[index]
            if not line or line[0] not in " +-":
                raise ValueError("Malformed patch hunk")
            text = line[1:]
            if line[0] in " -":
                old.append(text)
            if line[0] in " +":
                new.append(text)
            index += 1
        if start < 0 or output[start : start + len(old)] != old:
            raise ValueError(f"Patch context no longer matches {path.name}")
        output[start : start + len(old)] = new
        offset += len(new) - len(old)
    path.write_text("".join(output), encoding="utf-8")


def apply_replacement(project: Path, relative_file: str, old: str, new: str, allowed_files: set[str]) -> None:
    relative = Path(relative_file)
    _validate_target(project.resolve(), relative_file, allowed_files)
    path = (project / relative).resolve()
    if project.resolve() not in path.parents:
        raise ValueError("Patch escaped the target project")
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise ValueError("Patch anchor must occur exactly once")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
