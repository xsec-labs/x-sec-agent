"""Path helpers for xSecAgent runtime artifacts.

Skill source files and templates are read-only. Runtime artifacts should live
under XSEC_RUN_ROOT, or under the repository .xsec-runs/default directory.
"""

from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_PREFIXES = {
    "evidence",
    "reports",
    "tmp",
    "data",
    "tools",
    "upload-fuzz-output",
    "social_dicts",
}
PROTECTED_DIRS = [
    REPO_ROOT / "templates",
    REPO_ROOT / "references",
    REPO_ROOT / "skills",
]
PROTECTED_FILES = {
    (REPO_ROOT / "SKILL.md").resolve(),
}


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def run_root() -> Path:
    configured = os.environ.get("XSEC_RUN_ROOT") or os.environ.get("XSEC_OUTPUT_ROOT")
    return Path(configured).expanduser().resolve() if configured else (REPO_ROOT / ".xsec-runs" / "default").resolve()


def _first_part(path_text: str) -> str:
    parts = Path(path_text).parts
    while parts and parts[0] in {".", ""}:
        parts = parts[1:]
    return parts[0] if parts else ""


def uses_run_root(path_text: str) -> bool:
    path = Path(path_text).expanduser()
    return not path.is_absolute() and _first_part(path_text) in RUN_PREFIXES


def resolve_artifact_path(path_text: str | os.PathLike[str]) -> Path:
    raw = str(path_text)
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path.resolve()
    if uses_run_root(raw):
        return (run_root() / path).resolve()
    return (Path.cwd() / path).resolve()


def assert_writable_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.name == "SKILL.md" or resolved in PROTECTED_FILES:
        raise ValueError(f"refusing to write Skill source file: {resolved}")
    for protected in PROTECTED_DIRS:
        protected = protected.resolve()
        if resolved == protected or _is_relative_to(resolved, protected):
            raise ValueError(f"refusing to write Skill source directory: {resolved}")
    return resolved


def resolve_output_path(path_text: str | os.PathLike[str]) -> Path:
    return assert_writable_path(resolve_artifact_path(path_text))
