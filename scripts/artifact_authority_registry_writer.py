from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Any, MutableMapping


REGISTRY_RELATIVE_PATH = "registry/artifact_authority_registry.json"
DIGEST_SEMANTICS = {
    "sha256": "HISTORICAL_REGISTRATION_BYTES",
    "current_file_sha256": "CURRENT_REPOSITORY_BYTES",
    "self_excluded_path": REGISTRY_RELATIVE_PATH,
}


def _repository_path(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("registry artifact path must be a non-empty string")
    if relative.startswith("/") or "\\" in relative or ":" in relative:
        raise ValueError(f"registry artifact path is not repository-relative: {relative!r}")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} or part.endswith((".", " ")) for part in parts):
        raise ValueError(f"registry artifact path is not a portable direct path: {relative!r}")

    root = root.resolve()
    candidate = root.joinpath(*parts)
    for component in (candidate, *candidate.parents):
        if component == root:
            break
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"registry artifact path traverses a link or reparse point: {relative!r}")
    if not candidate.is_file():
        raise ValueError(f"registry artifact is missing or not a regular file: {relative!r}")
    return candidate


def bind_current_file_digests(
    registry_path: Path,
    registry: MutableMapping[str, Any],
) -> None:
    """Bind every registry row to current repository bytes before a writer persists it."""
    registry_path = Path(registry_path)
    if registry_path.name != "artifact_authority_registry.json" or registry_path.parent.name != "registry":
        raise ValueError("authority registry writer received a noncanonical registry path")
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("authority registry artifacts must be a list")

    root = registry_path.parent.parent
    for index, row in enumerate(artifacts):
        if not isinstance(row, dict):
            raise ValueError(f"authority registry artifact {index} must be an object")
        relative = row.get("path")
        if relative == REGISTRY_RELATIVE_PATH:
            row["current_file_sha256"] = None
            continue
        current = _repository_path(root, relative)
        row["current_file_sha256"] = hashlib.sha256(current.read_bytes()).hexdigest()

    registry["artifact_count"] = len(artifacts)
    registry["digest_semantics"] = dict(DIGEST_SEMANTICS)
