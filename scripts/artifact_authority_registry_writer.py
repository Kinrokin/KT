from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Any, MutableMapping


REGISTRY_RELATIVE_PATH = "registry/artifact_authority_registry.json"
DIGEST_SEMANTICS = {
    "sha256": "HISTORICAL_REGISTRATION_BYTES",
    "current_file_sha256": "CURRENT_REPOSITORY_BYTES",
    "self_excluded_path": REGISTRY_RELATIVE_PATH,
}
HISTORICAL_STATES = {"ARCHIVE", "STALE", "DUPLICATE", "SUPERSEDED", "RETIRED"}
_RESERVED_DEVICE_BASENAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
_PRIMARY_CLASS_ALIASES = {
    "GENERATED_RUNTIME_PACKET": "GENERATED_OUTPUT",
    "CANONICAL_RUNBOOK": "CANONICAL_GOVERNANCE",
    "EVIDENCE_ARCHIVE": "ARCHIVE_HISTORY",
    "EVIDENCE_SUMMARY": "ARCHIVE_HISTORY",
    "EVIDENCE_LEDGER": "ARCHIVE_HISTORY",
    "CANONICAL_FIXTURE": "ARCHIVE_HISTORY",
}


def _unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError(f"non-finite JSON value: {value}")


def _load_json(path: Path) -> Any:
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_json_keys,
        parse_constant=_no_constant,
        parse_float=finite_float,
    )


def _field_errors(value: object, schema: dict, location: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{location}: expected object"]
    errors = [
        f"{location}: missing required field {key}"
        for key in schema["required"]
        if key not in value
    ]
    types = {
        "string": str,
        "boolean": bool,
        "integer": int,
        "array": list,
        "object": dict,
        "null": type(None),
    }
    for key, rule in schema["properties"].items():
        if key not in value:
            continue
        field = value[key]
        if "type" in rule:
            allowed = rule["type"] if isinstance(rule["type"], list) else [rule["type"]]
            if type(field) not in tuple(types[name] for name in allowed):
                errors.append(f"{location}.{key}: invalid type")
        if "enum" in rule and field not in rule["enum"]:
            errors.append(f"{location}.{key}: value outside declared enum")
        if "const" in rule and field != rule["const"]:
            errors.append(f"{location}.{key}: unexpected value")
    return errors


def _validate_registry_contract(root: Path, registry: MutableMapping[str, Any]) -> None:
    schema = _load_json(root / "registry" / "artifact_authority_registry.schema.json")
    if not isinstance(schema, dict) or schema.get("$id") != "kt.artifact_authority_registry.schema.v3":
        raise ValueError("unsupported authority registry schema")
    errors = _field_errors(registry, schema, "registry")
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("registry.artifacts: expected array")
        artifacts = []
    if registry.get("artifact_count") != len(artifacts):
        errors.append("registry.artifact_count does not match artifacts")
    if registry.get("digest_semantics") != DIGEST_SEMANTICS:
        errors.append("registry digest semantics mismatch")

    row_schema = schema["properties"]["artifacts"]["items"]
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    for index, row in enumerate(artifacts):
        location = f"artifacts[{index}]"
        errors.extend(_field_errors(row, row_schema, location))
        if not isinstance(row, dict):
            continue
        path = row.get("path")
        identity = row.get("artifact_id")
        if isinstance(path, str):
            normalized = unicodedata.normalize("NFKC", path).casefold()
            if normalized in seen_paths:
                errors.append(f"{location}: duplicate artifact path")
            seen_paths.add(normalized)
        if isinstance(identity, str):
            if identity in seen_ids:
                errors.append(f"{location}: duplicate artifact_id")
            seen_ids.add(identity)
        current_digest = row.get("current_file_sha256")
        if path == REGISTRY_RELATIVE_PATH:
            if current_digest is not None:
                errors.append(f"{location}: registry self digest must be null")
        elif not isinstance(current_digest, str) or re.fullmatch(r"[0-9a-f]{64}", current_digest) is None:
            errors.append(f"{location}: current file digest missing or malformed")
        if row.get("primary_class") == "UNKNOWN_REVIEW_REQUIRED":
            errors.append(f"{location}: unknown artifact review required")
        if (
            row.get("controls_execution") is True
            and (
                row.get("authority_state") != "LIVE_CURRENT_HEAD_VALIDATED"
                or row.get("validation_status") != "PASS"
            )
        ):
            errors.append(f"{location}: execution control requires validated live PASS")
        historical = (
            row.get("primary_class") in {"ARCHIVE_HISTORY", "GENERATED_OUTPUT"}
            or row.get("authority_state") in HISTORICAL_STATES
        )
        if historical and (
            row.get("controls_execution") is True or row.get("current_authority") is True
        ):
            errors.append(f"{location}: historical or generated row cannot be current")
    if errors:
        raise ValueError("authority registry v3 validation failed: " + " | ".join(errors))


def _repository_path(root: Path, relative: object) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("registry artifact path must be a non-empty string")
    if relative.startswith("/") or "\\" in relative or ":" in relative:
        raise ValueError(f"registry artifact path is not repository-relative: {relative!r}")
    parts = relative.split("/")
    if any(
        part in {"", ".", ".."}
        or part.endswith((".", " "))
        or part.split(".", 1)[0].upper() in _RESERVED_DEVICE_BASENAMES
        for part in parts
    ):
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


def _sha256_repository_file(root: Path, relative: str) -> str:
    'Hash a registered file through an O_NOFOLLOW descriptor walk.'
    parts = relative.split("/")
    if os.name != "nt" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(root.resolve(), flags)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            leaf = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=fd,
            )
            try:
                before = os.fstat(leaf)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError(f"registry artifact is not a regular file: {relative!r}")
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(leaf, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(leaf)
                if any(
                    getattr(before, field) != getattr(after, field)
                    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                ):
                    raise ValueError(f"registry artifact changed during read: {relative!r}")
                return digest.hexdigest()
            finally:
                os.close(leaf)
        finally:
            os.close(fd)
    candidate = _repository_path(root, relative)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(candidate, flags)
    try:
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def existing_artifact_ids_for_paths(registry: MutableMapping[str, Any], paths: list[str]) -> list[str]:
    """Require one admitted canonical row per generated path without changing its authority."""
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("authority registry artifacts must be a list")
    by_path: dict[str, list[dict]] = {}
    for row in artifacts:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("authority registry contains an invalid artifact row")
        key = unicodedata.normalize("NFKC", row["path"]).casefold()
        by_path.setdefault(key, []).append(row)
    identities = []
    for path in paths:
        if not isinstance(path, str):
            raise ValueError("generated artifact path must be a string")
        matches = by_path.get(unicodedata.normalize("NFKC", path).casefold(), [])
        if len(matches) != 1 or matches[0]["path"] != path:
            raise ValueError(f"generated artifact requires one exact canonical registration: {path}")
        identities.append(matches[0]["artifact_id"])
    if len(set(paths)) != len(paths):
        raise ValueError("generated artifacts contain duplicate paths")
    return identities


def _normalize_explicit_nonexecuting_rows(registry: MutableMapping[str, Any]) -> None:
    """Convert legacy rows only when their own metadata explicitly forbids authority."""
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        return
    allowed_markers = ("PREP", "SHADOW", "DIAGNOSTIC", "REPLAY", "BLOCKED", "EVIDENCE", "LAB")
    required = {"primary_class", "authority_state", "validation_status", "claim_authority",
                "controls_execution", "sha256", "current_authority"}
    for index, row in enumerate(artifacts):
        if not isinstance(row, dict) or required.issubset(row):
            continue
        legacy_key = row.get("authority") or row.get("status")
        role_key = row.get("role")
        legacy_state = legacy_key
        if legacy_state is None and isinstance(role_key, str) and role_key.startswith("v17_7_3_"):
            legacy_state = row.get("authority_state")
        explicit_nonexec = (
            isinstance(legacy_state, str)
            and any(marker in legacy_state.upper() for marker in allowed_markers)
            and row.get("controls_execution") is not True
            and row.get("runtime_authority") is not True
            and row.get("promotion_authority") is not True
            and row.get("claim_expansion") is not True
        )
        if not explicit_nonexec or row.get("current_authority") is True:
            continue
        row.pop("authority", None)
        row.pop("status", None)
        row["role"] = row.get("role") or "generated_output"
        row["primary_class"] = "GENERATED_OUTPUT"
        row["authority_state"] = "GENERATED_PENDING_VALIDATION"
        row["validation_status"] = row.get("validation_status") or "PASS"
        row["controls_execution"] = False
        row["claim_authority"] = "NONE"
        row["sha256"] = row.get("sha256")
        row["current_authority"] = False
        row.setdefault("supersedes", [])
        row.setdefault("superseded_by", None)


def merge_registry_entries(registry: MutableMapping[str, Any], entries: list[dict[str, Any]]) -> None:
    """Append only genuinely new paths; preserve admitted identity and authority rows."""
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("authority registry artifacts must be a list")
    by_path = {
        row["path"]: row for row in artifacts
        if isinstance(row, dict) and isinstance(row.get("path"), str)
    }
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str):
            raise ValueError("registry entry path must be a string")
        if path in by_path:
            continue
        artifacts.append(entry)
        by_path[path] = entry


def _normalize_primary_class_alias(row: dict[str, Any]) -> None:
    primary_class = row.get("primary_class")
    mapped = _PRIMARY_CLASS_ALIASES.get(primary_class)
    if mapped is None:
        return
    row["primary_class"] = mapped
    if mapped == "ARCHIVE_HISTORY":
        row["authority_state"] = "ARCHIVE"
        row["current_authority"] = False
        row["controls_execution"] = False
        row["claim_authority"] = "NONE"


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
    _normalize_explicit_nonexecuting_rows(registry)

    root = registry_path.parent.parent
    for index, row in enumerate(artifacts):
        if not isinstance(row, dict):
            raise ValueError(f"authority registry artifact {index} must be an object")
        _normalize_primary_class_alias(row)
        relative = row.get("path")
        if relative == REGISTRY_RELATIVE_PATH:
            row["current_file_sha256"] = None
            continue
        current = _repository_path(root, relative)
        row["current_file_sha256"] = _sha256_repository_file(root, relative)

    registry["artifact_count"] = len(artifacts)
    registry["digest_semantics"] = dict(DIGEST_SEMANTICS)
    _validate_registry_contract(root, registry)


def rebind_authority_registry_file(registry_path: Path) -> None:
    """Refresh final output digests and atomically persist one valid v3 registry."""
    registry_path = Path(registry_path)
    registry = _load_json(registry_path)
    if not isinstance(registry, dict):
        raise ValueError("authority registry must be an object")
    bind_current_file_digests(registry_path, registry)
    temporary = registry_path.with_name(f".{registry_path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise FileExistsError(f"refusing to replace existing registry temporary: {temporary}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(registry, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, registry_path)
    finally:
        temporary.unlink(missing_ok=True)
