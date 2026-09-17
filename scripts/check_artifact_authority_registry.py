from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = "registry/artifact_authority_registry.json"
HISTORICAL_STATES = {"ARCHIVE", "STALE", "DUPLICATE", "SUPERSEDED", "RETIRED"}
_RESERVED_DEVICE_BASENAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


def _no_constant(value):
    raise ValueError(f"non-finite JSON value: {value}")


def load_json(path: Path):
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys,
                      parse_constant=_no_constant, parse_float=finite_float)


def current_packet_errors(artifacts: list[dict]) -> list[str]:
    """The existing packet selection is global. Classification grants no permission."""
    selected = [r for r in artifacts if isinstance(r, dict)
                and r.get("primary_class") == "CANONICAL_PACKET_CURRENT"]
    errors = []
    if len(selected) > 1:
        errors.append("overlapping global current execution packets")
    for row in selected:
        if row.get("authority_scope", "GLOBAL") != "GLOBAL":
            errors.append(f"{row.get('path')}: undeclared packet authority scope")
        if (row.get("authority_state") != "LIVE_CURRENT_HEAD_VALIDATED"
                or row.get("validation_status") != "PASS"
                or row.get("controls_execution") is not True
                or row.get("current_authority") is not True):
            errors.append(f"{row.get('path')}: current packet lacks validated current binding")
    return errors


def _markdown_field(text: str, label: str) -> tuple[bool, str | None]:
    matches = re.findall(
        rf"(?mi)^[ \t]*(?:[-*][ \t]+)?{re.escape(label)}:[ \t]*(.*?)[ \t]*$",
        text,
    )
    if len(matches) != 1:
        return False, None
    value = matches[0].strip()
    if len(value) >= 2 and value.startswith("`") and value.endswith("`"):
        value = value[1:-1].strip()
    if value.casefold() in {"none", "none."}:
        return True, None
    return bool(value), value


def _markdown_fields_match(text: str, expected: dict[str, str | None]) -> bool:
    for label, expected_value in expected.items():
        present, actual = _markdown_field(text, label)
        if not present or actual != expected_value:
            return False
    return True


def packet_selection_errors(root: Path, artifacts: list[dict]) -> list[str]:
    contract = load_json(root / "governance/repo_layout_contract.json")
    manifest = load_json(root / "packets/current/manifest.json")
    memory_index = load_json(root / "memory/ARTIFACT_INDEX.json")
    current_truth = load_json(root / "reports/current/current_truth_receipt.json")
    current_context = (root / "memory/CURRENT_CONTEXT.md").read_text(encoding="utf-8")
    next_lawful_move = (root / "memory/NEXT_LAWFUL_MOVE.md").read_text(encoding="utf-8")
    active_cutline = (root / "memory/ACTIVE_CUTLINE.md").read_text(encoding="utf-8")
    if not isinstance(contract, dict) or not isinstance(manifest, dict):
        return ["current packet contract and manifest must be objects"]
    if "current_packet" not in contract or not isinstance(manifest.get("packets"), list):
        return ["current packet contract or manifest missing selection field"]
    current = [r for r in artifacts if isinstance(r, dict)
               and r.get("primary_class") == "CANONICAL_PACKET_CURRENT"]
    decision_log_rows = [
        r for r in artifacts
        if isinstance(r, dict) and r.get("path") == "memory/DECISION_LOG.jsonl"
    ]
    selected = contract["current_packet"]
    if selected is None:
        if current or manifest["packets"] != []:
            return ["no-packet selection conflicts with registry or manifest"]
        no_packet = (
            contract.get("current_packet_state") in {None, "NO_CURRENT_EXECUTION_PACKET"}
            and manifest.get("selection_state") in {None, "NO_CURRENT_EXECUTION_PACKET"}
            and isinstance(memory_index, dict)
            and memory_index.get("current_packet") is None
            and memory_index.get("current_packet_sha256") is None
            and memory_index.get("selection_state") == "NO_CURRENT_EXECUTION_PACKET"
            and isinstance(current_truth, dict)
            and current_truth.get("current_packet") is None
            and current_truth.get("current_packet_sha256") is None
            and current_truth.get("next_lawful_move") is None
            and current_truth.get("selection_state") == "NO_CURRENT_EXECUTION_PACKET"
            and _markdown_fields_match(current_context, {
                "Current packet": None,
                "Current packet SHA256": None,
                "Next lawful move": None,
            })
            and _markdown_fields_match(next_lawful_move, {
                "Current packet": None,
                "Current packet SHA256": None,
                "Next lawful move": None,
            })
            and _markdown_fields_match(active_cutline, {
                "Current packet": None,
                "Current packet SHA256": None,
                "Active execution lane": None,
            })
            and len(decision_log_rows) == 1
            and all(
                row.get("primary_class") == "ARCHIVE_HISTORY"
                and row.get("authority_state") in HISTORICAL_STATES
                and row.get("claim_authority") == "NONE"
                and row.get("controls_execution") is False
                and row.get("current_authority") is False
                for row in decision_log_rows
            )
            and re.search(
                r"\b(?:RUN_[A-Z0-9_]+|BUD[0-9][A-Z0-9_]*)\b",
                "\n".join((current_context, next_lawful_move, active_cutline)),
            ) is None
        )
        return [] if no_packet else ["current truth surfaces conflict with no-current-packet selection"]
    if not isinstance(selected, str) or len(current) != 1 or current[0]["path"] != selected:
        return ["current packet selection does not match registry"]
    rows = manifest["packets"]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        return ["current packet manifest must have one selected record"]
    if (contract.get("current_packet_state") not in {None, "CURRENT_EXECUTION_PACKET"}
            or manifest.get("selection_state") not in {None, "CURRENT_EXECUTION_PACKET"}):
        return ["current packet selection-state mismatch"]
    record = rows[0]
    digest = current[0].get("current_file_sha256")
    next_move = current_truth.get("next_lawful_move") if isinstance(current_truth, dict) else None
    if (record.get("path") != selected or record.get("current_authority") is not True
            or record.get("sha256") != digest or record.get("next_lawful_move") != next_move
            or not isinstance(next_move, str) or not next_move.strip()):
        return ["current packet manifest binding mismatch"]
    mirrors_match = (
        isinstance(digest, str)
        and isinstance(memory_index, dict)
        and memory_index.get("current_packet") == selected
        and memory_index.get("current_packet_sha256") == digest
        and memory_index.get("selection_state") == "CURRENT_EXECUTION_PACKET"
        and isinstance(current_truth, dict)
        and current_truth.get("current_packet") == selected
        and current_truth.get("current_packet_sha256") == digest
        and current_truth.get("selection_state") == "CURRENT_EXECUTION_PACKET"
        and isinstance(next_move, str)
        and bool(next_move.strip())
        and _markdown_fields_match(current_context, {
            "Current packet": selected,
            "Current packet SHA256": digest,
            "Next lawful move": next_move,
        })
        and _markdown_fields_match(next_lawful_move, {
            "Current packet": selected,
            "Current packet SHA256": digest,
            "Next lawful move": next_move,
        })
        and _markdown_fields_match(active_cutline, {
            "Current packet": selected,
            "Current packet SHA256": digest,
            "Active execution lane": next_move,
        })
    )
    if not mirrors_match:
        return ["current packet truth-surface binding mismatch"]
    return []


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _fields(value: object, schema: dict, location: str) -> list[str]:
    """Check the flat field constraints used by the retained v3 schema."""
    if not isinstance(value, dict):
        return [f"{location}: expected object"]
    errors = [f"{location}: missing required field {key}" for key in schema["required"] if key not in value]
    types = {"string": str, "boolean": bool, "integer": int, "array": list, "object": dict, "null": type(None)}
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


def _sha256_registered_file(root: Path, relative: str) -> str:
    'Hash a registered file through a descriptor-anchored walk.'
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
                    raise ValueError("registered current file missing or not regular")
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
                    raise ValueError("registered file changed during read")
                return digest.hexdigest()
            finally:
                os.close(leaf)
        finally:
            os.close(fd)
    candidate = root / relative
    if os.name == "nt" or not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise ValueError("secure digest read unavailable (fail-closed)")
    fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
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


def check(root: Path = ROOT) -> list[str]:
    try:
        registry = load_json(root / REGISTRY_PATH)
        schema = load_json(root / "registry/artifact_authority_registry.schema.json")
        if schema.get("$id") != "kt.artifact_authority_registry.schema.v3":
            return ["unsupported authority registry schema"]
        errors = _fields(registry, schema, "registry")
        if not isinstance(registry, dict) or not isinstance(registry.get("artifacts"), list):
            return errors
        artifacts = registry["artifacts"]
        if registry.get("digest_semantics") != {
                "sha256": "HISTORICAL_REGISTRATION_BYTES",
                "current_file_sha256": "CURRENT_REPOSITORY_BYTES",
                "self_excluded_path": REGISTRY_PATH}:
            errors.append("registry must explicitly distinguish historical and current file digests")
        errors.extend(current_packet_errors(artifacts))
        errors.extend(packet_selection_errors(root, artifacts))
        row_schema = schema["properties"]["artifacts"]["items"]
        if "artifact_count" in registry and (type(registry["artifact_count"]) is not int or registry["artifact_count"] != len(artifacts)):
            errors.append("registry.artifact_count does not match artifacts")
        paths: set[str] = set()
        seen_paths: set[str] = set()
        path_aliases: set[str] = set()
        seen_ids: set[str] = set()
        for number, artifact in enumerate(artifacts):
            label = f"artifacts[{number}]"
            if isinstance(artifact, dict) and isinstance(artifact.get("path"), str):
                label += f" ({artifact['path']})"
            errors.extend(_fields(artifact, row_schema, label))
            if not isinstance(artifact, dict):
                continue
            if "current_authority" in artifact and type(artifact["current_authority"]) is not bool:
                errors.append(f"{label}.current_authority: invalid type")
            path = artifact.get("path")
            identity = artifact.get("artifact_id")
            if isinstance(path, str):
                if not path or path.startswith("/") or "\\" in path or any(part in (".", "..", "") for part in path.split("/")) or ":" in path:
                    errors.append(f"{label}: path must be repository-relative")
                    continue
                if any(part.endswith((".", " ")) for part in path.split("/")):
                    errors.append(f"{label}: nonportable trailing dot or space in path")
                    continue
                if any(part.split(".", 1)[0].upper() in _RESERVED_DEVICE_BASENAMES for part in path.split("/")):
                    errors.append(f"{label}: nonportable reserved device name in path")
                    continue
                if path in seen_paths:
                    errors.append(f"{label}: duplicate artifact path; explicit reconciliation required")
                alias = unicodedata.normalize("NFKC", path).casefold()
                if alias in path_aliases and path not in seen_paths:
                    errors.append(f"{label}: duplicate normalized artifact path")
                path_aliases.add(alias)
                seen_paths.add(path)
                paths.add(path)
                candidate = root / path
                try:
                    for part in [candidate, *candidate.parents]:
                        if part == root:
                            break
                        mode = part.lstat()
                        if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
                            raise ValueError("link/reparse path forbidden")
                    if not candidate.is_file():
                        raise ValueError("registered current file missing or not regular")
                    binding = artifact.get("current_file_sha256")
                    if path == REGISTRY_PATH:
                        if "current_file_sha256" not in artifact or binding is not None:
                            raise ValueError("registry self digest must be explicitly excluded")
                    elif not isinstance(binding, str) or re.fullmatch(r"[0-9a-f]{64}", binding) is None:
                        raise ValueError("current file digest missing or malformed")
                    elif _sha256_registered_file(root, path) != binding:
                        raise ValueError("stale current file digest")
                except (OSError, ValueError) as exc:
                    errors.append(f"{label}: {exc}")
            if isinstance(identity, str):
                if identity in seen_ids:
                    errors.append(f"{label}: duplicate artifact_id")
                seen_ids.add(identity)
            if artifact.get("primary_class") == "UNKNOWN_REVIEW_REQUIRED":
                errors.append(f"{label}: unknown artifact review required")
            if (artifact.get("controls_execution") is True
                    and (artifact.get("authority_state") != "LIVE_CURRENT_HEAD_VALIDATED"
                         or artifact.get("validation_status") != "PASS")):
                errors.append(
                    f"{label}: execution control requires LIVE_CURRENT_HEAD_VALIDATED with PASS"
                )
            historical = (artifact.get("primary_class") in {"ARCHIVE_HISTORY", "GENERATED_OUTPUT"}
                          or artifact.get("authority_state") in HISTORICAL_STATES)
            if historical and (artifact.get("controls_execution") is True
                               or artifact.get("current_authority") is True):
                errors.append(f"{label}: historical/generated artifact cannot control current execution")
            if historical and artifact.get("claim_authority") not in {"NONE", "INTERNAL_SHADOW"}:
                errors.append(f"{label}: historical/generated artifact cannot elevate current claims")
        tracked = subprocess.check_output(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "ls-files", "-z"], cwd=root
        ).decode("utf-8").split("\0")
        tracked_paths = set(tracked) - {""}
        errors.extend(f"registry missing tracked file: {path}" for path in sorted(tracked_paths - paths))
        errors.extend(f"registry contains untracked file: {path}" for path in sorted(paths - tracked_paths))
        return errors
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError) as exc:
        return [f"cannot validate authority registry: {type(exc).__name__}: {exc}"]


def main() -> int:
    errors = check(ROOT)
    print(json.dumps({"schema_id": "kt.artifact_authority_registry_check.v1",
                      "status": "FAIL" if errors else "PASS", "errors": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
