from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


def utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_obj(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=canonical_json(obj) + "\n", label=label)


def write_jsonl_worm(*, path: Path, rows: Iterable[Dict[str, Any]], label: str) -> None:
    txt = "\n".join([canonical_json(r) for r in rows]) + "\n"
    write_text_worm(path=path, text=txt, label=label)


def ensure_empty_dir_worm(out_dir: Path, *, label: str) -> None:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        raise FL3ValidationError(f"FAIL_CLOSED: {label} out_dir is not empty (WORM reuse forbidden): {out_dir.as_posix()}")


_SENSITIVE_RE = re.compile(
    r"(?i)\\b("
    r"bomb|explosive|weapon|suicide|self[- ]harm|kill|murder|poison|ricin|anthrax|"
    r"malware|ransomware|phish|phishing|exploit|ddos|sql\\s*injection|"
    r"lockpick|meth|cocaine|heroin|launder(ing)?|money\\s*mule|insider\\s*trading|market\\s*manipulation"
    r")\\b"
)


def looks_sensitive(text: str) -> bool:
    return bool(_SENSITIVE_RE.search(text or ""))


def require_str(obj: Dict[str, Any], field: str) -> str:
    v = obj.get(field)
    if not isinstance(v, str) or not v.strip():
        raise FL3ValidationError(f"FAIL_CLOSED: missing/invalid {field}")
    return v.strip()


def require_int(obj: Dict[str, Any], field: str) -> int:
    v = obj.get(field)
    if not isinstance(v, int):
        raise FL3ValidationError(f"FAIL_CLOSED: missing/invalid {field} (expected int)")
    return int(v)


def require_dict(obj: Dict[str, Any], field: str) -> Dict[str, Any]:
    v = obj.get(field)
    if not isinstance(v, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: missing/invalid {field} (expected object)")
    return v


def require_list(obj: Dict[str, Any], field: str) -> List[Any]:
    v = obj.get(field)
    if not isinstance(v, list):
        raise FL3ValidationError(f"FAIL_CLOSED: missing/invalid {field} (expected array)")
    return v


def stable_sorted_strs(items: Sequence[str]) -> List[str]:
    return sorted([str(x).strip() for x in items if str(x).strip()])


@dataclass(frozen=True)
class Pins:
    sealed_tag: str
    sealed_commit: str
    law_bundle_hash: str
    suite_registry_id: str
    determinism_expected_root_hash: str
    head_git_sha: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sealed_tag": self.sealed_tag,
            "sealed_commit": self.sealed_commit,
            "law_bundle_hash": self.law_bundle_hash,
            "suite_registry_id": self.suite_registry_id,
            "determinism_expected_root_hash": self.determinism_expected_root_hash,
            "head_git_sha": self.head_git_sha,
        }

