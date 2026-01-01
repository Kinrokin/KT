from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml

from crucible_dsl_schemas import CrucibleSchemaError, CrucibleSpec, crucible_spec_hash, sha256_text


@dataclass(frozen=True)
class LoadedCrucible:
    path: Path
    raw_text: str
    data: Dict[str, Any]
    spec: CrucibleSpec
    crucible_spec_hash: str


def _load_text(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        raise CrucibleSchemaError(f"Unable to read crucible spec: {exc.__class__.__name__}")
    if len(raw.encode("utf-8")) > 512 * 1024:
        raise CrucibleSchemaError("Crucible spec file exceeds max bytes (fail-closed)")
    return raw


def load_crucible(path: Path) -> LoadedCrucible:
    path = path.resolve()
    if not path.exists():
        raise CrucibleSchemaError(f"Crucible spec does not exist (fail-closed): {path.as_posix()}")

    raw_text = _load_text(path)
    suffix = path.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            obj = yaml.safe_load(raw_text)
        elif suffix == ".json":
            obj = json.loads(raw_text)
        else:
            raise CrucibleSchemaError("Crucible spec extension must be .yaml/.yml/.json (fail-closed)")
    except CrucibleSchemaError:
        raise
    except Exception as exc:
        raise CrucibleSchemaError(f"Crucible spec parse failed: {exc.__class__.__name__}")

    if not isinstance(obj, dict):
        raise CrucibleSchemaError("Crucible spec root must be an object (fail-closed)")

    spec = CrucibleSpec.from_dict(obj)
    spec_hash = crucible_spec_hash(spec)
    return LoadedCrucible(path=path, raw_text=raw_text, data=obj, spec=spec, crucible_spec_hash=spec_hash)


def compute_prompt_hash(prompt: str) -> str:
    return sha256_text(prompt)

