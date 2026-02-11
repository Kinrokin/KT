from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[4]
CRU_DIR = ROOT / "tools" / "growth" / "crucibles"
REGISTRY_PATH = CRU_DIR / "CRUCIBLE_REGISTRY.yaml"
REGISTRY_SCHEMA = CRU_DIR / "crucible_registry_schema_v1.json"
SPEC_SCHEMA = CRU_DIR / "crucible_spec_schema_v1.json"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_registry_schema_present() -> None:
    data = json.loads(REGISTRY_SCHEMA.read_text(encoding="utf-8"))
    assert data.get("schema_id") == "kt.crucible.registry.v1"


def test_spec_schema_present() -> None:
    data = json.loads(SPEC_SCHEMA.read_text(encoding="utf-8"))
    assert data.get("schema_id") == "kt.crucible.spec.v1"


def test_registry_matches_specs() -> None:
    registry = _load_yaml(REGISTRY_PATH)
    crucibles = registry.get("crucibles", [])
    ids = {c["id"] for c in crucibles}
    paths = {c["path"] for c in crucibles}

    spec_files = sorted(CRU_DIR.glob("CRU-*.yaml"))
    spec_ids = {p.stem for p in spec_files}
    spec_paths = {f"KT_PROD_CLEANROOM/tools/growth/crucibles/{p.name}" for p in spec_files}

    assert ids == spec_ids
    assert paths == spec_paths


def test_crucible_tags_present() -> None:
    spec_files = sorted(CRU_DIR.glob("CRU-*.yaml"))
    for path in spec_files:
        data = _load_yaml(path)
        assert "tags" in data
        assert isinstance(data["tags"], dict)
        for key in (
            "domains",
            "subdomains",
            "microdomains",
            "ventures",
            "reasoning_modes",
            "modalities",
            "tools",
            "paradox_classes",
        ):
            assert key in data["tags"]
