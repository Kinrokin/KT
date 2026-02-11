from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CRU_DIR = ROOT / "tools" / "growth" / "crucibles"
REGISTRY_PATH = CRU_DIR / "CRUCIBLE_REGISTRY.yaml"

MIN_DISTINCT_DOMAINS = 2


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_crucible_tags() -> dict[str, dict]:
    spec_files = sorted(CRU_DIR.glob("CRU-*.yaml"))
    tags_by_id: dict[str, dict] = {}
    for path in spec_files:
        data = _load_yaml(path)
        tags_by_id[path.stem] = data.get("tags", {})
    return tags_by_id


def test_epoch_crucible_coverage() -> None:
    registry = _load_yaml(REGISTRY_PATH)
    reg_ids = {c["id"] for c in registry.get("crucibles", [])}
    tags_by_id = _load_crucible_tags()

    plan_roots = [
        ROOT / "tools" / "growth" / "orchestrator",
        ROOT,
    ]
    epoch_plans = []
    for base in plan_roots:
        if base.exists():
            epoch_plans.extend(base.rglob("EPOCH_*.json"))
    epoch_plans = [p for p in epoch_plans if "artifacts/epochs" not in p.as_posix()]
    epoch_plans = sorted(set(epoch_plans))
    assert epoch_plans, "No epoch plans found (fail-closed)"

    for path in epoch_plans:
        data = _load_json(path)
        order = data.get("crucible_order", [])
        specs = data.get("crucible_specs", {})
        assert isinstance(order, list) and order, f"Epoch {path} missing crucible_order (fail-closed)"
        assert isinstance(specs, dict) and specs, f"Epoch {path} missing crucible_specs (fail-closed)"

        unknown = [c for c in order if c not in reg_ids]
        assert not unknown, f"Epoch {path} references unregistered crucibles: {unknown}"

        domains = set()
        reasoning_modes = set()
        paradox_classes = set()
        has_paradox_domain = False

        for crucible_id in order:
            tags = tags_by_id.get(crucible_id, {})
            domains.update(tags.get("domains", []))
            reasoning_modes.update(tags.get("reasoning_modes", []))
            paradox_classes.update(tags.get("paradox_classes", []))
            if "paradox" in tags.get("domains", []):
                has_paradox_domain = True

        assert len(domains) >= MIN_DISTINCT_DOMAINS, f"Epoch {path} lacks domain diversity (fail-closed)"
        assert reasoning_modes, f"Epoch {path} lacks reasoning_modes (fail-closed)"

        if has_paradox_domain or "PARADOX" in str(path.name).upper():
            assert paradox_classes, f"Epoch {path} missing paradox_classes despite paradox axis (fail-closed)"
