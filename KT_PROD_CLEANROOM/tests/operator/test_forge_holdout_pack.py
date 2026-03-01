from __future__ import annotations

import json
from pathlib import Path


def test_forge_promotion_eligible_holdout_pack_has_counter_pressure_refs() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    pack_root = repo_root / "KT-Codex" / "packs" / "KT_FORGE_PROMOTION_ELIGIBLE_HOLDOUT_v1"
    manifest_path = pack_root / "pack_manifest.json"
    assert manifest_path.exists()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.get("schema_id") == "kt.core_pressure_pack_manifest.v1"
    assert manifest.get("pack_id") == "KT_FORGE_PROMOTION_ELIGIBLE_HOLDOUT_v1"

    refs = manifest.get("counter_pressure_refs")
    assert isinstance(refs, list) and refs, "counter_pressure_refs must be present (admission requires it)"
    for r in refs:
        assert isinstance(r, dict)
        assert isinstance(r.get("sha256"), str) and len(str(r.get("sha256"))) == 64
        assert isinstance(r.get("path"), str) and str(r.get("path")).strip()
        assert isinstance(r.get("kind"), str) and str(r.get("kind")).strip()

    # Ensure referenced files exist and are minimally well-formed.
    for key in ("world_set_file", "invariants_file", "cases_file", "validators_file"):
        rel = str(manifest.get(key, "")).strip()
        assert rel
        assert (pack_root / rel).exists()

    worlds = json.loads((pack_root / str(manifest["world_set_file"])).read_text(encoding="utf-8"))
    assert worlds.get("schema_id") == "kt.world_set.v1"
    assert isinstance(worlds.get("worlds"), list) and worlds["worlds"]

    inv = json.loads((pack_root / str(manifest["invariants_file"])).read_text(encoding="utf-8"))
    assert inv.get("schema_id") == "kt.mve_invariants.v1"

    # Promotion-eligible smoke cases must avoid conflict/terminal topics.
    allowed = {"CONFIDENTIALITY", "PROMPT_INJECTION"}
    cases_text = (pack_root / str(manifest["cases_file"])).read_text(encoding="utf-8")
    lines = [ln.strip() for ln in cases_text.splitlines() if ln.strip()]
    assert lines
    for ln in lines:
        obj = json.loads(ln)
        assert obj.get("topic_code") in allowed

