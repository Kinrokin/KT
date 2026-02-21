from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from tools.verification.worm_write import write_text_worm


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _write_json_worm(path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(
        path=path,
        text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label=label,
    )


def _write_jsonl_worm(path: Path, rows: Iterable[Dict[str, Any]], label: str) -> None:
    lines = [json.dumps(r, sort_keys=True, ensure_ascii=True) for r in rows]
    write_text_worm(path=path, text="\n".join(lines) + "\n", label=label)


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _determinism_fingerprint(*, adapter_id: str, world_id: str, case_id: str, seed: int) -> str:
    h = hashlib.sha256()
    h.update(adapter_id.encode("utf-8"))
    h.update(b"\n")
    h.update(world_id.encode("utf-8"))
    h.update(b"\n")
    h.update(case_id.encode("utf-8"))
    h.update(b"\n")
    h.update(str(seed).encode("utf-8"))
    return h.hexdigest()


@dataclass(frozen=True)
class World:
    world_id: str
    law_bundle_id: str
    suite_authority_id: str
    normative_assumption_codes: Tuple[str, ...]
    interpretive_frame_code: str
    jurisdiction_code: str
    counter_pressure_profile: str
    admissibility_rules: Dict[str, Any]


def _parse_world(obj: Dict[str, Any]) -> World:
    if obj.get("schema_id") != "kt.world_definition.v1":
        _fail_closed("world_definition schema_id mismatch")
    world_id = str(obj.get("world_id", "")).strip()
    if not world_id:
        _fail_closed("world_id missing")
    law_bundle_id = str(obj.get("law_bundle_id", "")).strip()
    suite_authority_id = str(obj.get("suite_authority_id", "")).strip()
    if not law_bundle_id or not suite_authority_id:
        _fail_closed("world missing law_bundle_id or suite_authority_id")

    normative = obj.get("normative_assumptions", [])
    if not isinstance(normative, list) or not normative:
        _fail_closed("world normative_assumptions missing/invalid")
    codes: List[str] = []
    for item in normative:
        if not isinstance(item, dict):
            _fail_closed("world normative_assumptions entry not object")
        code = str(item.get("assumption_code", "")).strip()
        if not code:
            _fail_closed("world normative_assumptions assumption_code missing")
        codes.append(code)

    interpretive_frame = obj.get("interpretive_frame", {})
    frame_code = str(getattr(interpretive_frame, "get", lambda _k, _d=None: "")("frame_code", "")).strip()
    if not frame_code:
        _fail_closed("world interpretive_frame.frame_code missing")

    jurisdiction = obj.get("jurisdictional_scope", {})
    jur_code = str(getattr(jurisdiction, "get", lambda _k, _d=None: "")("jurisdiction_code", "")).strip()
    if not jur_code:
        _fail_closed("world jurisdictional_scope.jurisdiction_code missing")

    profile = str(obj.get("counter_pressure_profile", "")).strip()
    if not profile:
        _fail_closed("world counter_pressure_profile missing")

    rules = obj.get("admissibility_rules", {})
    if not isinstance(rules, dict):
        _fail_closed("world admissibility_rules not object")

    return World(
        world_id=world_id,
        law_bundle_id=law_bundle_id,
        suite_authority_id=suite_authority_id,
        normative_assumption_codes=tuple(codes),
        interpretive_frame_code=frame_code,
        jurisdiction_code=jur_code,
        counter_pressure_profile=profile,
        admissibility_rules=rules,
    )


def _world_requires_refusal(*, world: World, topic_code: str) -> bool:
    # Deterministic, rule-only, safe: no prompt content.
    if "NO_MEDICAL_ADVICE" in world.normative_assumption_codes and topic_code == "MEDICAL_GUIDANCE":
        return True
    if "NO_LEGAL_ADVICE" in world.normative_assumption_codes and topic_code == "LEGAL_GUIDANCE":
        return True
    return False


def _eval_case_in_world(
    *,
    adapter_id: str,
    seed: int,
    law_bundle_hash_in_force: str,
    world: World,
    world_definition_ref: Dict[str, Any],
    case: Dict[str, Any],
    counter_pressure_refs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    case_id = str(case.get("case_id", "")).strip()
    if not case_id:
        _fail_closed("case_id missing")
    topic_code = str(case.get("topic_code", "")).strip()
    if not topic_code:
        _fail_closed("topic_code missing")

    admitted = True
    inadmissibility_codes: List[str] = []
    if not world_definition_ref.get("sha256"):
        admitted = False
        inadmissibility_codes.append("WORLD_DEFINITION_MISSING")
    if not law_bundle_hash_in_force:
        admitted = False
        inadmissibility_codes.append("LAW_HASH_MISSING")
    if not world.suite_authority_id:
        admitted = False
        inadmissibility_codes.append("SUITE_AUTHORITY_UNAUTHORIZED")
    if world.admissibility_rules.get("requires_counter_pressure") is True and not counter_pressure_refs:
        admitted = False
        inadmissibility_codes.append("COUNTER_PRESSURE_MISSING")

    determinism = _determinism_fingerprint(adapter_id=adapter_id, world_id=world.world_id, case_id=case_id, seed=seed)

    if not admitted:
        return {
            "schema_id": "kt.multiversal_evaluation_result.v1",
            "artifact_id": adapter_id,
            "world_id": world.world_id,
            "world_definition_ref": world_definition_ref,
            "evaluation_id": case_id,
            "law_bundle_hash_in_force": law_bundle_hash_in_force,
            "suite_authority_id": world.suite_authority_id,
            "verdict": "REJECTED_AT_ADMISSION",
            "admission_status": "REJECTED",
            "admissible": False,
            "inadmissibility_reason_codes": sorted(set(inadmissibility_codes)),
            "conflicts_detected": [],
            "counter_pressure_refs": [],
            "determinism_fingerprint": determinism,
        }

    refusal_required = _world_requires_refusal(world=world, topic_code=topic_code)
    if refusal_required:
        verdict = "PASS_WITH_RESTRICTIONS"
        admissible = True
    else:
        verdict = "WORLD_LOCAL_PASS"
        admissible = True

    return {
        "schema_id": "kt.multiversal_evaluation_result.v1",
        "artifact_id": adapter_id,
        "world_id": world.world_id,
        "world_definition_ref": world_definition_ref,
        "evaluation_id": case_id,
        "law_bundle_hash_in_force": law_bundle_hash_in_force,
        "suite_authority_id": world.suite_authority_id,
        "verdict": verdict,
        "admission_status": "ADMITTED",
        "admissible": admissible,
        "conflicts_detected": [],
        "counter_pressure_refs": counter_pressure_refs,
        "determinism_fingerprint": determinism,
    }


def _emit_conflicts(
    *,
    adapter_id: str,
    seed: int,
    case: Dict[str, Any],
    results_by_world: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    # Preserves disagreement, no averaging. Only category-level.
    topic_code = str(case.get("topic_code", "")).strip()
    case_id = str(case.get("case_id", "")).strip()
    if topic_code not in ("MEDICAL_GUIDANCE", "LEGAL_GUIDANCE"):
        return []

    verdicts = {wid: r["verdict"] for wid, r in results_by_world.items() if r.get("admission_status") == "ADMITTED"}
    if len(set(verdicts.values())) <= 1:
        return []

    worlds = sorted(verdicts.keys())
    conflict_id = f"MW_{case_id}"
    determinism = hashlib.sha256((adapter_id + "\n" + case_id + "\n" + str(seed)).encode("utf-8")).hexdigest()

    if topic_code == "MEDICAL_GUIDANCE":
        claim_code = "MEDICAL_ADVICE_ALLOWED"
    else:
        claim_code = "LEGAL_ADVICE_ALLOWED"

    return [
        {
            "schema_id": "kt.multiversal_conflict_event.v1",
            "conflict_id": conflict_id,
            "timestamp": case.get("timestamp", "1970-01-01T00:00:00Z"),
            "artifact_id": adapter_id,
            "worlds": worlds,
            "axis": "GOVERNANCE",
            "conflict_class": "NORMATIVE",
            "terminal": True,
            "resolution_status": "ESCALATED_STALEMATE",
            "disputed_claim_code": claim_code,
            "law_citations": [],
            "determinism_fingerprint": determinism,
        }
    ]


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MVE-0 runner (governed multiversal evaluation; deterministic; WORM outputs).")
    ap.add_argument("--pack-manifest", required=True, help="Path to KT_CORE_PRESSURE_PACK_v1/pack_manifest.json.")
    ap.add_argument("--adapter-id", required=True, help="Artifact/adapter identifier (string).")
    ap.add_argument("--seed", type=int, default=0, help="Deterministic seed (int).")
    ap.add_argument("--law-bundle-hash-in-force", required=True, help="Hex64 law bundle hash pin.")
    ap.add_argument("--out-dir", required=True, help="Output directory (must be under WORM run root).")
    args = ap.parse_args(argv)

    pack_manifest_path = Path(args.pack_manifest)
    if not pack_manifest_path.is_file():
        _fail_closed("pack_manifest missing")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    mve_dir = out_dir / "mve"
    mve_dir.mkdir(parents=True, exist_ok=False)

    pack = _read_json(pack_manifest_path)
    if str(pack.get("schema_id", "")).strip() != "kt.core_pressure_pack_manifest.v1":
        _fail_closed("pack_manifest schema_id mismatch")

    pack_root = pack_manifest_path.parent
    world_set_path = (pack_root / str(pack.get("world_set_file", "")).strip()).resolve()
    cases_path = (pack_root / str(pack.get("cases_file", "")).strip()).resolve()
    validators_path = (pack_root / str(pack.get("validators_file", "")).strip()).resolve()

    if not world_set_path.is_file() or not cases_path.is_file() or not validators_path.is_file():
        _fail_closed("pack referenced file missing")

    world_set_obj = _read_json(world_set_path)
    worlds_raw = world_set_obj.get("worlds")
    if not isinstance(worlds_raw, list) or not worlds_raw:
        _fail_closed("world_set.worlds missing/invalid")

    worlds: List[World] = []
    world_defs: List[Dict[str, Any]] = []
    for w in worlds_raw:
        if not isinstance(w, dict):
            _fail_closed("world_set entry not object")
        world_defs.append(w)
        worlds.append(_parse_world(w))

    cases = _read_jsonl(cases_path)
    _ = _read_json(validators_path)  # validators reserved for future enforcement

    # Copy world set into evidence with hash ref.
    world_set_bytes = json.dumps(world_set_obj, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    world_set_sha = _sha256_bytes(world_set_bytes)
    write_text_worm(path=mve_dir / "world_set.json", text=world_set_bytes.decode("utf-8"), label="world_set.json")

    counter_pressure_refs: List[Dict[str, Any]] = []
    for cp in pack.get("counter_pressure_refs", []):
        if not isinstance(cp, dict):
            _fail_closed("pack counter_pressure_refs entry not object")
        counter_pressure_refs.append(cp)

    all_results: List[Dict[str, Any]] = []
    all_conflicts: List[Dict[str, Any]] = []

    for case in cases:
        results_by_world: Dict[str, Dict[str, Any]] = {}
        for w in worlds:
            world_def_ref = {
                "sha256": world_set_sha,
                "path": "mve/world_set.json",
                "kind": "json",
            }
            res = _eval_case_in_world(
                adapter_id=args.adapter_id,
                seed=int(args.seed),
                law_bundle_hash_in_force=str(args.law_bundle_hash_in_force),
                world=w,
                world_definition_ref=world_def_ref,
                case=case,
                counter_pressure_refs=counter_pressure_refs,
            )
            results_by_world[w.world_id] = res
            all_results.append(res)

        conflicts = _emit_conflicts(adapter_id=args.adapter_id, seed=int(args.seed), case=case, results_by_world=results_by_world)
        for c in conflicts:
            all_conflicts.append(c)
            for wid in results_by_world.keys():
                results_by_world[wid]["conflicts_detected"] = sorted(
                    set(results_by_world[wid].get("conflicts_detected", [])) | {c["conflict_id"]}
                )

    fitness_entries: List[Dict[str, Any]] = []
    for w in worlds:
        verdicts = [r for r in all_results if r["world_id"] == w.world_id]
        regions = []
        for r in verdicts:
            if r["verdict"] == "WORLD_LOCAL_PASS":
                regions.append("A")
            elif r["verdict"] == "PASS_WITH_RESTRICTIONS":
                regions.append("B")
            else:
                regions.append("C")
        region = "C" if "C" in regions else ("B" if "B" in regions else "A")
        fitness_entries.append({"world_id": w.world_id, "region": region})

    promotion_blocked = any(c.get("terminal") is True for c in all_conflicts) or any(e["region"] == "C" for e in fitness_entries)
    block_reason = "UNRESOLVED_MULTIVERSAL_CONFLICT" if any(c.get("terminal") is True for c in all_conflicts) else (
        "REGION_C_PRESENT" if any(e["region"] == "C" for e in fitness_entries) else "TEMPORAL_INSTABILITY_DETECTED"
    )

    multiversal_fitness = {
        "schema_id": "kt.multiversal_fitness_record.v1",
        "artifact_id": args.adapter_id,
        "timestamp": "1970-01-01T00:00:00Z",
        "world_fitness": fitness_entries,
        "temporal_lineage": [{"world_id": e["world_id"], "epoch": 0, "region": e["region"]} for e in fitness_entries],
        "promotion_blocked": bool(promotion_blocked),
        "block_reason_code": block_reason,
        "determinism_fingerprint": hashlib.sha256((args.adapter_id + "\n" + str(args.seed)).encode("utf-8")).hexdigest(),
    }

    summary = {
        "schema_id": "kt.mve_summary.v1",
        "adapter_id": args.adapter_id,
        "pack_manifest_sha256": _sha256_file(pack_manifest_path),
        "world_set_sha256": world_set_sha,
        "cases_sha256": _sha256_file(cases_path),
        "seed": int(args.seed),
        "results_count": len(all_results),
        "conflicts_count": len(all_conflicts),
        "promotion_blocked": bool(promotion_blocked),
    }

    _write_jsonl_worm(path=mve_dir / "multiversal_results.jsonl", rows=all_results, label="multiversal_results.jsonl")
    _write_jsonl_worm(path=mve_dir / "multiversal_conflicts.jsonl", rows=all_conflicts, label="multiversal_conflicts.jsonl")
    _write_json_worm(path=mve_dir / "multiversal_fitness.json", obj=multiversal_fitness, label="multiversal_fitness.json")
    _write_json_worm(path=mve_dir / "mve_summary.json", obj=summary, label="mve_summary.json")

    manifest = {}
    for p in sorted(mve_dir.rglob("*")):
        if p.is_file():
            manifest[str(p.relative_to(mve_dir)).replace("\\", "/")] = _sha256_file(p)
    _write_json_worm(path=mve_dir / "mve_sha256_manifest.json", obj=manifest, label="mve_sha256_manifest.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
