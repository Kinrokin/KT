from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _read_json_dict(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL_CLOSED: unreadable JSON {label}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        _fail_closed(f"{label} must be a JSON object: {path.as_posix()}")
    return obj


def _read_jsonl(path: Path, *, label: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        for ln in path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            obj = json.loads(ln)
            if not isinstance(obj, dict):
                _fail_closed(f"{label} JSONL row not object")
            rows.append(obj)
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL_CLOSED: unreadable JSONL {label}: {path.as_posix()}") from exc
    return rows


def _write_json_worm(path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def _dep(dep_id: str, status: str, *, evidence: List[str] | None = None, details: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "dep_id": dep_id,
        "status": status,
        "evidence": evidence or [],
        "details": details or {},
    }


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Titan promotion gate (dependency graph; fail-closed on missing/invalid artifacts).")
    ap.add_argument("--mve-dir", required=True, help="Directory containing MVE artifacts (out_dir/mve).")
    ap.add_argument("--temporal-gate", required=True, help="Path to temporal_fitness_gate.json.")
    ap.add_argument("--run-id", required=True, help="Run identifier (stable string).")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM; must be empty).")
    ap.add_argument("--mode", choices=["auto", "mve0", "mve1"], default="auto", help="Expected MVE mode (default: auto from mve_summary).")
    args = ap.parse_args(argv)

    mve_dir = Path(args.mve_dir).resolve()
    if not mve_dir.is_dir():
        _fail_closed("mve_dir missing")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    run_id = str(args.run_id).strip()
    if not run_id:
        _fail_closed("run_id missing")

    mve_summary_path = (mve_dir / "mve_summary.json").resolve()
    if not mve_summary_path.is_file():
        _fail_closed("missing mve_summary.json")
    summary = _read_json_dict(mve_summary_path, label="mve_summary")
    mode = str(summary.get("mode", "")).strip() or "mve0"
    if str(args.mode) != "auto":
        mode = str(args.mode)

    required = [
        "world_set.json",
        "multiversal_results.jsonl",
        "multiversal_conflicts.jsonl",
        "multiversal_fitness.json",
        "mve_summary.json",
        "mve_sha256_manifest.json",
    ]
    if mode == "mve1":
        required += [
            "multiversal_output_stubs.jsonl",
            "mve_drift_report.json",
            "mve_capture_resistance_report.json",
        ]
    missing = [name for name in required if not (mve_dir / name).is_file()]
    if missing:
        _fail_closed("missing required MVE artifacts: " + ",".join(missing))

    adapter_id = str(summary.get("adapter_id", "")).strip()
    if not adapter_id:
        _fail_closed("mve_summary.adapter_id missing")

    fitness = _read_json_dict(mve_dir / "multiversal_fitness.json", label="multiversal_fitness")
    conflicts = _read_jsonl(mve_dir / "multiversal_conflicts.jsonl", label="multiversal_conflicts")

    # Conflict admission gate: validate minimal required fields are present (schema-bound upstream).
    for c in conflicts:
        if str(c.get("schema_id", "")).strip() != "kt.multiversal_conflict_event.v1":
            _fail_closed("conflict schema_id mismatch")
        for k in ("conflict_id", "artifact_id", "worlds", "axis", "conflict_class", "terminal", "resolution_status", "determinism_fingerprint"):
            if k not in c:
                _fail_closed("conflict missing required field: " + k)

    temporal_gate_path = Path(args.temporal_gate).resolve()
    if not temporal_gate_path.is_file():
        _fail_closed("temporal_gate missing")
    temporal_gate = _read_json_dict(temporal_gate_path, label="temporal_fitness_gate")
    if str(temporal_gate.get("schema_id", "")).strip() != "kt.temporal_fitness_gate.v1":
        _fail_closed("temporal_fitness_gate schema_id mismatch")

    deps: List[Dict[str, Any]] = []
    reason_codes: List[str] = []

    deps.append(_dep("mve_artifacts_present", "PASS", evidence=[(mve_dir / "mve_sha256_manifest.json").as_posix()]))

    # Determinism proof (artifact-level): presence of sha256 manifest.
    manifest = _read_json_dict(mve_dir / "mve_sha256_manifest.json", label="mve_sha256_manifest")
    deps.append(_dep("artifact_determinism_manifest", "PASS" if manifest else "FAIL", details={"files": int(len(manifest))}))
    if not manifest:
        reason_codes.append("RC_DETERMINISM_MANIFEST_MISSING")

    terminal_conflicts = [c for c in conflicts if bool(c.get("terminal", False))]
    deps.append(_dep("conflict_preservation", "PASS", details={"conflicts": int(len(conflicts))}))
    deps.append(_dep("terminal_conflicts_absent", "PASS" if not terminal_conflicts else "FAIL", details={"terminal_conflicts": int(len(terminal_conflicts))}))
    if terminal_conflicts:
        reason_codes.append("RC_TERMINAL_CONFLICT_PRESENT")

    # Fitness regions gate (Region C blocks promotion).
    wf = fitness.get("world_fitness") if isinstance(fitness.get("world_fitness"), list) else []
    regions = [str(r.get("region", "")).strip().upper() for r in wf if isinstance(r, dict)]
    region_c = any(r == "C" for r in regions)
    deps.append(_dep("fitness_region_c_absent", "PASS" if not region_c else "FAIL", details={"regions": regions}))
    if region_c:
        reason_codes.append("RC_REGION_C_PRESENT")

    if mode == "mve1":
        drift = _read_json_dict(mve_dir / "mve_drift_report.json", label="mve_drift_report")
        drift_terminal = bool(drift.get("terminal", False))
        deps.append(_dep("cross_world_invariants", "PASS" if not drift_terminal else "FAIL", details={"violations": int(len(drift.get("violations", [])))}))
        if drift_terminal:
            reason_codes.append("RC_MVE_INVARIANT_VIOLATION")

        capture = _read_json_dict(mve_dir / "mve_capture_resistance_report.json", label="mve_capture_resistance_report")
        cap_status = str(capture.get("status", "")).strip().upper()
        cap_ok = cap_status == "PASS" and not bool(capture.get("terminal", False))
        deps.append(_dep("evaluator_capture_resistance", "PASS" if cap_ok else "FAIL", details={"status": cap_status}))
        if not cap_ok:
            reason_codes.append("RC_EVALUATOR_CAPTURE_DETECTED")
    else:
        deps.append(_dep("cross_world_invariants", "N/A"))
        deps.append(_dep("evaluator_capture_resistance", "N/A"))

    temporal_blocked = bool(temporal_gate.get("promotion_blocked", False))
    deps.append(_dep("temporal_fitness_regression_absent", "PASS" if not temporal_blocked else "FAIL", evidence=[temporal_gate_path.as_posix()]))
    if temporal_blocked:
        reason_codes.append("RC_TEMPORAL_FITNESS_REGRESSION")

    promotion_blocked = any(d.get("status") == "FAIL" for d in deps) or bool(reason_codes)

    graph = {
        "schema_id": "kt.promotion_dependency_graph.v1",
        "adapter_id": adapter_id,
        "run_id": run_id,
        "mode": mode,
        "dependencies": deps,
        "promotion_blocked": bool(promotion_blocked),
        "block_reason_codes": sorted(set(reason_codes)),
        "determinism_fingerprint": hashlib.sha256((adapter_id + "\n" + run_id + "\n" + mode).encode("utf-8")).hexdigest(),
    }
    _write_json_worm(path=out_dir / "promotion_dependency_graph.json", obj=graph, label="promotion_dependency_graph.json")

    gate = {
        "schema_id": "kt.titan_promotion_gate.v1",
        "adapter_id": adapter_id,
        "run_id": run_id,
        "mode": mode,
        "mve_dir": mve_dir.as_posix(),
        "temporal_gate_path": temporal_gate_path.as_posix(),
        "promotion_blocked": bool(promotion_blocked),
        "block_reason_codes": sorted(set(reason_codes)),
        "dependency_graph_path": (out_dir / "promotion_dependency_graph.json").as_posix(),
        "determinism_fingerprint": hashlib.sha256((adapter_id + "\n" + run_id + "\n" + str(len(deps))).encode("utf-8")).hexdigest(),
    }
    _write_json_worm(path=out_dir / "titan_promotion_gate.json", obj=gate, label="titan_promotion_gate.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

