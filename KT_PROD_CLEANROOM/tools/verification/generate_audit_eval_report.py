from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


_AUDIT_SCHEMA_ID = "kt.audit_eval_report.v1"
_SUITE_DEF_SCHEMA_ID = "kt.suite_definition.v1"
_SUITE_EVAL_SCHEMA_ID = "kt.suite_eval_report.v1"
_AXIS_FITNESS_SCHEMA_ID = "kt.axis_fitness_report.v1"


def _is_truthy_env(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _relpath(repo_root: Path, path: Path) -> str:
    path = path.resolve()
    try:
        return path.relative_to(repo_root).as_posix()
    except Exception:  # noqa: BLE001
        return path.as_posix()


def _dedup_sorted(items: Iterable[str]) -> List[str]:
    return sorted({str(x).strip() for x in items if str(x).strip()})


def _decision_from_components(rows: Sequence[Dict[str, Any]]) -> str:
    """
    Conservative composition:
      - any QUARANTINE or hard_gate_pass=False => QUARANTINE
      - else any HOLD => HOLD
      - else PROMOTE
    """
    any_hold = False
    for r in rows:
        dec = str(r.get("decision", "")).strip().upper()
        if not bool(r.get("hard_gate_pass", True)):
            return "QUARANTINE"
        if dec == "QUARANTINE":
            return "QUARANTINE"
        if dec == "HOLD":
            any_hold = True
    return "HOLD" if any_hold else "PROMOTE"


def _one_line_verdict(
    *,
    decision: str,
    canonical_lane: bool,
    attestation_mode: str,
    run_id: str,
    law_bundle_hash: str,
    suite_registry_id: str,
    axis_scores: Dict[str, float],
) -> str:
    parts = [
        "KT_AUDIT_EVAL_VERDICT_V1",
        f"decision={decision}",
        f"canon={1 if canonical_lane else 0}",
        f"attestation={attestation_mode}",
        f"run_id={run_id}",
        f"law={law_bundle_hash}",
        f"suite_registry={suite_registry_id}",
    ]
    for axis_id in sorted(axis_scores.keys()):
        parts.append(f"{axis_id}={axis_scores[axis_id]:.4f}")
    return " | ".join(parts)


@dataclass(frozen=True)
class _Loaded:
    path: Path
    obj: Dict[str, Any]


def generate_audit_eval_report(
    *,
    suite_def_paths: Sequence[Path],
    suite_eval_report_paths: Sequence[Path],
    axis_fitness_report_paths: Sequence[Path],
    run_id: str,
    out_dir: Path,
    attestation_mode: str,
) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))

    canonical_lane = _is_truthy_env("KT_CANONICAL_LANE")
    mode = str(attestation_mode).strip().upper()
    if mode not in {"SIMULATED", "HMAC", "PKI"}:
        raise FL3ValidationError("FAIL_CLOSED: invalid attestation_mode")
    if canonical_lane and mode != "HMAC":
        raise FL3ValidationError("FAIL_CLOSED: canonical lane requires HMAC attestation_mode for audit report")

    run_id = str(run_id).strip()
    if not run_id:
        raise FL3ValidationError("FAIL_CLOSED: run_id must be non-empty")

    # Identity anchors
    law_sha_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").resolve()
    suite_reg_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITE_REGISTRY_FL3.json").resolve()
    if not law_sha_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: LAW_BUNDLE_FL3.sha256 missing")
    if not suite_reg_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: SUITE_REGISTRY_FL3.json missing")
    law_bundle_hash = law_sha_path.read_text(encoding="utf-8").strip()
    if len(law_bundle_hash) != 64:
        raise FL3ValidationError("FAIL_CLOSED: LAW_BUNDLE_FL3.sha256 invalid")
    suite_reg = _read_json_dict(suite_reg_path, name="suite_registry")
    suite_registry_id = str(suite_reg.get("suite_registry_id", "")).strip()
    if len(suite_registry_id) != 64:
        raise FL3ValidationError("FAIL_CLOSED: SUITE_REGISTRY_FL3.json suite_registry_id invalid/missing")

    # Load suite defs
    suite_defs: List[_Loaded] = []
    suite_def_by_id: Dict[str, _Loaded] = {}
    for p in _dedup_sorted([str(x) for x in suite_def_paths]):
        path = Path(p)
        obj = _read_json_dict(path, name="suite_definition")
        validate_schema_bound_object(obj)
        if str(obj.get("schema_id", "")).strip() != _SUITE_DEF_SCHEMA_ID:
            raise FL3ValidationError("FAIL_CLOSED: suite_definition schema_id mismatch")
        sid = str(obj.get("suite_definition_id", "")).strip()
        if not sid:
            raise FL3ValidationError("FAIL_CLOSED: suite_definition_id missing")
        if sid in suite_def_by_id:
            raise FL3ValidationError("FAIL_CLOSED: duplicate suite_definition_id inputs")
        loaded = _Loaded(path=path.resolve(), obj=obj)
        suite_defs.append(loaded)
        suite_def_by_id[sid] = loaded

    # Load suite eval reports
    suite_evals: List[_Loaded] = []
    suite_eval_by_id: Dict[str, _Loaded] = {}
    for p in _dedup_sorted([str(x) for x in suite_eval_report_paths]):
        path = Path(p)
        obj = _read_json_dict(path, name="suite_eval_report")
        validate_schema_bound_object(obj)
        if str(obj.get("schema_id", "")).strip() != _SUITE_EVAL_SCHEMA_ID:
            raise FL3ValidationError("FAIL_CLOSED: suite_eval_report schema_id mismatch")
        eid = str(obj.get("suite_eval_report_id", "")).strip()
        if not eid:
            raise FL3ValidationError("FAIL_CLOSED: suite_eval_report_id missing")
        if eid in suite_eval_by_id:
            raise FL3ValidationError("FAIL_CLOSED: duplicate suite_eval_report_id inputs")
        loaded = _Loaded(path=path.resolve(), obj=obj)
        suite_evals.append(loaded)
        suite_eval_by_id[eid] = loaded

        sdid = str(obj.get("suite_definition_id", "")).strip()
        if sdid not in suite_def_by_id:
            raise FL3ValidationError("FAIL_CLOSED: suite_eval_report references unknown suite_definition_id")
        suite_def = suite_def_by_id[sdid].obj
        if str(obj.get("validator_catalog_id", "")).strip() != str(suite_def.get("validator_catalog_id", "")).strip():
            raise FL3ValidationError("FAIL_CLOSED: suite_eval_report.validator_catalog_id mismatch vs suite_definition")
        if str(obj.get("axis_scoring_policy_id", "")).strip() != str(suite_def.get("axis_scoring_policy_id", "")).strip():
            raise FL3ValidationError("FAIL_CLOSED: suite_eval_report.axis_scoring_policy_id mismatch vs suite_definition")

    if not suite_evals:
        raise FL3ValidationError("FAIL_CLOSED: at least one suite_eval_report is required")

    # Load axis fitness reports
    fitness_reports: List[_Loaded] = []
    axis_scores: Dict[str, float] = {}
    for p in _dedup_sorted([str(x) for x in axis_fitness_report_paths]):
        path = Path(p)
        obj = _read_json_dict(path, name="axis_fitness_report")
        validate_schema_bound_object(obj)
        if str(obj.get("schema_id", "")).strip() != _AXIS_FITNESS_SCHEMA_ID:
            raise FL3ValidationError("FAIL_CLOSED: axis_fitness_report schema_id mismatch")
        rid = str(obj.get("axis_fitness_report_id", "")).strip()
        if not rid:
            raise FL3ValidationError("FAIL_CLOSED: axis_fitness_report_id missing")
        se_id = str(obj.get("suite_eval_report_id", "")).strip()
        if se_id not in suite_eval_by_id:
            raise FL3ValidationError("FAIL_CLOSED: axis_fitness_report references unknown suite_eval_report_id")
        loaded = _Loaded(path=path.resolve(), obj=obj)
        fitness_reports.append(loaded)

        ax_map = obj.get("axis_scores")
        if not isinstance(ax_map, dict) or not ax_map:
            raise FL3ValidationError("FAIL_CLOSED: axis_fitness_report.axis_scores missing/invalid")
        for axis_id, val in ax_map.items():
            aid = str(axis_id).strip()
            if not aid:
                raise FL3ValidationError("FAIL_CLOSED: axis_scores contains empty axis_id")
            if aid in axis_scores:
                raise FL3ValidationError(f"FAIL_CLOSED: duplicate axis_id across fitness reports: {aid}")
            if not isinstance(val, (int, float)):
                raise FL3ValidationError("FAIL_CLOSED: axis score must be number")
            axis_scores[aid] = float(val)

    if not fitness_reports:
        raise FL3ValidationError("FAIL_CLOSED: at least one axis_fitness_report is required")

    overall_decision = _decision_from_components([r.obj for r in fitness_reports])

    # Artifacts list: include all input reports and the suite/material refs they depend on.
    artifacts: List[Tuple[str, str]] = []
    include_paths: List[Path] = []
    include_paths.append(law_sha_path)
    include_paths.append(suite_reg_path)
    include_paths.extend([x.path for x in suite_defs])
    include_paths.extend([x.path for x in suite_evals])
    include_paths.extend([x.path for x in fitness_reports])

    # From suite defs: include the referenced catalog + policy objects.
    ref_paths: Set[Path] = set()
    for sd in suite_defs:
        cat_ref = str(sd.obj.get("validator_catalog_ref", "")).replace("\\", "/").strip()
        pol_ref = str(sd.obj.get("axis_scoring_policy_ref", "")).replace("\\", "/").strip()
        if not cat_ref or not pol_ref:
            raise FL3ValidationError("FAIL_CLOSED: suite_definition missing catalog/policy refs")
        cat_path = (repo_root / cat_ref).resolve()
        pol_path = (repo_root / pol_ref).resolve()
        ref_paths.add(cat_path)
        ref_paths.add(pol_path)
        # Validate the referenced objects are schema-bound.
        validate_schema_bound_object(_read_json_dict(cat_path, name="validator_catalog"))
        validate_schema_bound_object(_read_json_dict(pol_path, name="axis_scoring_policy"))

    include_paths.extend(sorted(ref_paths, key=lambda p: _relpath(repo_root, p)))

    for p in include_paths:
        rp = _relpath(repo_root, p)
        artifacts.append((rp, sha256_file_canonical(p)))

    # Dedup + sort by path.
    by_path: Dict[str, str] = {}
    for p, h in artifacts:
        if p in by_path and by_path[p] != h:
            raise FL3ValidationError("FAIL_CLOSED: artifact path hash mismatch across inputs")
        by_path[p] = h
    artifacts_rows = [{"path": p, "sha256": by_path[p]} for p in sorted(by_path.keys())]

    one_line = _one_line_verdict(
        decision=overall_decision,
        canonical_lane=canonical_lane,
        attestation_mode=mode,
        run_id=run_id,
        law_bundle_hash=law_bundle_hash,
        suite_registry_id=suite_registry_id,
        axis_scores=axis_scores,
    )

    created_at = utc_now_z()
    from schemas.schema_files import schema_version_hash  # type: ignore

    report: Dict[str, Any] = {
        "schema_id": _AUDIT_SCHEMA_ID,
        "schema_version_hash": schema_version_hash("fl3/kt.audit_eval_report.v1.json"),
        "audit_eval_report_id": "",
        "run_id": run_id,
        "law_bundle_hash": law_bundle_hash,
        "suite_registry_id": suite_registry_id,
        "canonical_lane": bool(canonical_lane),
        "attestation_mode": mode,
        "decision": overall_decision,
        "axis_scores": {k: axis_scores[k] for k in sorted(axis_scores.keys())},
        "artifacts": artifacts_rows,
        "one_line_verdict": one_line,
        "created_at": created_at,
        "notes": None,
    }
    report["audit_eval_report_id"] = sha256_hex_of_obj(report, drop_keys={"created_at", "audit_eval_report_id"})
    validate_schema_bound_object(report)

    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text_worm(
        path=out_dir / "audit_eval_report.json",
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="audit_eval_report.json",
    )
    write_text_worm(
        path=out_dir / "audit_eval_verdict.txt",
        text=one_line + "\n",
        label="audit_eval_verdict.txt",
    )
    print(one_line)
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_18 consolidated audit eval report generator (schema-bound; deterministic; WORM outputs).")
    ap.add_argument("--run-id", required=True, help="Run identifier for this audit report (human meaningful; non-empty).")
    ap.add_argument("--suite-def", action="append", default=[], help="Path to kt.suite_definition.v1 JSON (repeatable).")
    ap.add_argument("--suite-eval-report", action="append", default=[], help="Path to kt.suite_eval_report.v1 JSON (repeatable).")
    ap.add_argument("--axis-fitness-report", action="append", default=[], help="Path to kt.axis_fitness_report.v1 JSON (repeatable).")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM writes audit_eval_report.json + audit_eval_verdict.txt).")
    ap.add_argument("--attestation-mode", default="SIMULATED", choices=["SIMULATED", "HMAC", "PKI"], help="Attestation mode label to record in the report.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    _ = generate_audit_eval_report(
        suite_def_paths=[Path(p) for p in args.suite_def],
        suite_eval_report_paths=[Path(p) for p in args.suite_eval_report],
        axis_fitness_report_paths=[Path(p) for p in args.axis_fitness_report],
        run_id=str(args.run_id),
        out_dir=Path(args.out_dir),
        attestation_mode=str(args.attestation_mode),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

