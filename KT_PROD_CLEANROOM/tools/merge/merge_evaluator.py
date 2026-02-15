from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm


_MANIFEST_SCHEMA_ID = "kt.merge_manifest.v1"
_MANIFEST_SCHEMA_FILE = "fl3/kt.merge_manifest.v1.json"
_MANIFEST_SCHEMA_VERSION_HASH = schema_version_hash(_MANIFEST_SCHEMA_FILE)

_EVAL_SCHEMA_ID = "kt.merge_eval_receipt.v1"
_EVAL_SCHEMA_FILE = "fl3/kt.merge_eval_receipt.v1.json"
_EVAL_SCHEMA_VERSION_HASH = schema_version_hash(_EVAL_SCHEMA_FILE)

_ROLLBACK_SCHEMA_ID = "kt.merge_rollback_plan.v1"
_ROLLBACK_SCHEMA_FILE = "fl3/kt.merge_rollback_plan.v1.json"
_ROLLBACK_SCHEMA_VERSION_HASH = schema_version_hash(_ROLLBACK_SCHEMA_FILE)

_TOURNAMENT_RESULT_SCHEMA_ID = "kt.tournament_result.v1"

_RC_PRECONDITION = "MERGE_PRECONDITION_FAILED"
_RC_SAFETY_REGRESSION = "MERGE_SAFETY_REGRESSION"
_RC_UTILITY_GATE_FAILED = "MERGE_UTILITY_GATE_FAILED"
_RC_ROLLBACK_MISSING = "MERGE_ROLLBACK_PLAN_MISSING"
_RC_TIME_CONTRACT_VIOLATION = "TIME_CONTRACT_VIOLATION"


def _allowed_reason_codes(*, taxonomy: Dict[str, Any]) -> Set[str]:
    mappings = taxonomy.get("mappings") if isinstance(taxonomy.get("mappings"), list) else []
    out: Set[str] = set()
    for m in mappings:
        if isinstance(m, dict):
            rc = m.get("reason_code")
            if isinstance(rc, str) and rc.strip():
                out.add(rc.strip())
    return out


def _git_status_is_clean(repo_root: Path) -> Tuple[bool, str]:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(repo_root), text=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"FAIL_CLOSED: unable to run git status: {exc}"
    if out.strip():
        return False, "FAIL_CLOSED: repo is not clean"
    return True, ""


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _load_time_contract(*, repo_root: Path, relpath: str = "KT_PROD_CLEANROOM/AUDITS/FL4_TIME_CONTRACT.json") -> None:
    p = (repo_root / relpath).resolve()
    obj = _read_json_dict(p, name="time_contract")
    validate_schema_bound_object(obj)


def _extract_eval_signals(eval_report: Dict[str, Any]) -> Tuple[Dict[str, float], bool]:
    """
    Deterministic axis extraction from schema-bound eval_report artifacts.
    """
    results = eval_report.get("results") if isinstance(eval_report.get("results"), dict) else {}

    task_quality = 0.0
    if "utility_floor_score" in eval_report:
        try:
            task_quality = float(eval_report.get("utility_floor_score", 0.0))
        except Exception:
            task_quality = 0.0

    trace_present = bool(results.get("trace_present", False))
    metric_probe_agreement = bool(results.get("metric_probe_agreement", False))

    verdict = str(eval_report.get("final_verdict", "")).strip().upper()
    hard_pass = verdict == "PASS"

    axis_scores = {
        "format_compliance": 1.0 if trace_present else 0.0,
        "safety_refusal_integrity": 1.0 if hard_pass else 0.0,
        "governance_fidelity": 1.0 if metric_probe_agreement else 0.0,
        "task_quality": max(0.0, min(1.0, task_quality)),
    }
    return axis_scores, hard_pass


def _dominates(*, a: Dict[str, float], b: Dict[str, float], epsilon: float) -> bool:
    keys = sorted(set(a.keys()) | set(b.keys()))
    if not keys:
        return False
    not_worse = True
    strictly_better = False
    for k in keys:
        av = float(a.get(k, 0.0))
        bv = float(b.get(k, 0.0))
        if av < (bv - epsilon):
            not_worse = False
            break
        if av > (bv + epsilon):
            strictly_better = True
    return bool(not_worse and strictly_better)


def _load_entrant_evidence(*, entrants_root: Path, entrant: Dict[str, Any]) -> Tuple[Dict[str, float], bool]:
    adapter_root_hash = str(entrant.get("adapter_root_hash", "")).strip()
    adapter_id = str(entrant.get("adapter_id", "")).strip()
    adapter_version = str(entrant.get("adapter_version", "")).strip()
    if not adapter_root_hash or not adapter_id or not adapter_version:
        raise FL3ValidationError("FAIL_CLOSED: entrant fields missing (merge evaluator)")

    job_dir = (entrants_root / adapter_root_hash).resolve()
    jdm_path = job_dir / "job_dir_manifest.json"
    eval_path = job_dir / "eval_report.json"
    if not jdm_path.exists() or not eval_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: entrant evidence missing (merge evaluator)")

    jdm = _read_json_dict(jdm_path, name="job_dir_manifest")
    validate_schema_bound_object(jdm)
    if str(jdm.get("hash_manifest_root_hash", "")).strip() != adapter_root_hash:
        raise FL3ValidationError("FAIL_CLOSED: entrant adapter_root_hash mismatch (merge evaluator)")

    files = jdm.get("files") if isinstance(jdm.get("files"), list) else []
    binding = next((f for f in files if isinstance(f, dict) and f.get("path") == "eval_report.json"), None)
    if not isinstance(binding, dict):
        raise FL3ValidationError("FAIL_CLOSED: job_dir_manifest missing eval_report.json entry (merge evaluator)")
    expected_eval_sha = str(binding.get("sha256", "")).strip()
    got_eval_sha = sha256_file_canonical(eval_path)
    if expected_eval_sha != got_eval_sha:
        raise FL3ValidationError("FAIL_CLOSED: eval_report.json sha256 mismatch vs job_dir_manifest (merge evaluator)")

    ev = _read_json_dict(eval_path, name="eval_report")
    validate_schema_bound_object(ev)
    if str(ev.get("adapter_id", "")).strip() != adapter_id or str(ev.get("adapter_version", "")).strip() != adapter_version:
        raise FL3ValidationError("FAIL_CLOSED: eval_report adapter_id/version mismatch (merge evaluator)")

    return _extract_eval_signals(ev)


def _compute_dominance_pairs(
    *, hashes: List[str], axes_by_hash: Dict[str, Dict[str, float]], hard_pass_by_hash: Dict[str, bool], epsilon: float
) -> List[Dict[str, str]]:
    hashes = sorted(hashes)
    out: List[Dict[str, str]] = []
    for i, a in enumerate(hashes):
        for b in hashes[i + 1 :]:
            a_hp = bool(hard_pass_by_hash.get(a, False))
            b_hp = bool(hard_pass_by_hash.get(b, False))
            a_dom_b = False
            b_dom_a = False
            if a_hp and not b_hp:
                a_dom_b = True
            elif b_hp and not a_hp:
                b_dom_a = True
            elif a_hp and b_hp:
                a_dom_b = _dominates(a=axes_by_hash[a], b=axes_by_hash[b], epsilon=epsilon)
                b_dom_a = _dominates(a=axes_by_hash[b], b=axes_by_hash[a], epsilon=epsilon)

            if a_dom_b and b_dom_a:
                raise FL3ValidationError("FAIL_CLOSED: dominance cycle detected (merge evaluator)")
            if a_dom_b:
                out.append({"dominant_adapter_root_hash": a, "dominated_adapter_root_hash": b})
            elif b_dom_a:
                out.append({"dominant_adapter_root_hash": b, "dominated_adapter_root_hash": a})
    return sorted(out, key=lambda d: (d["dominant_adapter_root_hash"], d["dominated_adapter_root_hash"]))


def _compute_champion_set(*, hashes: List[str], dominance_pairs: List[Dict[str, str]]) -> List[str]:
    dominated = {p["dominated_adapter_root_hash"] for p in dominance_pairs}
    return sorted([h for h in sorted(hashes) if h not in dominated])


def build_merge_artifacts(
    *,
    repo_root: Path,
    merge_manifest_path: Path,
    tournament_result_path: Path,
    entrants_root: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    reasons: List[str] = []
    notes: Optional[str] = None

    try:
        _load_time_contract(repo_root=repo_root)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_TIME_CONTRACT_VIOLATION)

    ok, _err = _git_status_is_clean(repo_root)
    if not ok:
        reasons.append(_RC_PRECONDITION)

    taxonomy = load_failure_taxonomy(repo_root=repo_root)
    allowed_rc = _allowed_reason_codes(taxonomy=taxonomy)

    manifest = _read_json_dict(merge_manifest_path, name="merge_manifest")
    try:
        validate_schema_bound_object(manifest)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_PRECONDITION)
    if manifest.get("schema_id") != _MANIFEST_SCHEMA_ID or manifest.get("schema_version_hash") != _MANIFEST_SCHEMA_VERSION_HASH:
        reasons.append(_RC_PRECONDITION)

    tresult = _read_json_dict(tournament_result_path, name="tournament_result")
    try:
        validate_schema_bound_object(tresult)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_PRECONDITION)
    if tresult.get("schema_id") != _TOURNAMENT_RESULT_SCHEMA_ID:
        reasons.append(_RC_PRECONDITION)
    if str(tresult.get("status", "")).strip().upper() != "PASS":
        reasons.append(_RC_PRECONDITION)

    base_model_id = str(manifest.get("base_model_id", "")).strip()
    if base_model_id and str(tresult.get("base_model_id", "")).strip() and str(tresult.get("base_model_id", "")).strip() != base_model_id:
        reasons.append(_RC_PRECONDITION)

    parents = manifest.get("parents") if isinstance(manifest.get("parents"), list) else []
    parent_hashes = [str(p.get("adapter_root_hash", "")).strip() for p in parents if isinstance(p, dict)]
    parent_hashes = sorted([h for h in parent_hashes if h])
    if len(parent_hashes) < 2:
        reasons.append(_RC_PRECONDITION)

    entrants = tresult.get("entrants") if isinstance(tresult.get("entrants"), list) else []
    entrant_hashes = [str(e.get("adapter_root_hash", "")).strip() for e in entrants if isinstance(e, dict)]
    entrant_hashes = sorted([h for h in entrant_hashes if h])
    if any(h not in set(entrant_hashes) for h in parent_hashes):
        reasons.append(_RC_PRECONDITION)

    child_candidates = sorted(set(entrant_hashes) - set(parent_hashes))
    child_hash = child_candidates[0] if len(child_candidates) == 1 else ""
    if not child_hash:
        reasons.append(_RC_PRECONDITION)

    axes_by_hash: Dict[str, Dict[str, float]] = {}
    hard_pass_by_hash: Dict[str, bool] = {}
    for e in entrants:
        if not isinstance(e, dict):
            reasons.append(_RC_PRECONDITION)
            continue
        h = str(e.get("adapter_root_hash", "")).strip()
        if not h:
            reasons.append(_RC_PRECONDITION)
            continue
        try:
            axes, hp = _load_entrant_evidence(entrants_root=entrants_root, entrant=e)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_PRECONDITION)
            continue
        axes_by_hash[h] = axes
        hard_pass_by_hash[h] = hp

    epsilon = float(tresult.get("epsilon", 0.0)) if isinstance(tresult.get("epsilon"), (int, float)) else 0.0

    # Preconditions: parents are hard-pass and are all champions among parents.
    if not reasons:
        if any(not hard_pass_by_hash.get(h, False) for h in parent_hashes):
            reasons.append(_RC_PRECONDITION)
        else:
            parent_dom = _compute_dominance_pairs(
                hashes=parent_hashes, axes_by_hash=axes_by_hash, hard_pass_by_hash=hard_pass_by_hash, epsilon=epsilon
            )
            parent_champs = _compute_champion_set(hashes=parent_hashes, dominance_pairs=parent_dom)
            if set(parent_champs) != set(parent_hashes):
                reasons.append(_RC_PRECONDITION)

    safety_regression = False
    if not reasons and child_hash:
        if not hard_pass_by_hash.get(child_hash, False):
            safety_regression = True
            reasons.append(_RC_SAFETY_REGRESSION)

    utility_gate_pass = False
    if not reasons and child_hash:
        dom_pairs = _compute_dominance_pairs(
            hashes=entrant_hashes, axes_by_hash=axes_by_hash, hard_pass_by_hash=hard_pass_by_hash, epsilon=epsilon
        )
        champs = _compute_champion_set(hashes=entrant_hashes, dominance_pairs=dom_pairs)
        child_dominates_parent = any(
            p["dominant_adapter_root_hash"] == child_hash and p["dominated_adapter_root_hash"] in set(parent_hashes) for p in dom_pairs
        )
        if child_dominates_parent:
            utility_gate_pass = True
        elif child_hash in set(champs) and len(champs) == 1 and len(parent_hashes) >= 2:
            utility_gate_pass = True
        if not utility_gate_pass:
            reasons.append(_RC_UTILITY_GATE_FAILED)

    reasons = sorted(set(reasons))
    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        reasons = [_RC_PRECONDITION]
        notes = "closed_reason_codes_violation"

    created_at = utc_now_z()
    try:
        tournament_ref = str(tournament_result_path.resolve().relative_to(repo_root).as_posix())
    except Exception:
        tournament_ref = tournament_result_path.resolve().as_posix()

    status = "PASS" if not reasons else "FAIL_CLOSED"
    eval_receipt: Dict[str, Any] = {
        "schema_id": _EVAL_SCHEMA_ID,
        "schema_version_hash": _EVAL_SCHEMA_VERSION_HASH,
        "merge_eval_receipt_id": "",
        "merge_manifest_id": str(manifest.get("merge_manifest_id", "")).strip(),
        "status": status,
        "reason_codes": sorted(set(reasons)),
        "safety_regression": bool(safety_regression),
        "utility_gate_pass": bool(utility_gate_pass),
        "tournament_result_ref": tournament_ref,
        "created_at": created_at,
    }
    if child_hash:
        eval_receipt["notes"] = f"child_adapter_root_hash={child_hash}"
    if notes is not None:
        eval_receipt["notes"] = notes if "notes" not in eval_receipt else f"{eval_receipt['notes']};{notes}"
    eval_receipt["merge_eval_receipt_id"] = sha256_hex_of_obj(eval_receipt, drop_keys={"created_at", "merge_eval_receipt_id"})
    validate_schema_bound_object(eval_receipt)

    rollback_steps = [
        {"step_id": "01_disable_child_routing", "action": "router.disable_adapter", "target": child_hash or "child_adapter"},
        {"step_id": "02_reinstate_parents", "action": "router.enable_adapters", "target": ",".join(parent_hashes) if parent_hashes else "parents"},
    ]
    rollback: Dict[str, Any] = {
        "schema_id": _ROLLBACK_SCHEMA_ID,
        "schema_version_hash": _ROLLBACK_SCHEMA_VERSION_HASH,
        "rollback_plan_id": "",
        "merge_manifest_id": str(manifest.get("merge_manifest_id", "")).strip(),
        "steps": sorted(rollback_steps, key=lambda s: str(s.get("step_id", ""))),
        "created_at": created_at,
    }
    rollback["rollback_plan_id"] = sha256_hex_of_obj(rollback, drop_keys={"created_at", "rollback_plan_id"})
    validate_schema_bound_object(rollback)

    return eval_receipt, rollback


def run_merge_evaluator(
    *,
    repo_root: Path,
    merge_manifest_path: Path,
    tournament_result_path: Path,
    entrants_root: Path,
    out_dir: Path,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    eval_receipt, rollback = build_merge_artifacts(
        repo_root=repo_root,
        merge_manifest_path=merge_manifest_path,
        tournament_result_path=tournament_result_path,
        entrants_root=entrants_root,
    )

    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    eval_path = out_dir / "merge_eval_receipt.json"
    rollback_path = out_dir / "merge_rollback_plan.json"

    enforce_all_or_none_exist([eval_path, rollback_path], label="merge_artifacts")
    eval_text = json.dumps(eval_receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    rollback_text = json.dumps(rollback, indent=2, sort_keys=True, ensure_ascii=True) + "\n"

    for p, txt, label in (
        (eval_path, eval_text, "merge_eval_receipt.json"),
        (rollback_path, rollback_text, "merge_rollback_plan.json"),
    ):
        if p.exists() and p.read_text(encoding="utf-8") != txt:
            raise FL3ValidationError(f"FAIL_CLOSED: {label} determinism mismatch (refusing overwrite)")

    try:
        write_text_worm(path=eval_path, text=eval_text, label="merge_eval_receipt.json")
        write_text_worm(path=rollback_path, text=rollback_text, label="merge_rollback_plan.json")
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: {_RC_ROLLBACK_MISSING}: {exc}") from exc

    if str(eval_receipt.get("status")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: merge evaluator refused promotion")
    return eval_receipt, rollback


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_15 merge evaluator (admissibility, safety gate, rollback plan).")
    ap.add_argument("--merge-manifest", required=True, help="Path to kt.merge_manifest.v1 JSON (schema-bound).")
    ap.add_argument("--tournament-result", required=True, help="Path to kt.tournament_result.v1 JSON (schema-bound).")
    ap.add_argument(
        "--entrants-root",
        required=True,
        help="Directory containing entrant job dirs named by adapter_root_hash (must include job_dir_manifest.json + eval_report.json).",
    )
    ap.add_argument("--out-dir", required=True, help="Output directory (writes merge_eval_receipt.json + merge_rollback_plan.json WORM).")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    _ = run_merge_evaluator(
        repo_root=repo_root,
        merge_manifest_path=Path(args.merge_manifest),
        tournament_result_path=Path(args.tournament_result),
        entrants_root=Path(args.entrants_root),
        out_dir=Path(args.out_dir),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

