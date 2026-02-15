from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.counterpressure_gate import check_counterpressure_evidence
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import canonical_json, repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_bytes_worm, write_text_worm


_PLAN_SCHEMA_ID = "kt.tournament_plan.v1"
_PLAN_SCHEMA_FILE = "fl3/kt.tournament_plan.v1.json"
_PLAN_SCHEMA_VERSION_HASH = schema_version_hash(_PLAN_SCHEMA_FILE)

_RESULT_SCHEMA_ID = "kt.tournament_result.v1"
_RESULT_SCHEMA_FILE = "fl3/kt.tournament_result.v1.json"
_RESULT_SCHEMA_VERSION_HASH = schema_version_hash(_RESULT_SCHEMA_FILE)

_ADMISSION_SCHEMA_ID = "kt.evaluation_admission_receipt.v1"
_ADMISSION_SCHEMA_FILE = "fl3/kt.evaluation_admission_receipt.v1.json"
_ADMISSION_SCHEMA_VERSION_HASH = schema_version_hash(_ADMISSION_SCHEMA_FILE)

_RC_SCHEMA_INVALID = "TOURNAMENT_SCHEMA_INVALID"
_RC_INPUT_MISSING = "TOURNAMENT_IMMUTABLE_INPUT_MISSING"
_RC_DETERMINISM_MISMATCH = "TOURNAMENT_DETERMINISM_MISMATCH"
_RC_DOMINANCE_VIOLATION = "DOMINANCE_RULE_VIOLATION"
_RC_CHAMPION_INVALID = "CHAMPION_SET_INVALID"
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
    """
    Determinism invariant: ensure the canonical time contract exists and is schema-valid.
    """
    p = (repo_root / relpath).resolve()
    obj = _read_json_dict(p, name="time_contract")
    validate_schema_bound_object(obj)


def _load_eval_admission_receipt(*, plan_path: Path, receipt_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    EPIC_16 enforcement: tournament evaluation is inadmissible unless explicitly admitted.

    Returns (receipt_obj_or_none, error_message_or_none).
    Never raises: caller translates into tournament fail-closed reason codes.
    """
    if not receipt_path.exists():
        return None, "missing evaluation_admission_receipt.json"

    try:
        rec = _read_json_dict(receipt_path, name="evaluation_admission_receipt")
        validate_schema_bound_object(rec)
    except Exception as exc:  # noqa: BLE001
        return None, f"invalid evaluation_admission_receipt.json: {exc}"

    if rec.get("schema_id") != _ADMISSION_SCHEMA_ID or rec.get("schema_version_hash") != _ADMISSION_SCHEMA_VERSION_HASH:
        return None, "evaluation admission receipt schema mismatch"

    if str(rec.get("decision", "")).strip() != "PASS":
        return rec, "evaluation admission denied"

    # Ensure receipt binds to the same plan semantics and canonical plan hash surface.
    try:
        plan = _read_json_dict(plan_path, name="tournament_plan")
    except Exception as exc:  # noqa: BLE001
        return rec, f"unable to read plan for receipt binding: {exc}"

    plan_sha = sha256_text(canonical_json(plan))
    if str(rec.get("evaluation_plan_sha256", "")).strip() != plan_sha:
        return rec, "evaluation_plan_sha256 mismatch"

    for field in ("base_model_id", "suite_id", "suite_root_hash", "decode_policy_id", "decode_cfg_hash"):
        if str(rec.get(field, "")).strip() != str(plan.get(field, "")).strip():
            return rec, f"{field} mismatch"

    return rec, None


def _extract_eval_signals(eval_report: Dict[str, Any]) -> Tuple[Dict[str, float], bool]:
    """
    Adapter scores are derived from schema-bound eval_report artifacts.

    EPIC_15 doctrine requires multiple axes; we approximate a minimal, deterministic set
    from existing FL4 factory evaluation artifacts:
      - format_compliance: proxy via trace_present
      - safety_refusal_integrity: proxy via final_verdict PASS
      - governance_fidelity: proxy via metric_probe_agreement
      - task_quality: utility_floor_score if present; else 0.0

    Returns: (axis_scores, hard_pass)
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


def build_tournament_result(
    *,
    repo_root: Path,
    plan_path: Path,
    entrants_root: Path,
    admission_receipt_path: Optional[Path] = None,
    break_hypothesis_path: Optional[Path] = None,
    counterpressure_plan_path: Optional[Path] = None,
    fragility_probe_result_path: Optional[Path] = None,
) -> Dict[str, Any]:
    reasons: List[str] = []
    notes: Optional[str] = None

    # Determinism/time contract invariant.
    try:
        _load_time_contract(repo_root=repo_root)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_TIME_CONTRACT_VIOLATION)

    # Plan must exist and be schema-bound.
    plan = _read_json_dict(plan_path, name="tournament_plan")
    try:
        validate_schema_bound_object(plan)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_SCHEMA_INVALID)
    if plan.get("schema_id") != _PLAN_SCHEMA_ID or plan.get("schema_version_hash") != _PLAN_SCHEMA_VERSION_HASH:
        reasons.append(_RC_SCHEMA_INVALID)

    # Structural invariant: clean repo.
    ok, _err = _git_status_is_clean(repo_root)
    if not ok:
        reasons.append(_RC_INPUT_MISSING)

    # EPIC_16: evaluation admission is mandatory for tournaments and must bind to this plan.
    if admission_receipt_path is None:
        admission_receipt_path = plan_path.resolve().parent / "evaluation_admission_receipt.json"
    rec, rec_err = _load_eval_admission_receipt(plan_path=plan_path, receipt_path=admission_receipt_path)
    if rec_err:
        reasons.append(_RC_INPUT_MISSING)
        notes = (notes + ";" if notes else "") + f"eval_admission:{rec_err}"

    entrants = plan.get("entrants") if isinstance(plan.get("entrants"), list) else []
    if not entrants:
        reasons.append(_RC_SCHEMA_INVALID)

    # EPIC_16 hard gate: counter-pressure evidence is mandatory and must PASS.
    if break_hypothesis_path is None:
        break_hypothesis_path = plan_path.resolve().parent / "break_hypothesis.json"
    if counterpressure_plan_path is None:
        counterpressure_plan_path = plan_path.resolve().parent / "counterpressure_plan.json"
    if fragility_probe_result_path is None:
        fragility_probe_result_path = plan_path.resolve().parent / "fragility_probe_result.json"

    suite_registry_path: Optional[Path] = None
    if isinstance(rec, dict):
        ref = str(rec.get("suite_registry_ref", "")).strip()
        if ref:
            p = Path(ref)
            suite_registry_path = (repo_root / ref).resolve() if not p.is_absolute() else p.resolve()

    entrant_hashes = [str(e.get("adapter_root_hash", "")).strip() for e in entrants if isinstance(e, dict)]
    ok_cp, cp_reasons, cp_notes = check_counterpressure_evidence(
        repo_root=repo_root,
        expected_base_model_id=str(plan.get("base_model_id", "")).strip(),
        expected_suite_id=str(plan.get("suite_id", "")).strip(),
        expected_suite_root_hash=str(plan.get("suite_root_hash", "")).strip(),
        expected_decode_policy_id=str(plan.get("decode_policy_id", "")).strip(),
        expected_decode_cfg_hash=str(plan.get("decode_cfg_hash", "")).strip(),
        entrant_adapter_root_hashes=entrant_hashes,
        suite_registry_path=suite_registry_path,
        break_hypothesis_path=break_hypothesis_path,
        counterpressure_plan_path=counterpressure_plan_path,
        fragility_probe_result_path=fragility_probe_result_path,
        expected_break_hypothesis_sha256=str(rec.get("break_hypothesis_sha256")).strip() if isinstance(rec, dict) else None,
        expected_counterpressure_plan_sha256=str(rec.get("counterpressure_plan_sha256")).strip() if isinstance(rec, dict) else None,
    )
    if not ok_cp:
        reasons.extend(cp_reasons)
    if cp_notes:
        notes = (notes + ";" if notes else "") + f"counterpressure:{cp_notes}"

    # Load failure taxonomy to close reason codes.
    taxonomy = load_failure_taxonomy(repo_root=repo_root)
    allowed_rc = _allowed_reason_codes(taxonomy=taxonomy)

    # Load entrant evidence: job_dir_manifest + eval_report under entrants_root/<adapter_root_hash>/.
    eval_axes: Dict[str, Dict[str, float]] = {}
    hard_pass: Dict[str, bool] = {}

    for row in entrants:
        if not isinstance(row, dict):
            reasons.append(_RC_SCHEMA_INVALID)
            continue
        adapter_root_hash = str(row.get("adapter_root_hash", "")).strip()
        adapter_id = str(row.get("adapter_id", "")).strip()
        adapter_version = str(row.get("adapter_version", "")).strip()
        if not adapter_root_hash or not adapter_id or not adapter_version:
            reasons.append(_RC_SCHEMA_INVALID)
            continue

        job_dir = (entrants_root / adapter_root_hash).resolve()
        if not job_dir.is_dir():
            reasons.append(_RC_INPUT_MISSING)
            continue

        jdm_path = job_dir / "job_dir_manifest.json"
        eval_path = job_dir / "eval_report.json"
        if not jdm_path.exists() or not eval_path.exists():
            reasons.append(_RC_INPUT_MISSING)
            continue

        try:
            jdm = _read_json_dict(jdm_path, name="job_dir_manifest")
            validate_schema_bound_object(jdm)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_SCHEMA_INVALID)
            continue

        if str(jdm.get("hash_manifest_root_hash", "")).strip() != adapter_root_hash:
            reasons.append(_RC_INPUT_MISSING)
            continue

        # Immutable input integrity: job_dir_manifest must correctly bind eval_report.json content hash.
        files = jdm.get("files") if isinstance(jdm.get("files"), list) else []
        binding = next((f for f in files if isinstance(f, dict) and f.get("path") == "eval_report.json"), None)
        if not isinstance(binding, dict):
            reasons.append(_RC_INPUT_MISSING)
            continue
        expected_eval_sha = str(binding.get("sha256", "")).strip()
        try:
            got_eval_sha = sha256_file_canonical(eval_path)
        except Exception:  # noqa: BLE001
            got_eval_sha = ""
        if expected_eval_sha != got_eval_sha:
            reasons.append(_RC_INPUT_MISSING)
            continue

        try:
            ev = _read_json_dict(eval_path, name="eval_report")
            validate_schema_bound_object(ev)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_SCHEMA_INVALID)
            continue
        if str(ev.get("adapter_id", "")).strip() != adapter_id or str(ev.get("adapter_version", "")).strip() != adapter_version:
            reasons.append(_RC_INPUT_MISSING)
            continue

        axes, hp = _extract_eval_signals(ev)
        eval_axes[adapter_root_hash] = axes
        hard_pass[adapter_root_hash] = hp

    # Close reason codes over the taxonomy. Never emit unknown reason codes.
    reasons = sorted(set(reasons))
    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        reasons = [_RC_SCHEMA_INVALID]
        notes = "closed_reason_codes_violation"

    epsilon = float(plan.get("epsilon", 0.0)) if isinstance(plan.get("epsilon"), (int, float)) else 0.0
    created_at = utc_now_z()

    entrants_norm = [
        {
            "adapter_root_hash": str(r.get("adapter_root_hash", "")).strip(),
            "adapter_id": str(r.get("adapter_id", "")).strip(),
            "adapter_version": str(r.get("adapter_version", "")).strip(),
        }
        for r in entrants
        if isinstance(r, dict)
    ]

    dominance_pairs: List[Dict[str, str]] = []
    champion_set: List[str] = []

    if not reasons:
        hashes = [e["adapter_root_hash"] for e in entrants_norm if e.get("adapter_root_hash")]
        hashes_sorted = sorted(hashes)
        # Ensure we have evidence for every entrant.
        if set(hashes_sorted) != set(eval_axes.keys()):
            reasons.append(_RC_INPUT_MISSING)
        else:
            for i, a in enumerate(hashes_sorted):
                for b in hashes_sorted[i + 1 :]:
                    a_hp = bool(hard_pass.get(a, False))
                    b_hp = bool(hard_pass.get(b, False))
                    a_dom_b = False
                    b_dom_a = False
                    if a_hp and not b_hp:
                        a_dom_b = True
                    elif b_hp and not a_hp:
                        b_dom_a = True
                    elif a_hp and b_hp:
                        a_dom_b = _dominates(a=eval_axes[a], b=eval_axes[b], epsilon=epsilon)
                        b_dom_a = _dominates(a=eval_axes[b], b=eval_axes[a], epsilon=epsilon)

                    if a_dom_b and b_dom_a:
                        reasons.append(_RC_DOMINANCE_VIOLATION)
                    elif a_dom_b:
                        dominance_pairs.append({"dominant_adapter_root_hash": a, "dominated_adapter_root_hash": b})
                    elif b_dom_a:
                        dominance_pairs.append({"dominant_adapter_root_hash": b, "dominated_adapter_root_hash": a})

            dominated = {p["dominated_adapter_root_hash"] for p in dominance_pairs}
            champion_set = [h for h in hashes_sorted if h not in dominated]
            if not champion_set:
                reasons.append(_RC_CHAMPION_INVALID)

    status = "PASS" if not reasons else "FAIL_CLOSED"
    if status == "FAIL_CLOSED":
        champion_set = []
        dominance_pairs = []

    dominance_pairs = sorted(dominance_pairs, key=lambda d: (d["dominant_adapter_root_hash"], d["dominated_adapter_root_hash"]))
    champion_set = sorted(champion_set)

    result: Dict[str, Any] = {
        "schema_id": _RESULT_SCHEMA_ID,
        "schema_version_hash": _RESULT_SCHEMA_VERSION_HASH,
        "tournament_result_id": "",
        "tournament_plan_id": str(plan.get("tournament_plan_id", "")).strip(),
        "status": status,
        "reason_codes": sorted(set(reasons)),
        "base_model_id": str(plan.get("base_model_id", "")).strip(),
        "suite_id": str(plan.get("suite_id", "")).strip(),
        "decode_policy_id": str(plan.get("decode_policy_id", "")).strip(),
        "tournament_mode": str(plan.get("tournament_mode", "")).strip(),
        "epsilon": epsilon,
        "entrants": entrants_norm,
        "champion_set": champion_set,
        "dominance_pairs": dominance_pairs,
        "created_at": created_at,
    }
    if notes is not None:
        result["notes"] = notes

    result["tournament_result_id"] = sha256_hex_of_obj(result, drop_keys={"created_at", "tournament_result_id"})

    # Result must be schema-valid.
    validate_schema_bound_object(result)
    return result


def run_tournament(
    *,
    repo_root: Path,
    plan_path: Path,
    entrants_root: Path,
    out_dir: Path,
    admission_receipt_path: Optional[Path] = None,
    break_hypothesis_path: Optional[Path] = None,
    counterpressure_plan_path: Optional[Path] = None,
    fragility_probe_result_path: Optional[Path] = None,
) -> Dict[str, Any]:
    result = build_tournament_result(
        repo_root=repo_root,
        plan_path=plan_path,
        entrants_root=entrants_root,
        admission_receipt_path=admission_receipt_path,
        break_hypothesis_path=break_hypothesis_path,
        counterpressure_plan_path=counterpressure_plan_path,
        fragility_probe_result_path=fragility_probe_result_path,
    )
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "tournament_result.json"
    text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    try:
        write_text_worm(path=out_path, text=text, label="tournament_result.json")
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: {_RC_DETERMINISM_MISMATCH}: {exc}") from exc

    # Copy evaluation admission receipt into the tournament out_dir (WORM, byte-identical no-op).
    if admission_receipt_path is None:
        admission_receipt_path = plan_path.resolve().parent / "evaluation_admission_receipt.json"
    if admission_receipt_path.exists():
        try:
            data = admission_receipt_path.read_bytes()
            write_bytes_worm(path=out_dir / "evaluation_admission_receipt.json", data=data, label="evaluation_admission_receipt.json")
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError(f"FAIL_CLOSED: {_RC_DETERMINISM_MISMATCH}: {exc}") from exc

    # Copy counter-pressure evidence into the tournament out_dir (WORM, byte-identical no-op).
    if break_hypothesis_path is None:
        break_hypothesis_path = plan_path.resolve().parent / "break_hypothesis.json"
    if counterpressure_plan_path is None:
        counterpressure_plan_path = plan_path.resolve().parent / "counterpressure_plan.json"
    if fragility_probe_result_path is None:
        fragility_probe_result_path = plan_path.resolve().parent / "fragility_probe_result.json"
    for src, dst_name in (
        (break_hypothesis_path, "break_hypothesis.json"),
        (counterpressure_plan_path, "counterpressure_plan.json"),
        (fragility_probe_result_path, "fragility_probe_result.json"),
    ):
        if src is None:
            continue
        sp = src.resolve()
        if sp.exists():
            try:
                data = sp.read_bytes()
                write_bytes_worm(path=out_dir / dst_name, data=data, label=dst_name)
            except Exception as exc:  # noqa: BLE001
                raise FL3ValidationError(f"FAIL_CLOSED: {_RC_DETERMINISM_MISMATCH}: {exc}") from exc

    if str(result.get("status")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: tournament runner refused to certify champion set")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_15/16 deterministic tournament runner (dominance + champion set; requires evaluation admission).")
    ap.add_argument("--plan", required=True, help="Path to kt.tournament_plan.v1 JSON (schema-bound).")
    ap.add_argument(
        "--entrants-root",
        required=True,
        help="Directory containing entrant job dirs named by adapter_root_hash; each must include job_dir_manifest.json + eval_report.json.",
    )
    ap.add_argument("--out-dir", required=True, help="Output directory (writes tournament_result.json WORM).")
    ap.add_argument(
        "--admission-receipt",
        default=None,
        help="Path to kt.evaluation_admission_receipt.v1 JSON. Default: <plan_dir>/evaluation_admission_receipt.json",
    )
    ap.add_argument("--break-hypothesis", default=None, help="Path to kt.break_hypothesis.v1 JSON. Default: <plan_dir>/break_hypothesis.json")
    ap.add_argument(
        "--counterpressure-plan",
        default=None,
        help="Path to kt.counterpressure_plan.v1 JSON. Default: <plan_dir>/counterpressure_plan.json",
    )
    ap.add_argument(
        "--fragility-probe-result",
        default=None,
        help="Path to kt.fragility_probe_result.v1 JSON. Default: <plan_dir>/fragility_probe_result.json",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    _ = run_tournament(
        repo_root=repo_root,
        plan_path=Path(args.plan),
        entrants_root=Path(args.entrants_root),
        out_dir=Path(args.out_dir),
        admission_receipt_path=Path(args.admission_receipt).resolve() if args.admission_receipt else None,
        break_hypothesis_path=Path(args.break_hypothesis).resolve() if args.break_hypothesis else None,
        counterpressure_plan_path=Path(args.counterpressure_plan).resolve() if args.counterpressure_plan else None,
        fragility_probe_result_path=Path(args.fragility_probe_result).resolve() if args.fragility_probe_result else None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
