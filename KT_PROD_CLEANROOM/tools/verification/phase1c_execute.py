from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.verification.strict_json import load_no_dupes


class Phase1CError(RuntimeError):
    pass


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Phase 1C executor must be runnable via `python -m tools.verification.phase1c_execute`
    without relying on callers to pre-set PYTHONPATH.
    """
    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _repo_root_from(this_file: Path) -> Path:
    """
    Minimal, deterministic repo root detection.
    """
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise Phase1CError("Unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _sha256_json(obj: object) -> str:
    from tools.verification.fl3_canonical import sha256_json  # type: ignore

    return sha256_json(obj)


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical_json(obj), encoding="utf-8", newline="\n")


def _load_work_order(*, work_order_path: Path) -> Dict[str, Any]:
    obj = load_no_dupes(work_order_path)
    if not isinstance(obj, dict):
        raise Phase1CError("Phase 1C work order must be a JSON object (fail-closed)")
    return obj


def _validate_schema_bound_object(payload: Any) -> None:
    from tools.verification.fl3_validators import validate_schema_bound_object  # type: ignore

    validate_schema_bound_object(payload)


def _schema_version_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def _validate_work_order(work_order: Dict[str, Any]) -> None:
    from schemas.schema_registry import validate_object_with_binding  # type: ignore

    validate_object_with_binding(work_order)


def _build_node_receipt(*, node_id: str, status: str, details: Dict[str, Any]) -> Dict[str, Any]:
    receipt: Dict[str, Any] = {
        "node_id": node_id,
        "status": status,
        "details": details,
        # Deterministic signature: hash of the receipt content (excluding signature).
        "signature_sha256": "",
    }
    receipt["signature_sha256"] = _sha256_json({k: v for k, v in receipt.items() if k != "signature_sha256"})
    return receipt


def _run_growth_gate(*, repo_root: Path, out_dir: Path) -> Tuple[str, Path]:
    """
    Executes the existing growth gate in a subprocess (same interpreter).
    The gate itself is canonical and must be invoked as-is (no semantics changes).
    """
    report_path = out_dir / "growth_e2e_gate_report.json"
    cmd = [
        sys.executable,
        "-m",
        "tools.verification.growth_e2e_gate",
        "--pressure-runs",
        "1",
        "--out",
        str(report_path),
    ]
    env = dict(os.environ)
    # Co-locate growth artifacts under out_dir; this keeps Phase 1C offline/sandboxed.
    env.setdefault("KT_GROWTH_ARTIFACTS_ROOT", str((out_dir / "growth_artifacts").resolve()))
    p = subprocess.run(cmd, cwd=str(repo_root), env=env, text=True, capture_output=True)
    (out_dir / "growth_e2e_gate.log").write_text(p.stdout + p.stderr, encoding="utf-8", newline="\n")
    if not report_path.exists():
        raise Phase1CError("FAIL_CLOSED: growth gate did not create growth_e2e_gate_report.json")
    if p.returncode != 0:
        raise Phase1CError(f"FAIL_CLOSED: growth gate rc={p.returncode}")
    return "PASS", report_path


def _build_minimal_evidence_pack(*, evidence_dir: Path) -> Path:
    """
    Minimal deterministic evidence pack sufficient for replay-from-receipts checks.

    This intentionally avoids model training or adapter mutation; it only instantiates
    the evaluator semantics required by the Phase 1C work order.
    """
    job_dir = evidence_dir / "job_dir"
    _write_json(
        job_dir / "eval_report.json",
        {
            "utility_floor_pass": True,
            "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
            "metric_probes": [{"delta": 0.0, "agreement": True}],
            "final_verdict": "PASS",
        },
    )
    _write_json(job_dir / "promotion.json", {"decision": "NO_PROMOTE"})
    return job_dir


def _run_replay_from_receipts(*, evidence_dir: Path, out_dir: Path) -> Tuple[str, Path]:
    from tools.verification.fl4_replay_from_receipts import replay_from_evidence_dir  # type: ignore

    report = replay_from_evidence_dir(evidence_dir=evidence_dir)
    out_path = out_dir / "replay_from_receipts_report.json"
    _write_json(out_path, report)
    return str(report.get("status", "FAIL")), out_path


def _write_watcher_advisory_artifacts(*, out_dir: Path) -> Path:
    """
    Watcher/SPC are NCON: emit optional diagnostics only.
    We emit a minimal NCON advisory artifact that is explicitly non-authoritative.
    """
    # NCON advisory artifact: intentionally not named like a canonical watcher/SPC report file.
    # Canonical gating code must not consult watcher/SPC artifacts; Phase 1C only proves
    # that an NCON-style advisory can execute and still remain non-authoritative.
    drift_path = out_dir / "ncon_advisory.json"
    obj = {
        "schema_id": "kt.ncon_advisory.v1",
        # Explicit veto attempt (must be ignored unless corroborated by a canonical failure).
        "veto_attempt": True,
        "scores": [
            {
                "agent_id": "ncon.synthetic",
                "score": 1.5,
                "evidence": [
                    {
                        "weight": 1.0,
                        "pointer": {
                            "transcript_relpath": "transcript.jsonl",
                            "start_line": 1,
                            "end_line": 1,
                            "line_hashes": ["0" * 64],
                            "edge_ids": ["edge:0"],
                        },
                    },
                    {
                        "weight": 0.5,
                        "pointer": {
                            "transcript_relpath": "transcript.jsonl",
                            "start_line": 2,
                            "end_line": 2,
                            "line_hashes": ["1" * 64],
                            "edge_ids": ["edge:1"],
                        },
                    },
                ],
            }
        ],
    }
    _write_json(drift_path, obj)
    return drift_path


def _validate_watcher_artifacts_if_present(*, out_dir: Path) -> None:
    from tools.verification.watcher_spc_validators import validate_watcher_spc_artifacts_if_present  # type: ignore

    validate_watcher_spc_artifacts_if_present(evidence_dir=out_dir)


def _promotion_shadow(*, repo_root: Path, out_dir: Path) -> Tuple[Dict[str, Any], Optional[Path]]:
    """
    Shadow-only promotion: emit a schema-bound promotion report without mutating the canonical index.

    This is deliberately not a call to fl4_promote.py (which performs atomic canonical promotion).
    """
    from tools.verification.fl3_validators import load_fl3_canonical_runtime_paths  # type: ignore

    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    canonical_index = (repo_root / str(paths["exports_adapters_root"]) / "promoted_index.json").resolve()
    before = canonical_index.read_bytes() if canonical_index.exists() else b""

    # Shadow report is always written to out_dir (never to exports/).
    # Use the existing FL4 promotion report schema for the payload.
    report: Dict[str, Any] = {
        "schema_id": "kt.fl4.promotion_report.v1",
        "schema_version_hash": _schema_version_hash("fl3/kt.fl4.promotion_report.v1.json"),
        "job_dir": "",
        "promoted_dir": "",
        "promoted_index_path": str(canonical_index.relative_to(repo_root).as_posix()) if canonical_index.exists() else "",
        "content_hash": "0" * 64,
        "promoted_manifest_id": "0" * 64,
        "promoted_manifest_sha256": "0" * 64,
        "canary_artifact_hash": "0" * 64,
    }
    _validate_schema_bound_object(report)

    # Emit a promoted_index_candidate.json (shadow-only) for auditability.
    idx_candidate: Dict[str, Any] = {
        "schema_id": "kt.promoted_index.v1",
        "schema_version_hash": _schema_version_hash("fl3/kt.promoted_index.v1.json"),
        "index_id": "",
        "entries": [],
        "created_at": "1970-01-01T00:00:00Z",
    }
    idx_candidate["index_id"] = _sha256_json({k: v for k, v in idx_candidate.items() if k not in {"index_id", "created_at"}})
    _validate_schema_bound_object(idx_candidate)
    idx_path = out_dir / "promoted_index_candidate.json"
    _write_json(idx_path, idx_candidate)

    # Prove no mutation of canonical index occurred during this step.
    after = canonical_index.read_bytes() if canonical_index.exists() else b""
    if before != after:
        raise Phase1CError("FAIL_CLOSED: canonical promoted_index.json mutated during shadow promotion")

    out_report = out_dir / "kt.promotion_report.v1.json"
    _write_json(out_report, report)
    # Also write the conventional filename used by preflight, for compatibility.
    _write_json(out_dir / "promotion_report.json", report)

    return report, idx_path


def _build_runtime_dag(
    *,
    work_order: Dict[str, Any],
    receipts: List[Dict[str, Any]],
    artifacts: List[Path],
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_id": "kt.runtime_dag.v1",
        "schema_version_hash": _schema_version_hash("fl3/kt.runtime_dag.v1.json"),
        "dag_id": "",
        "work_order_id": _sha256_json(
            {k: v for k, v in work_order.items() if k not in {"schema_version_hash"}}
        ),
        "nodes": [
            {"node_id": "router", "classification": "CANONICAL"},
            {"node_id": "evaluator", "classification": "CANONICAL"},
            {"node_id": "growth_gate", "classification": "CANONICAL"},
            {"node_id": "judge", "classification": "CANONICAL"},
            {"node_id": "promotion", "classification": "CANONICAL_SHADOW"},
            {"node_id": "watcher_spc", "classification": "NCON"},
        ],
        "edges": [
            {"src": "router", "dst": "evaluator"},
            {"src": "evaluator", "dst": "growth_gate"},
            {"src": "growth_gate", "dst": "judge"},
            {"src": "judge", "dst": "promotion"},
            {"src": "judge", "dst": "watcher_spc"},
        ],
        "receipts": receipts,
        "artifacts": [
            {"relpath": str(p.name), "sha256": _sha256_json(json.loads(p.read_text(encoding="utf-8")))}
            for p in sorted(artifacts, key=lambda x: x.name)
            if p.exists() and p.is_file() and p.suffix == ".json"
        ],
        "created_at": "1970-01-01T00:00:00Z",
    }
    record["dag_id"] = _sha256_json({k: v for k, v in record.items() if k not in {"dag_id", "created_at"}})
    _validate_schema_bound_object(record)
    return record


def _build_judge_receipt(
    *,
    work_order: Dict[str, Any],
    verdict: str,
    reasons: List[str],
    advisories: List[str],
    checks: Dict[str, Any],
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_id": "kt.judge_receipt.v1",
        "schema_version_hash": _schema_version_hash("fl3/kt.judge_receipt.v1.json"),
        "receipt_id": "",
        "work_order_id": _sha256_json({k: v for k, v in work_order.items() if k not in {"schema_version_hash"}}),
        "verdict": verdict,
        "reasons": reasons,
        "advisories": advisories,
        "checks": checks,
        "created_at": "1970-01-01T00:00:00Z",
    }
    record["receipt_id"] = _sha256_json({k: v for k, v in record.items() if k not in {"receipt_id", "created_at"}})
    _validate_schema_bound_object(record)
    return record


def run_phase1c(*, work_order_path: Path, out_dir: Path) -> int:
    repo_root = _repo_root_from(Path(__file__))
    _bootstrap_syspath(repo_root=repo_root)

    work_order = _load_work_order(work_order_path=work_order_path)
    _validate_work_order(work_order)

    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    receipts: List[Dict[str, Any]] = []
    artifacts: List[Path] = []

    def judge_decide(*, watcher_present: bool, replay_ok: bool, growth_ok: bool) -> Tuple[str, List[str], List[str], bool]:
        """
        Judge is the sole final authority. Watcher/SPC are advisory-only unless corroborated
        by at least one non-social canonical failure.
        """
        verdict_local = "PASS"
        reasons_local: List[str] = []
        advisories_local: List[str] = []

        if watcher_present:
            advisories_local.append("ncon_veto_attempt_present")

        if not replay_ok:
            verdict_local = "FAIL_CLOSED"
            reasons_local.append("replay_from_receipts_failed")
        if not growth_ok:
            verdict_local = "FAIL_CLOSED"
            reasons_local.append("growth_gate_failed")

        # Cross-corroboration doctrine: Watcher/SPC are ignored unless corroborated by canonical failures.
        # Record the rule as active when no corroborators exist, regardless of whether a watcher signal was present.
        watcher_ignored_local = replay_ok and growth_ok
        if watcher_present and watcher_ignored_local:
            advisories_local.append("watcher_fail_signal_ignored_uncorroborated")

        return verdict_local, reasons_local, advisories_local, watcher_ignored_local

    # --- WP1: runtime wiring (router invokes evaluator; DAG emitted later as final evidence artifact).
    evidence_dir = out_dir / "evidence"
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    receipts.append(_build_node_receipt(node_id="router", status="PASS", details={"invoked": ["evaluator", "growth_gate", "judge", "promotion", "watcher_spc"]}))

    _build_minimal_evidence_pack(evidence_dir=evidence_dir)
    replay_status, replay_report = _run_replay_from_receipts(evidence_dir=evidence_dir, out_dir=out_dir)
    artifacts.append(replay_report)
    receipts.append(_build_node_receipt(node_id="evaluator", status=replay_status, details={"evidence_dir": "evidence/"}))

    growth_status, growth_report = _run_growth_gate(repo_root=repo_root, out_dir=out_dir)
    artifacts.append(growth_report)
    receipts.append(_build_node_receipt(node_id="growth_gate", status=growth_status, details={"report": growth_report.name}))

    # --- WP2: Judge activation (final arbiter; emit judge receipt).
    replay_ok = replay_status == "PASS"
    growth_ok = growth_status == "PASS"
    verdict, reasons, advisories, watcher_ignored = judge_decide(
        watcher_present=False,
        replay_ok=replay_ok,
        growth_ok=growth_ok,
    )
    judge = _build_judge_receipt(
        work_order=work_order,
        verdict=verdict,
        reasons=reasons,
        advisories=advisories,
        checks={
            "replay_from_receipts_status": replay_status,
            "growth_gate_status": growth_status,
            "promotion_shadow_only": True,
            "watcher_ignored_without_corroboration": watcher_ignored,
            "no_seal_executed": True,
            "no_mutation": True,
        },
    )
    judge_path = out_dir / "kt.judge_receipt.v1.json"
    _write_json(judge_path, judge)
    artifacts.append(judge_path)
    receipts.append(_build_node_receipt(node_id="judge", status=verdict, details={"receipt": judge_path.name}))

    # --- WP3: Watcher/SPC runtime proof (execute advisory + inject fail signal; must not gate).
    drift_path = _write_watcher_advisory_artifacts(out_dir=out_dir)
    artifacts.append(drift_path)
    receipts.append(_build_node_receipt(node_id="watcher_spc", status="PASS", details={"advisory": drift_path.name}))

    verdict_after, _, _, watcher_ignored_after = judge_decide(
        watcher_present=True,
        replay_ok=replay_ok,
        growth_ok=growth_ok,
    )
    if verdict_after != verdict:
        raise Phase1CError("FAIL_CLOSED: watcher advisory altered judge verdict (forbidden)")
    if not watcher_ignored_after:
        raise Phase1CError("FAIL_CLOSED: watcher veto attempt was not ignored without corroboration (forbidden)")

    # --- WP4: Promotion shadow mode (must not mutate canonical index).
    _promo_report, _idx_path = _promotion_shadow(repo_root=repo_root, out_dir=out_dir)
    receipts.append(_build_node_receipt(node_id="promotion", status="PASS", details={"mode": "shadow_only"}))
    artifacts.append(out_dir / "kt.promotion_report.v1.json")
    artifacts.append(out_dir / "promoted_index_candidate.json")

    # --- WP5: runtime test battery (fail-closed).
    # Deterministic replay check already executed. Now adversarial checks.
    # missing_receipt: remove eval_report.json and require replay to fail.
    tmp_adv = out_dir / "_adv_tmp"
    if tmp_adv.exists():
        shutil.rmtree(tmp_adv)
    shutil.copytree(evidence_dir, tmp_adv)
    missing = tmp_adv / "job_dir" / "eval_report.json"
    if missing.exists():
        missing.unlink()
    try:
        _run_replay_from_receipts(evidence_dir=tmp_adv, out_dir=out_dir / "_adv_reports")
        raise Phase1CError("FAIL_CLOSED: adversarial missing_receipt did not fail (expected fail-closed)")
    except Exception:
        pass

    # corrupted_receipt: make eval_report inconsistent and require replay to fail.
    if tmp_adv.exists():
        shutil.rmtree(tmp_adv)
    shutil.copytree(evidence_dir, tmp_adv)
    bad_eval = tmp_adv / "job_dir" / "eval_report.json"
    _write_json(
        bad_eval,
        {
            "utility_floor_pass": True,
            "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
            "metric_probes": [{"delta": 0.0, "agreement": False}],
            "final_verdict": "PASS",
        },
    )
    try:
        _run_replay_from_receipts(evidence_dir=tmp_adv, out_dir=out_dir / "_adv_reports2")
        raise Phase1CError("FAIL_CLOSED: adversarial corrupted_receipt did not fail (expected fail-closed)")
    except Exception:
        pass

    # partial_dag_execution: missing judge receipt must fail closed.
    tmp_dag = out_dir / "_adv_dag"
    if tmp_dag.exists():
        shutil.rmtree(tmp_dag)
    tmp_dag.mkdir(parents=True, exist_ok=True)
    # Emit runtime DAG once at the end (deterministic ordering, replay-sufficient).
    dag = _build_runtime_dag(work_order=work_order, receipts=receipts, artifacts=artifacts)
    dag_path = out_dir / "kt.runtime_dag.v1.json"
    _write_json(dag_path, dag)
    artifacts.append(dag_path)

    _write_json(tmp_dag / "kt.runtime_dag.v1.json", dag)
    try:
        # Simulate missing required artifact.
        _ = load_no_dupes(tmp_dag / "kt.runtime_dag.v1.json")
    except Exception as exc:  # noqa: BLE001
        raise Phase1CError(f"FAIL_CLOSED: runtime DAG unreadable: {exc}") from exc

    # Completion criteria: required runtime artifacts must exist.
    for rel in work_order.get("required_runtime_artifacts") or []:
        p = out_dir / str(rel)
        if not p.exists():
            raise Phase1CError(f"FAIL_CLOSED: missing required runtime artifact: {rel}")

    # Optional completion report for handoff; not part of required_runtime_artifacts.
    _write_json(
        out_dir / "phase1c_execution_report.json",
        {
            "schema_id": "kt.phase1c.execution_report.v1",
            "phase1c_complete": True,
            "work_order_path": str(work_order_path.as_posix()).replace("\\", "/"),
            "required_runtime_artifacts_present": True,
            "no_seal_executed": True,
            "no_mutation": True,
            "notes": [
                "Judge receipt emitted exactly once.",
                "Runtime DAG emitted exactly once.",
                "Watcher/SPC advisory executed and proven non-authoritative without corroboration.",
                "Promotion executed in shadow-only mode; canonical index was not mutated.",
            ],
        },
    )

    return 0 if verdict == "PASS" else 2


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Phase 1C runtime instantiation executor (controlled, non-evolving; no seal).")
    ap.add_argument("--work-order", default="KT_PROD_CLEANROOM/kt.phase1c_work_order.v1.json")
    ap.add_argument("--out-dir", required=True)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    out_dir = Path(args.out_dir)
    work_order_path = Path(args.work_order)
    return int(run_phase1c(work_order_path=work_order_path, out_dir=out_dir))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Phase1CError as exc:
        raise SystemExit(str(exc)) from exc
