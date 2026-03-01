from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.serious_layer.common import (
    Pins,
    canonical_json,
    ensure_empty_dir_worm,
    sha256_obj,
    sha256_text,
    stable_sorted_strs,
    utc_now_iso_z,
    write_json_worm,
    write_jsonl_worm,
)
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


def _parse_pins_json(value: str) -> Pins:
    try:
        obj = json.loads(value)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError("FAIL_CLOSED: --pins-json must be valid JSON") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError("FAIL_CLOSED: --pins-json must be a JSON object")

    def s(k: str) -> str:
        v = obj.get(k)
        if not isinstance(v, str) or not v.strip():
            raise FL3ValidationError(f"FAIL_CLOSED: --pins-json missing/invalid {k}")
        return v.strip()

    return Pins(
        sealed_tag=s("sealed_tag"),
        sealed_commit=s("sealed_commit"),
        law_bundle_hash=s("law_bundle_hash"),
        suite_registry_id=s("suite_registry_id"),
        determinism_expected_root_hash=s("determinism_expected_root_hash"),
        head_git_sha=s("head_git_sha"),
    )


def _load_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return obj if isinstance(obj, dict) else None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _classify_run_status(*, run_dir: Path) -> str:
    err = (run_dir / "error.txt").resolve()
    if err.exists():
        return "FAIL_CLOSED"
    v = (run_dir / "verdict.txt").resolve()
    if not v.exists():
        return "UNKNOWN"
    t = _read_text(v).upper()
    if "_PASS" in t and "FAIL_CLOSED" not in t:
        return "PASS"
    if "_HOLD" in t:
        return "HOLD"
    if "_BLOCKED" in t:
        return "BLOCKED"
    return "UNKNOWN"


@dataclass(frozen=True)
class RunFacts:
    run_dir: str
    status: str
    verdict: str
    lane: str
    lane_id: str
    pins: Dict[str, Any]
    bundle_root_hash: str
    gpis: int
    gpis_reasons: List[str]


def _compute_gpis(*, run_dir: Path) -> Tuple[int, List[str]]:
    """
    Governance Proof Integrity Score (GPIS): evidence integrity of the bundle.
    Deterministic and explainable: score + reasons.
    """
    score = 100
    reasons: List[str] = []

    verdict_path = (run_dir / "verdict.txt").resolve()
    if not verdict_path.exists():
        score -= 30
        reasons.append("missing_verdict")

    secret_path = (run_dir / "evidence" / "secret_scan_report.json").resolve()
    secret = _load_optional_json(secret_path) or {}
    secret_status = str(secret.get("status", "")).strip().upper() if secret_path.exists() else "MISSING"
    if secret_status != "PASS":
        score -= 25
        reasons.append(f"secret_scan_{secret_status.lower()}")

    lint_path = (run_dir / "delivery" / "delivery_lint_report.json").resolve()
    lint = _load_optional_json(lint_path) or {}
    lint_status = str(lint.get("status", "")).strip().upper() if lint_path.exists() else "MISSING"
    if lint_status != "PASS":
        score -= 15
        reasons.append(f"delivery_lint_{lint_status.lower()}")

    dm_path = (run_dir / "delivery" / "delivery_manifest.json").resolve()
    if not dm_path.exists():
        score -= 10
        reasons.append("missing_delivery_manifest")
    else:
        dm = _load_optional_json(dm_path) or {}
        if not isinstance(dm.get("pins"), dict):
            score -= 5
            reasons.append("delivery_manifest_missing_pins")

    # Replay wrappers and sha256 receipt (client verification).
    replay_sh = (run_dir / "evidence" / "replay.sh").resolve()
    replay_ps1 = (run_dir / "evidence" / "replay.ps1").resolve()
    if not replay_sh.exists() or not replay_ps1.exists():
        score -= 10
        reasons.append("missing_replay_wrappers")

    hashes_dir = (run_dir / "hashes").resolve()
    if not hashes_dir.exists():
        score -= 5
        reasons.append("missing_hashes_dir")

    score = max(0, min(100, int(score)))
    reasons = stable_sorted_strs(reasons)
    return score, reasons


def _facts(*, run_dir: Path) -> RunFacts:
    dm = _load_optional_json((run_dir / "delivery" / "delivery_manifest.json").resolve()) or {}
    rp = _load_optional_json((run_dir / "evidence" / "run_protocol.json").resolve()) or {}
    status = _classify_run_status(run_dir=run_dir)
    gpis, reasons = _compute_gpis(run_dir=run_dir)
    return RunFacts(
        run_dir=run_dir.as_posix(),
        status=status,
        verdict=_read_text((run_dir / "verdict.txt").resolve()) if (run_dir / "verdict.txt").exists() else "",
        pins=dm.get("pins", {}) if isinstance(dm.get("pins"), dict) else {},
        lane=str(dm.get("lane", "")).strip(),
        lane_id=str(rp.get("lane_id", "")).strip(),
        bundle_root_hash=str(rp.get("bundle_root_hash", "")).strip(),
        gpis=int(gpis),
        gpis_reasons=list(reasons),
    )


def _resolve_existing_run_dir(*, repo_root: Path, value: str) -> Path:
    target = Path(str(value)).expanduser()
    if not target.is_absolute():
        target = (repo_root / target).resolve()
    runs_root = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()
    try:
        target.relative_to(runs_root)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError("FAIL_CLOSED: baseline/window runs must be under KT_PROD_CLEANROOM/exports/_runs") from exc
    if not target.exists() or not target.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: run dir does not exist: {target.as_posix()}")
    return target


def _window_runs(*, repo_root: Path, baseline: Path, window: str) -> List[Path]:
    runs_root = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_OPERATOR").resolve()
    candidates: List[Path] = []
    if runs_root.exists():
        for p in sorted(runs_root.iterdir(), reverse=True):
            if p.is_dir():
                candidates.append(p.resolve())

    w = str(window).strip()
    if not w:
        runs = [baseline]
    elif w.isdigit():
        n = int(w)
        if n <= 0:
            raise FL3ValidationError("FAIL_CLOSED: --window N must be > 0")
        runs = candidates[:n]
        if baseline not in runs:
            runs.append(baseline)
    else:
        items = [x.strip() for x in w.replace(";", ",").split(",") if x.strip()]
        if not items:
            raise FL3ValidationError("FAIL_CLOSED: --window list is empty")
        runs = [_resolve_existing_run_dir(repo_root=repo_root, value=x) for x in items]
        if baseline not in runs:
            runs.append(baseline)

    # Deduplicate
    out: List[Path] = []
    seen: set[str] = set()
    for p in runs:
        key = p.as_posix()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _compute_dri(*, baseline: RunFacts, current: RunFacts) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Drift Risk Index: 0..100, higher is worse.
    Deterministic and explainable with drift signals.
    """
    signals: List[Dict[str, Any]] = []
    score = 0

    if current.status != "PASS":
        score += 30
        signals.append({"signal": "status_not_pass", "baseline": baseline.status, "current": current.status})

    pin_fields = ("sealed_commit", "law_bundle_hash", "suite_registry_id", "determinism_expected_root_hash")
    for k in pin_fields:
        b = str((baseline.pins or {}).get(k, "")).strip()
        c = str((current.pins or {}).get(k, "")).strip()
        if b and c and b != c:
            score += 20
            signals.append({"signal": "pin_delta", "field": k, "baseline": b, "current": c})

    if baseline.bundle_root_hash and current.bundle_root_hash and baseline.bundle_root_hash != current.bundle_root_hash:
        score += 10
        signals.append({"signal": "bundle_root_hash_changed", "baseline": baseline.bundle_root_hash, "current": current.bundle_root_hash})

    # GPIS degradation indicates evidence integrity drift.
    if current.gpis < baseline.gpis:
        delta = baseline.gpis - current.gpis
        add = 10 if delta >= 10 else 5
        score += add
        signals.append({"signal": "gpis_drop", "baseline": baseline.gpis, "current": current.gpis, "delta": delta})

    score = max(0, min(100, int(score)))
    signals = sorted(signals, key=lambda s: (str(s.get("signal", "")), str(s.get("field", ""))))
    return score, signals


def run_continuous_gov_serious(
    *,
    repo_root: Path,
    out_dir: Path,
    pins: Pins,
    baseline_run: str,
    window: str,
    thresholds_json: str,
) -> Dict[str, Any]:
    ensure_empty_dir_worm(out_dir, label="continuous_gov_serious_v1")

    baseline = _resolve_existing_run_dir(repo_root=repo_root, value=baseline_run)
    base_facts = _facts(run_dir=baseline)
    runs = _window_runs(repo_root=repo_root, baseline=baseline, window=window)
    compared = [r for r in runs if r != baseline]
    compared_facts = [_facts(run_dir=r) for r in compared]

    thresholds: Dict[str, Any] = {}
    if str(thresholds_json).strip():
        try:
            thresholds_obj = json.loads(str(thresholds_json))
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError("FAIL_CLOSED: --thresholds must be valid JSON") from exc
        if not isinstance(thresholds_obj, dict):
            raise FL3ValidationError("FAIL_CLOSED: --thresholds must be a JSON object")
        thresholds = thresholds_obj

    gpis_block_min = int(thresholds.get("gpis_block_min", 95)) if isinstance(thresholds.get("gpis_block_min", 95), int) else 95
    dri_advisory_min = int(thresholds.get("dri_advisory_min", 30)) if isinstance(thresholds.get("dri_advisory_min", 30), int) else 30
    dri_block_min = int(thresholds.get("dri_block_min", 60)) if isinstance(thresholds.get("dri_block_min", 60), int) else 60

    # Baseline snapshot
    baseline_snapshot: Dict[str, Any] = {
        "schema_id": "kt.operator.serious_layer.governance.baseline_snapshot.unbound.v1",
        "created_utc": utc_now_iso_z(),
        "snapshot_id": "",
        "run_dir": base_facts.run_dir,
        "lane": base_facts.lane,
        "lane_id": base_facts.lane_id,
        "status": base_facts.status,
        "bundle_root_hash": base_facts.bundle_root_hash,
        "gpis": base_facts.gpis,
        "gpis_reasons": base_facts.gpis_reasons,
        "pins": dict(base_facts.pins),
        "pack_and_overlay_hashes": {},
        "environment_fingerprint": {"determinism_expected_root_hash": pins.determinism_expected_root_hash},
        "notes": "Baseline snapshot is an immutable reference to a prior operator run bundle.",
    }
    baseline_snapshot["snapshot_id"] = sha256_obj(
        {k: v for k, v in baseline_snapshot.items() if k not in {"created_utc", "snapshot_id"}}
    )
    write_json_worm(path=out_dir / "baseline_snapshot.json", obj=baseline_snapshot, label="baseline_snapshot.json")

    # Drift rows and regression triggers
    drift_rows: List[Dict[str, Any]] = []
    advisories: List[str] = []
    blocks: List[str] = []
    for cf in compared_facts:
        dri, signals = _compute_dri(baseline=base_facts, current=cf)
        if cf.gpis < gpis_block_min:
            blocks.append(f"GPIS_BELOW_MIN run={cf.run_dir} gpis={cf.gpis} min={gpis_block_min}")
        if dri >= dri_block_min:
            blocks.append(f"DRI_BLOCK run={cf.run_dir} dri={dri} min={dri_block_min}")
        if dri >= dri_advisory_min:
            advisories.append(f"DRI_ADVISORY run={cf.run_dir} dri={dri} min={dri_advisory_min}")

        drift_rows.append(
            {
                "run_dir": cf.run_dir,
                "status": cf.status,
                "lane": cf.lane,
                "lane_id": cf.lane_id,
                "pins": cf.pins,
                "bundle_root_hash": cf.bundle_root_hash,
                "gpis": cf.gpis,
                "gpis_reasons": cf.gpis_reasons,
                "dri": int(dri),
                "drift_signals": signals,
                "css": None,
                "cri": None,
            }
        )

    drift_rows = sorted(drift_rows, key=lambda r: (str(r.get("run_dir", ""))))
    worst_dri = max([int(r.get("dri", 0)) for r in drift_rows], default=0)
    min_gpis = min([int(r.get("gpis", 100)) for r in drift_rows], default=100)

    drift_report: Dict[str, Any] = {
        "schema_id": "kt.operator.serious_layer.governance.drift_report.unbound.v1",
        "created_utc": utc_now_iso_z(),
        "drift_report_id": "",
        "baseline_snapshot_id": baseline_snapshot["snapshot_id"],
        "baseline_run_dir": base_facts.run_dir,
        "window": str(window).strip(),
        "runs": drift_rows,
        "metrics": {
            "worst_dri": int(worst_dri),
            "min_gpis": int(min_gpis),
            "gpis_block_min": int(gpis_block_min),
            "dri_advisory_min": int(dri_advisory_min),
            "dri_block_min": int(dri_block_min),
        },
        "alerts": stable_sorted_strs(blocks + advisories),
        "advisory_required": bool(any("ADVISORY" in a for a in advisories)) or bool(worst_dri >= dri_advisory_min),
        "block_required": bool(blocks) or bool(worst_dri >= dri_block_min) or bool(min_gpis < gpis_block_min),
        "pins": pins.as_dict(),
        "notes": "CSS/CRI are declared but require model-plane probes; they are null in v1 serious layer unless provided by upstream artifacts.",
    }
    drift_report["drift_report_id"] = sha256_obj({k: v for k, v in drift_report.items() if k not in {"created_utc", "drift_report_id"}})
    write_json_worm(path=out_dir / "drift_report.json", obj=drift_report, label="drift_report.json")

    regression_gate: Dict[str, Any] = {
        "schema_id": "kt.operator.serious_layer.governance.regression_gate.unbound.v1",
        "created_utc": utc_now_iso_z(),
        "gate_id": "",
        "baseline_snapshot_id": baseline_snapshot["snapshot_id"],
        "window": str(window).strip(),
        "block_triggers": stable_sorted_strs(blocks),
        "status": "BLOCK" if bool(blocks) else "PASS",
        "required_actions": stable_sorted_strs(
            [
                "Investigate evidence integrity failures (secret scan / delivery lint / replay wrappers).",
                "Re-run affected lanes in clean mode after remediation.",
            ]
            if blocks
            else []
        ),
        "pins": pins.as_dict(),
    }
    regression_gate["gate_id"] = sha256_obj({k: v for k, v in regression_gate.items() if k not in {"created_utc", "gate_id"}})
    write_json_worm(path=out_dir / "regression_gate.json", obj=regression_gate, label="regression_gate.json")

    # Keep legacy names for compatibility with SKU_CG contract.
    regression_report = {
        "schema_id": "kt.operator.continuous_gov.regression_report.unbound.v1",
        "baseline_run_dir": base_facts.run_dir,
        "regressions": [{"kind": "SERIOUS_LAYER_BLOCK", "run_dir": b.split(" run=")[-1].split(" ")[0], "details": b} for b in blocks],
        "regression_count": int(len(blocks)),
        "created_utc": utc_now_iso_z(),
    }
    write_json_worm(path=out_dir / "regression_report.json", obj=regression_report, label="regression_report.json")

    trend = {
        "schema_id": "kt.operator.continuous_gov.trend_snapshot.unbound.v1",
        "baseline_run_dir": base_facts.run_dir,
        "runs": [base_facts.__dict__] + [cf.__dict__ for cf in compared_facts],
        "counts": {
            "PASS": int(sum(1 for r in [base_facts] + compared_facts if r.status == "PASS")),
            "HOLD": int(sum(1 for r in [base_facts] + compared_facts if r.status == "HOLD")),
            "BLOCKED": int(sum(1 for r in [base_facts] + compared_facts if r.status == "BLOCKED")),
            "FAIL_CLOSED": int(sum(1 for r in [base_facts] + compared_facts if r.status == "FAIL_CLOSED")),
            "UNKNOWN": int(sum(1 for r in [base_facts] + compared_facts if r.status == "UNKNOWN")),
        },
        "created_utc": utc_now_iso_z(),
    }
    write_json_worm(path=out_dir / "trend_snapshot.json", obj=trend, label="trend_snapshot.json")

    md_lines: List[str] = []
    md_lines.append("# KT Continuous Governance Diff Summary (Serious Layer v1)")
    md_lines.append("")
    md_lines.append(f"- baseline_run: `{base_facts.run_dir}`")
    md_lines.append(f"- window: `{str(window).strip() or '<baseline_only>'}`")
    md_lines.append(f"- worst_dri: `{worst_dri}` min_gpis: `{min_gpis}`")
    md_lines.append(f"- regression_gate: `{regression_gate['status']}` triggers: `{len(blocks)}`")
    if blocks:
        md_lines.append("")
        md_lines.append("## Block triggers")
        for b in blocks:
            md_lines.append(f"- {b}")
    write_text_worm(path=out_dir / "diff_summary.md", text="\n".join(md_lines) + "\n", label="diff_summary.md")

    # Governance ledger entry (append-only JSONL).
    ledger_entry = {
        "schema_id": "kt.operator.serious_layer.governance.ledger_entry.unbound.v1",
        "created_utc": utc_now_iso_z(),
        "entry_id": "",
        "event_type": "CONTINUOUS_GOV_DIFF",
        "linked_runs": stable_sorted_strs([base_facts.run_dir] + [cf.run_dir for cf in compared_facts]),
        "observed_metric_deltas": {"worst_dri": int(worst_dri), "min_gpis": int(min_gpis)},
        "linked_receipts": [],
        "pins": pins.as_dict(),
    }
    ledger_entry["entry_id"] = sha256_obj({k: v for k, v in ledger_entry.items() if k not in {"created_utc", "entry_id"}})
    write_jsonl_worm(path=out_dir / "governance_ledger.jsonl", rows=[ledger_entry], label="governance_ledger.jsonl")

    advisory: Optional[Dict[str, Any]] = None
    if drift_report.get("advisory_required"):
        advisory = {
            "schema_id": "kt.operator.serious_layer.governance.advisory.unbound.v1",
            "created_utc": utc_now_iso_z(),
            "advisory_id": "",
            "severity": "HIGH" if drift_report.get("block_required") else "MEDIUM",
            "summary": "Governance drift advisory: evidence integrity and/or pins changed in the monitoring window.",
            "what_changed": drift_report.get("alerts", []),
            "risk_assessment": "Drift increases audit and operational risk. Investigate and remediate before promotion or external delivery.",
            "recommended_actions": regression_gate.get("required_actions", []),
            "pins": pins.as_dict(),
        }
        advisory["advisory_id"] = sha256_obj({k: v for k, v in advisory.items() if k not in {"created_utc", "advisory_id"}})
        write_json_worm(path=out_dir / "advisory.json", obj=advisory, label="advisory.json")

    verdict = "PASS" if regression_gate.get("status") == "PASS" else "HOLD"
    return {
        "status": verdict,
        "baseline_snapshot_id": baseline_snapshot["snapshot_id"],
        "drift_report_id": drift_report["drift_report_id"],
        "regression_gate_id": regression_gate["gate_id"],
        "out_dir": out_dir.as_posix(),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT Serious Layer Continuous Governance program (v1; operator-local; fail-closed).")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--pins-json", required=True)
    ap.add_argument("--baseline-run", required=True)
    ap.add_argument("--window", default="")
    ap.add_argument("--thresholds", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve()
    for parent in [repo_root] + list(repo_root.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            repo_root = parent
            break
    else:
        raise SystemExit("FAIL_CLOSED: unable to locate repo root")

    out_dir = Path(args.out_dir).resolve()
    pins = _parse_pins_json(str(args.pins_json))
    res = run_continuous_gov_serious(
        repo_root=repo_root,
        out_dir=out_dir,
        pins=pins,
        baseline_run=str(args.baseline_run),
        window=str(args.window),
        thresholds_json=str(args.thresholds),
    )
    print(canonical_json(res))
    return 0 if res.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

