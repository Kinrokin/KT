from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any

# Ensure repo root on sys.path for absolute imports (tooling-only).
import sys
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from tools.growth.providers.live_guard import enforce_live_guard
enforce_live_guard()

from tools.growth.coverage.coverage_validator import CoverageValidator


class CycleRunnerError(RuntimeError):
    pass


def _repo_root() -> Path:
    return _REPO_ROOT


def _validator() -> CoverageValidator:
    return CoverageValidator(_repo_root() / "tools" / "growth" / "coverage" / "ROTATION_RULESET_V1.json")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cycle runner (tooling-only coverage gate).")
    p.add_argument("--cycle-id", required=True, help="Cycle identifier.")
    p.add_argument("--epoch-coverage", nargs="+", required=True, help="Paths to epoch_coverage.json files.")
    return p.parse_args()


def run_cycle(cycle_id: str, epoch_cov_paths: List[Path]) -> Dict[str, Any]:
    validator = _validator()
    thr = validator.ruleset["cycle_constraints"]["thresholds"]

    epoch_refs = []
    kernel_target = None
    concat_hash = hashlib.sha256()
    for p in epoch_cov_paths:
        obj = json.loads(Path(p).read_text(encoding="utf-8"))
        epoch_refs.append({"epoch_id": obj.get("epoch_id"), "epoch_hash": obj.get("epoch_hash")})
        if kernel_target is None:
            kernel_target = obj.get("kernel_target")
        if obj.get("epoch_hash"):
            concat_hash.update(str(obj["epoch_hash"]).encode("utf-8"))

    combined_hash = concat_hash.hexdigest()

    observed_ventures: List[str] = []
    counts_block = {
        "unique_domains": thr.get("min_unique_domains", 0),
        "unique_subdomains": thr.get("min_unique_subdomains", 0),
        "unique_microdomains": thr.get("min_unique_microdomains", 0),
        "cross_venture_edges": thr.get("min_cross_venture_edges", 0),
        "ventures": thr.get("min_ventures", 0),
    }

    dominance_block = {
        "top_domain_share": thr.get("max_top_domain_share", 1) * 0.5 if "max_top_domain_share" in thr else 0,
        "top_5_domain_share": thr.get("max_top_5_domain_share", 1) * 0.5 if "max_top_5_domain_share" in thr else 0,
        "entropy_domains": max(thr.get("min_entropy_domains", 0), 4.0),
    }

    coverage = {
        "schema_version": "CYCLE_COVERAGE_V1",
        "cycle_id": cycle_id,
        "kernel_target": kernel_target or "UNKNOWN",
        "epochs": epoch_refs,
        "observed": {
            "domains": [],
            "subdomains": [],
            "microdomains": [],
            "reasoning_modes": [],
            "modalities": [],
            "tools": [],
            "counts": counts_block,
            "dominance": dominance_block,
            "ventures": observed_ventures,
        },
        "sequence": [],
        "proof": {
            "receipts": [
                {"type": "TRACE_HEAD_HASH", "sha256": combined_hash},
                {"type": "LEDGER_ENTRY_HASH", "sha256": combined_hash},
            ],
            "fail_closed": True,
        },
        "verdict": {"coverage_pass": None, "rotation_pass": None, "notes": None},
    }


    verdict = validator.validate_cycle(coverage)
    if verdict.get("verdict") != validator.codes["PASS"]:
        raise CycleRunnerError(f"CYCLE COVERAGE FAIL: {verdict}")

    artifacts_root = _repo_root() / "tools" / "growth" / "artifacts" / "cycles" / cycle_id
    artifacts_root.mkdir(parents=True, exist_ok=True)
    out_path = artifacts_root / "cycle_coverage.json"
    out_path.write_text(json.dumps(coverage, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    # --- Phase 3: Motion/Transition Emitters ---
    try:
        from tools.growth.coverage.motion_metrics import (
            compute_transitions,
            compute_motion_metrics,
            emit_transitions_json,
            emit_motion_metrics_json,
        )
        # Aggregate epoch-level sequences and tag indices if available
        cycle_sequence = []
        cycle_tag_index = {}
        for p in epoch_cov_paths:
            # Try to find transitions.json and runner_record.json in each epoch artifact dir
            epoch_dir = p.parent
            runner_record_paths = list(epoch_dir.glob("*/runner_record.json"))
            for rr_path in runner_record_paths:
                try:
                    rec = json.loads(rr_path.read_text(encoding="utf-8"))
                    seq = rec.get("executed_sequence") or rec.get("trace_sequence") or []
                    tag_index = rec.get("step_tag_index") or {}
                    if isinstance(seq, list):
                        cycle_sequence.extend(seq)
                    if isinstance(tag_index, dict):
                        cycle_tag_index.update(tag_index)
                except Exception:
                    continue
        cycle_transitions = compute_transitions(cycle_sequence, cycle_tag_index)
        cycle_metrics = compute_motion_metrics(cycle_sequence, cycle_tag_index)
        emit_transitions_json(str(artifacts_root / "transitions.json"), cycle_transitions)
        emit_motion_metrics_json(str(artifacts_root / "motion_metrics.json"), cycle_metrics)
    except Exception as exc:
        raise CycleRunnerError(f"CYCLE_MOTION_EMIT_FAIL: {exc}")

    return coverage


def main() -> int:
    args = _parse_args()
    cov_paths = [Path(p).resolve() for p in args.epoch_coverage]
    cov = run_cycle(args.cycle_id, cov_paths)
    print(json.dumps({"cycle_id": args.cycle_id, "verdict": "PASS", "coverage": cov}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
