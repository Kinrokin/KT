"""
Compute advisory-only regret metrics per epoch (offline, fail-closed).

Writes KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/<epoch_id>/epoch_regret.json
based solely on real evidence (micro_steps + epoch_summary). No stubs, no routing/gov changes.
"""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class RegretComputeError(RuntimeError):
    pass


LANE_COVERAGE = "coverage_lane"
LANE_REANCHOR = "reanchor_lane"
LANE_STABILIZE = "stabilize_lane"


@dataclass(frozen=True)
class EpochEvidence:
    root: Path
    epoch_id: str
    lane_actual: str
    forced_any: bool
    low_any: bool
    constraint_any: bool
    resolve_not_clean_any: bool
    eval_low_any: bool
    debt_delta: Optional[int]
    debt_present: bool
    evidence_complete: bool


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegretComputeError(f"Missing required input: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise RegretComputeError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _read_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return _load_json(path)


def _lane_from_epoch_id(epoch_id: str) -> str:
    e = (epoch_id or "").upper()
    if e.startswith("EPOCH_REANCHOR_CONSTRAINT"):
        return LANE_REANCHOR
    if e.startswith("EPOCH_STABILIZE"):
        return LANE_STABILIZE
    if e.startswith("EPOCH_NEXT_AUTO") or e.startswith("EPOCH_COVERAGE") or e.startswith("EPOCH_ACCEPTANCE") or e.startswith("EPOCH_PASS"):
        return LANE_COVERAGE
    raise RegretComputeError(f"Unknown epoch_id lane prefix: {epoch_id} (fail-closed)")


def _collect_micro_steps(epoch_root: Path) -> Optional[List[Dict[str, Any]]]:
    steps: List[Dict[str, Any]] = []
    for path in sorted(epoch_root.glob("CRU_*/micro_steps.json"), key=lambda p: p.name):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        chunk = payload.get("steps") if isinstance(payload, dict) else payload
        if isinstance(chunk, list):
            steps.extend([e for e in chunk if isinstance(e, dict)])
    if steps:
        return steps
    root_micro = _read_optional_json(epoch_root / "micro_steps.json")
    if isinstance(root_micro, dict):
        chunk = root_micro.get("steps")
        if isinstance(chunk, list):
            return [e for e in chunk if isinstance(e, dict)]
    return None


def _count_flags(steps: Optional[List[Dict[str, Any]]]) -> Tuple[bool, bool, bool, bool, bool]:
    if not steps:
        return (False, False, False, False, False)
    forced = False
    low = False
    constraint = False
    resolve_nc = False
    eval_low = False
    for s in steps:
        flags = s.get("flags") or {}
        phase = s.get("phase") or s.get("step") or s.get("name")
        mode = flags.get("resolve_mode")
        coh = flags.get("coherence_bucket")
        ch = flags.get("constraint_hit")
        if isinstance(mode, str):
            ml = mode.strip().lower()
            if ml in {"forced", "partial", "unresolved", "refuse"}:
                forced = True
            if ml != "clean":
                resolve_nc = True
        if isinstance(coh, str) and coh.strip().upper() == "LOW":
            low = True
            if phase == "EVAL":
                eval_low = True
        if ch and ch != "none":
            if ch in {"policy", "contract"}:
                constraint = True
            elif ch == "budget":
                verdict = flags.get("budget_verdict")
                if isinstance(verdict, str) and verdict.strip().upper() != "WITHIN_BUDGET":
                    constraint = True
                else:
                    # budget within budget is not a hit for regret purposes
                    pass
    return (forced, low, constraint, resolve_nc, eval_low)


def _extract_evidence(epoch_root: Path) -> EpochEvidence:
    summary = _load_json(epoch_root / "epoch_summary.json")
    micro = _collect_micro_steps(epoch_root)
    epoch_id = str(summary.get("epoch_id") or epoch_root.name)
    lane_actual = _lane_from_epoch_id(epoch_id)

    coherence_debt = summary.get("coherence_debt")
    coherence_debt_delta = summary.get("coherence_debt_delta")
    debt_present = coherence_debt is not None
    debt_delta = None
    try:
        debt_delta = int(coherence_debt_delta) if coherence_debt_delta is not None else None
    except Exception:
        debt_delta = None

    if micro is None:
        return EpochEvidence(
            root=epoch_root,
            epoch_id=epoch_id,
            lane_actual=lane_actual,
            forced_any=False,
            low_any=False,
            constraint_any=False,
            resolve_not_clean_any=False,
            eval_low_any=False,
            debt_delta=debt_delta,
            debt_present=debt_present,
            evidence_complete=False,
        )

    forced, low, constraint, resolve_nc, eval_low = _count_flags(micro)
    return EpochEvidence(
        root=epoch_root,
        epoch_id=epoch_id,
        lane_actual=lane_actual,
        forced_any=forced,
        low_any=low,
        constraint_any=constraint,
        resolve_not_clean_any=resolve_nc,
        eval_low_any=eval_low,
        debt_delta=debt_delta,
        debt_present=debt_present,
        evidence_complete=True,
    )


def _score(e: EpochEvidence) -> float:
    score = 1.0
    if e.forced_any:
        score -= 0.4
    if e.low_any:
        score -= 0.3
    if e.constraint_any:
        score -= 0.2
    if e.resolve_not_clean_any:
        score -= 0.3
    if e.eval_low_any:
        score -= 0.2
    if e.debt_delta is not None:
        if e.debt_delta > 0:
            score -= 0.2
        elif e.debt_delta < 0:
            score += 0.1
    return max(0.0, min(score, 1.0))


def _discover_epochs(epochs_dir: Path) -> List[Path]:
    if not epochs_dir.exists():
        raise RegretComputeError(f"epochs dir missing: {epochs_dir.as_posix()} (fail-closed)")
    roots = [p for p in epochs_dir.iterdir() if p.is_dir()]
    if not roots:
        raise RegretComputeError(f"epochs dir empty: {epochs_dir.as_posix()} (fail-closed)")
    return roots


def _mtime_key(path: Path) -> Tuple[float, str]:
    return (path.stat().st_mtime, path.name)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compute advisory regret per epoch (offline; fail-closed).")
    p.add_argument(
        "--epochs-dir",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/epochs"),
        help="Epoch artifacts root.",
    )
    p.add_argument(
        "--history",
        type=int,
        default=None,
        help="Only consider most recent N epochs (mtime desc). Default: all.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    roots = _discover_epochs(args.epochs_dir)
    roots = sorted(set(roots), key=_mtime_key)  # chronological
    if args.history:
        roots = roots[-int(args.history) :]

    lane_scores: Dict[str, List[float]] = {}
    wrote = 0
    for root in roots:
        try:
            ev = _extract_evidence(root)
        except RegretComputeError as exc:
            print(str(exc))
            continue

        if not ev.evidence_complete:
            payload = {
                "schema": "KT_EPOCH_REGRET_V1",
                "epoch_id": ev.epoch_id,
                "lane_actual": ev.lane_actual,
                "regret_global": None,
                "regret_skip_reason": "missing_micro_steps",
            }
            (root / "epoch_regret.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            continue

        actual = _score(ev)
        scores_for_lane = lane_scores.get(ev.lane_actual, [])
        scores_for_lane.append(actual)
        lane_scores[ev.lane_actual] = scores_for_lane

        # Counterfactual best from history across all lanes that have at least one score.
        historical_best = None
        for lst in lane_scores.values():
            if lst:
                best = max(lst)
                historical_best = best if historical_best is None else max(historical_best, best)

        if historical_best is None:
            payload = {
                "schema": "KT_EPOCH_REGRET_V1",
                "epoch_id": ev.epoch_id,
                "lane_actual": ev.lane_actual,
                "actual_score": actual,
                "regret_global": None,
                "regret_skip_reason": "insufficient_history",
            }
        else:
            regret = max(historical_best - actual, 0.0)
            payload = {
                "schema": "KT_EPOCH_REGRET_V1",
                "epoch_id": ev.epoch_id,
                "lane_actual": ev.lane_actual,
                "actual_score": round(actual, 4),
                "counterfactual_best": round(historical_best, 4),
                "regret_global": round(regret, 4),
                "evidence": {
                    "forced_any": ev.forced_any,
                    "low_any": ev.low_any,
                    "constraint_any": ev.constraint_any,
                    "resolve_not_clean_any": ev.resolve_not_clean_any,
                    "eval_low_any": ev.eval_low_any,
                    "debt_delta": ev.debt_delta,
                    "debt_present": ev.debt_present,
                },
            }

        (root / "epoch_regret.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        wrote += 1

    print(json.dumps({"epochs_processed": len(roots), "regret_written": wrote}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RegretComputeError as exc:
        print(str(exc))
        raise SystemExit(2)
