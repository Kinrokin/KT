from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class PlanSuggestError(RuntimeError):
    pass

try:
    from KT_PROD_CLEANROOM.tools.growth.state.kt_lane_policy import build_default_policy, KTLanePolicy
    from KT_PROD_CLEANROOM.tools.growth.state.cce_state import load_state as load_cce_state, cce_constants
    from KT_PROD_CLEANROOM.tools.growth.state.oce_state import load_state as load_oce_state, oce_constants
    from KT_PROD_CLEANROOM.tools.growth.state.rwrp_state import load_state as load_rwrp_state, rwrp_constants
except ImportError:  # pragma: no cover
    build_default_policy = None  # type: ignore[assignment]
    KTLanePolicy = Any  # type: ignore[assignment]
    load_cce_state = None  # type: ignore[assignment]
    cce_constants = lambda: {"cce_step": None, "cce_max": None, "cce_decay": None}  # type: ignore[assignment]
    load_oce_state = None  # type: ignore[assignment]
    oce_constants = lambda: {"oce_step": None, "oce_max": None, "oce_decay": None}  # type: ignore[assignment]
    load_rwrp_state = None  # type: ignore[assignment]
    rwrp_constants = lambda: {"rwrp_alpha": None, "rwrp_beta": None, "rwrp_max": None}  # type: ignore[assignment]


TriBool = Optional[bool]

DEFAULT_HISTORY = 50

@dataclass(frozen=True)
class EpochSignals:
    root: Path
    epoch_id: str
    epoch_hash: Optional[str]
    epoch_profile: Optional[str]
    epoch_verdict: Optional[str]
    kernel_target: Optional[str]
    coherence_debt: Optional[int]
    coherence_budget: Optional[float]
    regret_global: Optional[float]
    regret_skip_reason: Optional[str]
    coverage_cost: Optional[float]
    coverage_streak: Optional[int]
    cce_constants: Dict[str, Optional[float]]
    opportunity_cost: Optional[float]
    missed_exploration_streak: Optional[int]
    oce_constants: Dict[str, Optional[float]]
    rwrp_penalty: Dict[str, float]
    rwrp_constants: Dict[str, Optional[float]]
    unique_domains: int
    unique_subdomains: int
    entropy_domains: float
    top_domain_share: float
    map_domain_count: int
    hop_entropy_domain: Optional[float]
    domain_hop_rate: Optional[float]
    domain_transition_edges: int
    domain_transition_total: int
    sub_micro_transition_edges: int
    sub_micro_transition_total: int
    micro_steps_present: bool
    micro_steps: Optional[Dict[str, Any]]


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PlanSuggestError(f"Missing required input: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise PlanSuggestError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _read_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return _load_json(path)


def _discover_epochs(epochs_dir: Path) -> List[Path]:
    if not epochs_dir.exists():
        raise PlanSuggestError(f"epochs dir missing: {epochs_dir.as_posix()} (fail-closed)")
    roots = [p for p in epochs_dir.iterdir() if p.is_dir()]
    if not roots:
        raise PlanSuggestError(f"epochs dir empty: {epochs_dir.as_posix()} (fail-closed)")
    return roots


def _mtime_key(path: Path) -> Tuple[float, str]:
    # tie-break by name for determinism
    return (path.stat().st_mtime, path.name)


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _lane_from_epoch_id(epoch_id: str) -> Optional[str]:
    e = (epoch_id or "").upper()
    if e.startswith("EPOCH_REANCHOR_CONSTRAINT"):
        return "REANCHOR"
    if e.startswith("EPOCH_STABILIZE"):
        return "STABILIZER"
    if e.startswith("EPOCH_NEXT_AUTO") or e.startswith("EPOCH_COVERAGE") or e.startswith("EPOCH_ACCEPTANCE") or e.startswith("EPOCH_PASS"):
        return "COVERAGE_HOP_RECOVERY"
    return None


def _count_transition_dict(payload: Any) -> Tuple[int, int]:
    if not isinstance(payload, dict):
        return (0, 0)
    edges = len(payload)
    total = 0
    for v in payload.values():
        total += _coerce_int(v)
    return (edges, total)


def _collect_micro_steps(root: Path) -> Optional[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for path in sorted(root.glob("CRU_*/micro_steps.json"), key=lambda p: p.name):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        chunk = payload.get("steps") if isinstance(payload, dict) else payload
        if isinstance(chunk, list):
            for entry in chunk:
                if isinstance(entry, dict):
                    steps.append(entry)
    if steps:
        return {"steps": steps}
    root_micro = _read_optional_json(root / "micro_steps.json")
    if isinstance(root_micro, dict):
        return root_micro
    return None


def _extract_signals(root: Path) -> EpochSignals:
    summary = _load_json(root / "epoch_summary.json")
    coverage = _load_json(root / "epoch_coverage.json")
    motion = _read_optional_json(root / "motion_metrics.json")
    transitions = _read_optional_json(root / "transitions.json") or {}
    micro_steps = _collect_micro_steps(root)
    regret = _read_optional_json(root / "epoch_regret.json") or {}

    observed = coverage.get("observed") or {}
    counts = observed.get("counts") or {}
    dominance = observed.get("dominance") or {}
    domains = observed.get("domains") or []

    unique_domains = _coerce_int(counts.get("unique_domains"))
    unique_subdomains = _coerce_int(counts.get("unique_subdomains"))
    entropy_domains = _coerce_float(dominance.get("entropy_domains"))
    top_domain_share = _coerce_float(dominance.get("top_domain_share"))
    map_domain_count = len(domains) if isinstance(domains, list) else 0

    hop_entropy_domain: Optional[float] = None
    domain_hop_rate: Optional[float] = None
    if isinstance(motion, dict):
        if motion.get("hop_entropy_domain") is not None:
            hop_entropy_domain = _coerce_float(motion.get("hop_entropy_domain"))
        if motion.get("domain_hop_rate") is not None:
            domain_hop_rate = _coerce_float(motion.get("domain_hop_rate"))

    dom_edges, dom_total = _count_transition_dict(transitions.get("domain_transitions"))
    sub_edges, sub_total = _count_transition_dict(transitions.get("subdomain_transitions"))
    mic_edges, mic_total = _count_transition_dict(transitions.get("microdomain_transitions"))

    kernel_target = (summary.get("kernel_identity") or {}).get("kernel_target")
    epoch_id = str(summary.get("epoch_id") or root.name)
    epoch_hash = summary.get("epoch_hash")
    epoch_profile = summary.get("epoch_profile")
    epoch_verdict = summary.get("epoch_verdict")
    coherence_debt = summary.get("coherence_debt")
    coherence_budget = summary.get("coherence_budget")
    if coherence_debt is not None:
        coherence_debt = _coerce_int(coherence_debt)
    if coherence_budget is not None:
        coherence_budget = _coerce_float(coherence_budget)
    regret_global = regret.get("regret_global")
    regret_skip_reason = regret.get("regret_skip_reason")
    if regret_global is not None:
        try:
            regret_global = float(regret_global)
        except Exception:
            regret_global = None

    cce_state = None
    coverage_cost = None
    coverage_streak = None
    cce_const = {"cce_step": None, "cce_max": None, "cce_decay": None}
    oce_state = None
    opportunity_cost = None
    missed_exploration_streak = None
    oce_const = {"oce_step": None, "oce_max": None, "oce_decay": None}
    rwrp_state = None
    rwrp_penalties: Dict[str, float] = {}
    rwrp_const = {"rwrp_alpha": None, "rwrp_beta": None, "rwrp_max": None}
    try:
        if load_cce_state is not None:
            cce_state = load_cce_state()
            coverage_cost = float(cce_state.coverage_cost)
            coverage_streak = int(cce_state.coverage_streak)
            cce_const = cce_constants()
        if load_oce_state is not None:
            oce_state = load_oce_state()
            opportunity_cost = float(oce_state.opportunity_cost)
            missed_exploration_streak = int(oce_state.missed_exploration_streak)
            oce_const = oce_constants()
        if load_rwrp_state is not None:
            rwrp_state = load_rwrp_state()
            rwrp_const = rwrp_constants()
            for lane, data in (rwrp_state.lane_regret_memory or {}).items():
                rwrp_penalties[lane] = float(data.penalty)
    except Exception:
        # fail-closed later when used
        cce_state = None

    return EpochSignals(
        root=root,
        epoch_id=epoch_id,
        epoch_hash=epoch_hash,
        epoch_profile=epoch_profile,
        epoch_verdict=epoch_verdict,
        kernel_target=kernel_target,
        coherence_debt=coherence_debt if isinstance(coherence_debt, int) else None,
        coherence_budget=coherence_budget if isinstance(coherence_budget, float) else None,
        regret_global=regret_global if isinstance(regret_global, float) else None,
        regret_skip_reason=regret_skip_reason if isinstance(regret_skip_reason, str) else None,
        coverage_cost=coverage_cost if isinstance(coverage_cost, float) else None,
        coverage_streak=coverage_streak if isinstance(coverage_streak, int) else None,
        cce_constants=cce_const,
        opportunity_cost=opportunity_cost if isinstance(opportunity_cost, float) else None,
        missed_exploration_streak=missed_exploration_streak if isinstance(missed_exploration_streak, int) else None,
        oce_constants=oce_const,
        rwrp_penalty=rwrp_penalties,
        rwrp_constants=rwrp_const,
        unique_domains=unique_domains,
        unique_subdomains=unique_subdomains,
        entropy_domains=entropy_domains,
        top_domain_share=top_domain_share,
        map_domain_count=map_domain_count,
        hop_entropy_domain=hop_entropy_domain,
        domain_hop_rate=domain_hop_rate,
        domain_transition_edges=dom_edges,
        domain_transition_total=dom_total,
        sub_micro_transition_edges=sub_edges + mic_edges,
        sub_micro_transition_total=sub_total + mic_total,
        micro_steps_present=micro_steps is not None,
        micro_steps=micro_steps,
    )


def _micro_step_value(micro_steps: Dict[str, Any], step_name: str, key: str) -> Optional[Any]:
    steps = micro_steps.get("steps")
    if not isinstance(steps, list):
        return None
    for entry in steps:
        if not isinstance(entry, dict):
            continue
        name = entry.get("step") or entry.get("phase") or entry.get("name")
        if name != step_name:
            continue
        if key in entry:
            return entry.get(key)
        flags = entry.get("flags")
        if isinstance(flags, dict) and key in flags:
            return flags.get(key)
    return None


def _count_micro_steps(micro_steps: Optional[Dict[str, Any]]) -> Dict[str, int]:
    if not isinstance(micro_steps, dict):
        return {"forced_resolve": 0, "low_coherence": 0, "constraint_hits": 0}
    steps = micro_steps.get("steps") or []
    forced = 0
    low = 0
    constraint_hits = 0
    for s in steps:
        if not isinstance(s, dict):
            continue
        flags = s.get("flags") or {}
        if flags.get("resolve_mode") in {"forced", "partial", "unresolved", "refuse"}:
            forced += 1
        if flags.get("coherence_bucket") == "LOW":
            low += 1
        ch = flags.get("constraint_hit")
        if ch and ch != "none":
            constraint_hits += 1
    return {"forced_resolve": forced, "low_coherence": low, "constraint_hits": constraint_hits}


def _compute_delayed_violation(
    triggers_history: List[Dict[str, Any]],
    *,
    micro_history: List[bool],
    window: int = 5,
) -> Tuple[int, Optional[str]]:
    """
    Delayed violation accumulator (fail-closed):
    - Uses the last `window` epochs excluding the current one.
    - Counts epochs that had operational strain (forced/low/constraint).
    - If evidence is missing in the window, returns 0 with a skip reason.
    """
    if len(triggers_history) < 2:
        return (0, "insufficient_history")

    lookback = min(window, len(triggers_history) - 1)
    prior = triggers_history[-(lookback + 1) : -1]
    prior_micro = micro_history[-(lookback + 1) : -1]

    if any(not m for m in prior_micro):
        return (0, "missing_micro_steps")

    count = 0
    for row in prior:
        forced = int(row.get("forced_resolve_count", 0) or 0)
        low = int(row.get("low_coherence_count", 0) or 0)
        constraints = int(row.get("constraint_hits", 0) or 0)
        resolve_nc = row.get("resolve_not_clean") is True
        eval_low = row.get("eval_coherence_low") is True
        if forced > 0 or low > 0 or constraints > 0 or resolve_nc or eval_low:
            count += 1
    return (count, None)


def _build_state_description(
    signals: EpochSignals,
    triggers: Dict[str, Any],
    *,
    stable_streak: bool,
    dense_motion_window: bool,
    consecutive_bad: int,
    delayed_violation_count: int,
    regret_pressure: float,
    coverage_fatigue: float,
) -> str:
    def _tri_bool(value: TriBool) -> int:
        if value is True:
            return 1
        if value is False:
            return 0
        return -1  # unknown / missing evidence

    parts = [
        "KT_STATE_V1",
        f"forced_resolve_count={triggers.get('forced_resolve_count', 0)}",
        f"low_coherence_count={triggers.get('low_coherence_count', 0)}",
        f"constraint_hits={triggers.get('constraint_hits', 0)}",
        f"resolve_not_clean={_tri_bool(triggers.get('resolve_not_clean'))}",
        f"eval_coherence_low={_tri_bool(triggers.get('eval_coherence_low'))}",
        f"coverage_stagnation={_tri_bool(triggers.get('coverage_stagnation'))}",
        f"map_entropy_low={int(bool(triggers.get('map_entropy_low')))}",
        f"coherence_debt={(signals.coherence_debt if signals.coherence_debt is not None else -1)}",
        f"coherence_budget={(signals.coherence_budget if signals.coherence_budget is not None else -1)}",
        f"regret_global={(signals.regret_global if signals.regret_global is not None else -1)}",
        f"coverage_cost={(signals.coverage_cost if signals.coverage_cost is not None else -1)}",
        f"coverage_streak={(signals.coverage_streak if signals.coverage_streak is not None else -1)}",
        f"opportunity_cost={(signals.opportunity_cost if signals.opportunity_cost is not None else -1)}",
        f"missed_exploration_streak={(signals.missed_exploration_streak if signals.missed_exploration_streak is not None else -1)}",
        f"unique_domains={signals.unique_domains}",
        f"unique_subdomains={signals.unique_subdomains}",
        f"entropy_domains={signals.entropy_domains}",
        f"top_domain_share={signals.top_domain_share}",
        f"hop_entropy_domain={signals.hop_entropy_domain or 0}",
        f"domain_hop_rate={signals.domain_hop_rate or 0}",
        f"map_domain_count={signals.map_domain_count}",
        f"dense_motion_window={int(bool(dense_motion_window))}",
        f"stable_streak={int(bool(stable_streak))}",
        f"consecutive_bad_epochs={int(consecutive_bad)}",
        f"delayed_violation_count={int(delayed_violation_count)}",
        f"regret_pressure={regret_pressure}",
        f"coverage_fatigue={coverage_fatigue}",
    ]
    return "\n".join(parts)


def _log_lane_policy(
    policy: KTLanePolicy,
    state_text: str,
    heuristic_lane: str,
    payload: Dict[str, Any],
    log_path: Path,
) -> None:
    try:
        policy_result = policy.predict(state_text)
    except Exception as exc:  # pragma: no cover
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "epoch_id": payload.get("epoch_id"),
            "heuristic_lane": heuristic_lane,
            "policy_error": str(exc),
        }
        _append_jsonl(log_path, entry)
        return

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "epoch_id": payload.get("epoch_id"),
        "heuristic_lane": heuristic_lane,
        "policy_lane": policy_result.get("recommendation"),
        "policy_confidence": policy_result.get("confidence"),
        "policy_distribution": policy_result.get("probs"),
        "policy_used": policy_result.get("policy_used"),
        "state_text": state_text,
    }
    _append_jsonl(log_path, entry)


def _trigger_resolve_not_clean(s: EpochSignals) -> TriBool:
    if not s.micro_steps_present or not isinstance(s.micro_steps, dict):
        return None
    mode = _micro_step_value(s.micro_steps, "RESOLVE", "resolve_mode")
    if not isinstance(mode, str):
        return None
    return mode.strip().lower() != "clean"


def _trigger_eval_coherence_low(s: EpochSignals) -> TriBool:
    if not s.micro_steps_present or not isinstance(s.micro_steps, dict):
        return None
    bucket = _micro_step_value(s.micro_steps, "EVAL", "coherence_bucket")
    if not isinstance(bucket, str):
        return None
    return bucket.strip().upper() == "LOW"


def _trigger_map_entropy_low(s: EpochSignals) -> bool:
    # Deterministic v1 rule:
    # - map_domain_count <= 1  OR  hop_entropy_domain == 0
    if s.map_domain_count <= 1:
        return True
    if s.hop_entropy_domain is None:
        return False
    return float(s.hop_entropy_domain) == 0.0


def _trigger_coverage_stagnation(curr: EpochSignals, prev: Optional[EpochSignals]) -> TriBool:
    if prev is None:
        return None
    return (curr.unique_domains <= prev.unique_domains) and (curr.unique_subdomains <= prev.unique_subdomains)


def _dense_motion(s: EpochSignals) -> bool:
    # Conservative: require non-trivial motion, not just presence.
    if (s.hop_entropy_domain or 0.0) > 0.0:
        return True
    if s.domain_transition_total > 1 or s.sub_micro_transition_total > 0:
        return True
    return False


def _pick_lane(
    *,
    resolve_not_clean: TriBool,
    eval_coherence_low: TriBool,
    map_entropy_low: bool,
    coverage_stagnation: TriBool,
    stable_streak: bool,
    dense_motion: bool,
    forced_resolve_count: int,
    low_coherence_count: int,
    consecutive_bad: int,
) -> str:
    # Priority: stabilize if we have explicit instability signals.
    if (resolve_not_clean is True) or (eval_coherence_low is True):
        return "STABILIZER"
    if forced_resolve_count > 0 or low_coherence_count > 0:
        if consecutive_bad >= 2:
            return "STABILIZER"
        return "REANCHOR"
    if map_entropy_low or coverage_stagnation is True:
        return "COVERAGE_HOP_RECOVERY"
    if stable_streak and dense_motion:
        return "DEPTH_CONSOLIDATION"
    return "NONE"


def _lane_public_name(lane: str) -> str:
    return {
        "COVERAGE_HOP_RECOVERY": "coverage_lane",
        "STABILIZER": "stabilize_lane",
        "REANCHOR": "reanchor_lane",
        "DEPTH_CONSOLIDATION": "depth_lane",
        "NONE": "none",
    }.get(lane, "none")


def _confidence(
    *,
    target: EpochSignals,
    trigger_evidence: Dict[str, Any],
) -> float:
    score = 0.4
    if target.hop_entropy_domain is not None or target.domain_hop_rate is not None:
        score += 0.2
    if target.domain_transition_total > 0 or target.sub_micro_transition_total > 0:
        score += 0.1
    if trigger_evidence.get("coverage_stagnation") is not None:
        score += 0.1
    if trigger_evidence.get("resolve_not_clean") is not None and trigger_evidence.get("eval_coherence_low") is not None:
        score += 0.2
    return round(min(score, 0.9), 2)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True))
        handle.write("\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plan suggester (tooling-only; advisory; deterministic).")
    p.add_argument("--epoch-root", action="append", help="Epoch artifact root (repeatable).")
    p.add_argument("--epochs-dir", help="Directory containing epoch artifact roots.")
    p.add_argument("--stable-window", type=int, default=3, help="Stable streak window for DEPTH_CONSOLIDATION suggestion (default: 3).")
    p.add_argument(
        "--history",
        type=int,
        default=None,
        help=f"When using --epochs-dir, only consider the most recent N epochs (mtime-sorted). Default: {DEFAULT_HISTORY}.",
    )
    p.add_argument("--out", help="Optional JSON output path for the latest suggestion.")
    p.add_argument("--ledger-out", help="Optional append-only JSONL ledger path.")
    p.add_argument(
        "--append-log",
        action="store_true",
        help="Append suggestion to default log path (tools/growth/state/plan_suggestions.jsonl).",
    )
    p.add_argument("--write-epoch", action="store_true", help="Write plan_suggestion.json into the latest epoch root.")
    p.add_argument(
        "--lane-policy",
        action="store_true",
        help="Invoke the lane policy adapter (KT_LANE_LORA_PHASE_A) and log its recommendation.",
    )
    p.add_argument(
        "--policy-log",
        type=Path,
        nargs="?",
        const=Path(__file__).resolve().parent / "lane_policy_comparison.jsonl",
        default=Path(__file__).resolve().parent / "lane_policy_comparison.jsonl",
        help="Path to append policy comparison logs.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    policy: Optional[KTLanePolicy] = None
    if args.lane_policy:
        if build_default_policy is None:  # pragma: no cover
            print("Lane policy module unavailable (fail-closed)", file=sys.stderr)
        else:
            try:
                policy = build_default_policy()
            except Exception as exc:  # pragma: no cover
                print(f"Lane policy load failed (shadow disabled): {exc}", file=sys.stderr)

    epoch_roots: List[Path] = []
    if args.epoch_root:
        epoch_roots.extend(Path(p).resolve() for p in args.epoch_root)
    if args.epochs_dir:
        epoch_roots.extend(_discover_epochs(Path(args.epochs_dir).resolve()))

    if not epoch_roots:
        raise PlanSuggestError("No epoch roots provided (fail-closed)")

    # Order by mtime so we can target "latest" reliably.
    epoch_roots = sorted(set(epoch_roots), key=_mtime_key, reverse=True)

    required_history = args.history
    if required_history is None:
        required_history = DEFAULT_HISTORY if args.epochs_dir else len(epoch_roots)
    epoch_roots = epoch_roots[:required_history]

    if len(epoch_roots) < 2:
        raise PlanSuggestError("Need at least 2 epochs to evaluate coverage stagnation (fail-closed)")

    # Evaluate chronologically for deltas.
    chronological = list(reversed(epoch_roots))
    signals = [_extract_signals(root) for root in chronological]

    triggers_by_epoch: List[Dict[str, Any]] = []
    micro_present_history: List[bool] = []
    prev: Optional[EpochSignals] = None
    lane_history: List[Optional[str]] = []
    for s in signals:
        resolve_not_clean = _trigger_resolve_not_clean(s)
        eval_coherence_low = _trigger_eval_coherence_low(s)
        map_entropy_low = _trigger_map_entropy_low(s)
        coverage_stagnation = _trigger_coverage_stagnation(s, prev)
        micro_counts = _count_micro_steps(s.micro_steps)

        triggers_by_epoch.append(
            {
                "epoch_id": s.epoch_id,
                "resolve_not_clean": resolve_not_clean,
                "eval_coherence_low": eval_coherence_low,
                "map_entropy_low": map_entropy_low,
                "coverage_stagnation": coverage_stagnation,
                "dense_motion": _dense_motion(s),
                "forced_resolve_count": micro_counts["forced_resolve"],
                "low_coherence_count": micro_counts["low_coherence"],
                "constraint_hits": micro_counts["constraint_hits"],
            }
        )
        micro_present_history.append(bool(s.micro_steps_present))
        lane_history.append(_lane_from_epoch_id(s.epoch_id))
        prev = s

    target = signals[-1]
    target_triggers = triggers_by_epoch[-1]
    prev_regret_global: Optional[float] = None
    prev_regret_skip: Optional[str] = None
    if len(signals) >= 2:
        prev_sig = signals[-2]
        prev_regret_global = prev_sig.regret_global
        prev_regret_skip = prev_sig.regret_skip_reason

    delayed_count, delayed_skip = _compute_delayed_violation(
        triggers_by_epoch, micro_history=micro_present_history, window=5
    )
    regret_pressure = round(min(delayed_count / 5.0, 1.0), 3) if delayed_skip is None else 0.0

    # Stable streak: last N epochs must have full observability and no triggers.
    window = max(int(args.stable_window), 1)
    streak = triggers_by_epoch[-window:]
    stable_streak = True
    for row in streak:
        if row["resolve_not_clean"] is None or row["eval_coherence_low"] is None or row["coverage_stagnation"] is None:
            stable_streak = False
            break
        if row["resolve_not_clean"] or row["eval_coherence_low"] or row["map_entropy_low"] or row["coverage_stagnation"]:
            stable_streak = False
            break

    dense_motion_window = all(bool(r.get("dense_motion")) for r in streak)

    consecutive_bad = 0
    for row in reversed(triggers_by_epoch):
        if row.get("forced_resolve_count", 0) > 0 or row.get("low_coherence_count", 0) > 0:
            consecutive_bad += 1
        else:
            break

    # Coverage fatigue: count consecutive coverage lanes in immediate history.
    coverage_streak = 0
    for lane in reversed(lane_history[:-1]):  # exclude current epoch
        if lane == "COVERAGE_HOP_RECOVERY":
            coverage_streak += 1
        else:
            break
    coverage_fatigue = min(coverage_streak, 3) / 3.0 if coverage_streak > 0 else 0.0

    recommended_lane = _pick_lane(
        resolve_not_clean=target_triggers["resolve_not_clean"],
        eval_coherence_low=target_triggers["eval_coherence_low"],
        map_entropy_low=bool(target_triggers["map_entropy_low"]),
        coverage_stagnation=target_triggers["coverage_stagnation"],
        stable_streak=stable_streak,
        dense_motion=dense_motion_window,
        forced_resolve_count=target_triggers.get("forced_resolve_count", 0),
        low_coherence_count=target_triggers.get("low_coherence_count", 0),
        consecutive_bad=consecutive_bad,
    )
    cce_applied = False
    cce_reason: Optional[str] = None
    coverage_cost = target.coverage_cost if target.coverage_cost is not None else 0.0
    # Simple deterministic scoring with CCE penalty on coverage.
    opportunity_cost = target.opportunity_cost if target.opportunity_cost is not None else 0.0
    lane_scores = {
        "COVERAGE_HOP_RECOVERY": max(0.0, 1.0 - coverage_cost - opportunity_cost),
        "REANCHOR": 1.0,
        "STABILIZER": 1.0,
        "DEPTH_CONSOLIDATION": 1.0,
        "NONE": 0.5,
    }
    # Regret-weighted replay penalty by lane.
    rwrp_penalty = target.rwrp_penalty or {}
    for lane, pen in rwrp_penalty.items():
        lane_scores[lane] = max(0.0, lane_scores.get(lane, 0.0) - pen)
    best_lane = max(lane_scores.items(), key=lambda kv: kv[1])[0]
    if recommended_lane == "COVERAGE_HOP_RECOVERY" and lane_scores["COVERAGE_HOP_RECOVERY"] < lane_scores[best_lane]:
        recommended_lane = best_lane
        cce_applied = True
        cce_reason = f"coverage_cost_penalty:{coverage_cost}"
    regret_bias_applied = False
    regret_bias_reason: Optional[str] = None
    # Soft, deterministic bias: if prior regret was high for coverage, nudge to REANCHOR.
    if recommended_lane == "COVERAGE_HOP_RECOVERY":
        if prev_regret_global is not None and prev_regret_skip is None and prev_regret_global >= 0.4:
            recommended_lane = "REANCHOR"
            regret_bias_applied = True
            regret_bias_reason = f"prev_regret_high:{prev_regret_global}"
        elif coverage_fatigue >= 0.66:
            recommended_lane = "REANCHOR"
            regret_bias_applied = True
            regret_bias_reason = f"coverage_fatigue:{coverage_fatigue}"

    confidence = _confidence(target=target, trigger_evidence=target_triggers)

    triggered: List[str] = []
    if target_triggers["resolve_not_clean"] is True:
        triggered.append("RESOLVE_NOT_CLEAN")
    if target_triggers["eval_coherence_low"] is True:
        triggered.append("EVAL_COHERENCE_LOW")
    if target_triggers["map_entropy_low"] is True:
        triggered.append("MAP_ENTROPY_LOW")
    if target_triggers["coverage_stagnation"] is True:
        triggered.append("COVERAGE_STAGNATION")

    payload: Dict[str, Any] = {
        "schema": "PLAN_SUGGESTION_V1",
        "epoch_id": target.epoch_id,
        "epoch_hash": target.epoch_hash,
        "epoch_profile": target.epoch_profile,
        "epoch_verdict": target.epoch_verdict,
        "kernel_target": target.kernel_target,
        "recommended_lane": _lane_public_name(recommended_lane),
        "recommended_lane_internal": recommended_lane,
        "regret_bias_applied": regret_bias_applied,
        "regret_bias_reason": regret_bias_reason,
        "cce_applied": cce_applied,
        "cce_reason": cce_reason,
        "oce_applied": opportunity_cost > 0.0,
        "oce_reason": "missed_exploration_streak>=1" if opportunity_cost > 0.0 else None,
        "rwrp_penalties": rwrp_penalty,
        "triggered_rules": triggered,
        "triggered": triggered,  # backward compatible alias
        "confidence": confidence,
        "signals": {
            "map_domain_count": target.map_domain_count,
            "unique_domains": target.unique_domains,
            "unique_subdomains": target.unique_subdomains,
            "entropy_domains": target.entropy_domains,
            "top_domain_share": target.top_domain_share,
            "hop_entropy_domain": target.hop_entropy_domain,
            "domain_hop_rate": target.domain_hop_rate,
            "domain_transition_edges": target.domain_transition_edges,
            "domain_transition_total": target.domain_transition_total,
            "sub_micro_transition_edges": target.sub_micro_transition_edges,
            "sub_micro_transition_total": target.sub_micro_transition_total,
            "micro_steps_present": target.micro_steps_present,
            "forced_resolve_count": target_triggers.get("forced_resolve_count", 0),
            "low_coherence_count": target_triggers.get("low_coherence_count", 0),
            "stable_streak": stable_streak,
            "dense_motion_window": dense_motion_window,
            "delayed_violation_count": delayed_count,
            "regret_pressure": regret_pressure,
            "delayed_violation_skip_reason": delayed_skip,
            "coherence_debt": target.coherence_debt,
            "coherence_budget": target.coherence_budget,
            "regret_global": target.regret_global,
            "regret_skip_reason": target.regret_skip_reason,
            "regret_prev_global": prev_regret_global,
            "regret_prev_skip_reason": prev_regret_skip,
            "coverage_fatigue": coverage_fatigue,
            "coverage_cost": target.coverage_cost,
            "coverage_streak": target.coverage_streak,
            "cce_constants": target.cce_constants,
            "opportunity_cost": target.opportunity_cost,
            "missed_exploration_streak": target.missed_exploration_streak,
            "oce_constants": target.oce_constants,
            "rwrp_penalty": rwrp_penalty,
            "rwrp_constants": target.rwrp_constants,
        },
        "trigger_evidence": target_triggers,
        "history": {
            "epochs_considered": [s.epoch_id for s in signals],
            "triggers_by_epoch": triggers_by_epoch,
        },
        "constraints": {
            "advisory_only": True,
            "does_not_gate": True,
            "does_not_mutate_plans": True,
        },
        "lane_hints": {
            "COVERAGE_HOP_RECOVERY": {
                "goal": "force motion + breadth",
                "recommended_epoch_profile": "COVERAGE_SEED",
                "notes": ["hop-heavy crucibles", "domain rotation emphasis"],
                "example_plans": [
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_NEXT_AUTO.json",
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_COVERAGE_SEED_RUN1.json",
                ],
            },
            "STABILIZER": {
                "goal": "restore clean resolves + coherence",
                "recommended_epoch_profile": "COVERAGE_MILESTONE",
                "notes": ["pass-pair crucibles", "reduced novelty"],
                "example_plans": [
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_PASS_PAIR_SEED.json",
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_ACCEPTANCE_GATE.json",
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_ACCEPTANCE_BENCHMARK.json",
                ],
            },
            "REANCHOR": {
                "goal": "re-anchor within the same domain after forced/low signals",
                "notes": ["constraint pressure", "no branching"],
                "example_plans": [
                    "KT_PROD_CLEANROOM/tools/growth/orchestrator/examples/EPOCH_REANCHOR_CONSTRAINT.json"
                ],
            },
            "DEPTH_CONSOLIDATION": {
                "goal": "deepen within a stable band",
                "notes": ["requires dense motion", "no automatic enforcement"],
                "example_plans": [],
            },
        },
    }

    if policy is not None and args.policy_log:
        state_text = _build_state_description(
            target,
            target_triggers,
            stable_streak=stable_streak,
            dense_motion_window=dense_motion_window,
            consecutive_bad=consecutive_bad,
            delayed_violation_count=delayed_count,
            regret_pressure=regret_pressure,
            coverage_fatigue=coverage_fatigue,
        )
        _log_lane_policy(
            policy,
            state_text,
            payload["recommended_lane"],
            payload,
            args.policy_log,
        )

    if args.out:
        _write_json(Path(args.out), payload)

    if args.write_epoch:
        _write_json(target.root / "plan_suggestion.json", payload)

    if args.ledger_out and args.append_log:
        raise PlanSuggestError("Provide only one of --ledger-out or --append-log (fail-closed)")

    ledger_path: Optional[Path] = None
    if args.ledger_out:
        ledger_path = Path(args.ledger_out)
    elif args.append_log:
        ledger_path = Path(__file__).resolve().parent / "plan_suggestions.jsonl"

    if ledger_path is not None:
        _append_jsonl(ledger_path, payload)

    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PlanSuggestError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
