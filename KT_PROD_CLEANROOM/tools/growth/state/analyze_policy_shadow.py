import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze shadow policy audit log (JSONL).")
    p.add_argument(
        "--policy-log",
        type=Path,
        default=Path(__file__).resolve().parent / "lane_policy_comparison.jsonl",
        help="Path to lane policy comparison JSONL.",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional JSON output path (in addition to stdout).",
    )
    return p.parse_args()


def _jloads(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _parse_state_text(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw or "=" not in raw or raw.startswith("KT_STATE"):
            continue
        k, v = raw.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        try:
            if "." in v:
                out[k] = float(v)
            else:
                out[k] = int(v)
        except Exception:
            out[k] = v
    return out


def _percentile(xs: List[float], q: float) -> float:
    if not xs:
        return float("nan")
    xs = sorted(xs)
    if q <= 0:
        return xs[0]
    if q >= 1:
        return xs[-1]
    pos = (len(xs) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return xs[lo]
    frac = pos - lo
    return xs[lo] * (1 - frac) + xs[hi] * frac


def main() -> int:
    args = _parse_args()
    if not args.policy_log.exists():
        raise SystemExit(f"Missing policy log: {args.policy_log.as_posix()}")

    rows: List[Dict[str, Any]] = []
    for line in args.policy_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = _jloads(line)
        if obj:
            rows.append(obj)

    valid: List[Dict[str, Any]] = []
    for r in rows:
        if r.get("policy_error"):
            continue
        if not r.get("heuristic_lane") or not r.get("policy_lane"):
            continue
        if r.get("policy_confidence") is None:
            continue
        valid.append(r)

    agree = 0
    disagree = 0
    matrix = Counter()
    disagree_conf: List[float] = []
    agree_conf: List[float] = []

    for r in valid:
        h = str(r["heuristic_lane"])
        p = str(r["policy_lane"])
        conf = float(r["policy_confidence"])
        key = f"{h}->{p}"
        matrix[key] += 1
        if h == p:
            agree += 1
            agree_conf.append(conf)
        else:
            disagree += 1
            disagree_conf.append(conf)

    # Outcome correlation proxy (disagreement-only): look at the next logged epoch.
    # Row i is the recommendation "for the next plan"; row i+1 reflects the outcome after the executed plan.
    disagree_next_bad_by_policy = defaultdict(list)
    disagree_next_forced_by_policy = defaultdict(list)
    disagree_next_low_by_policy = defaultdict(list)

    by_iter = {int(r.get("iteration", -1)): r for r in valid if isinstance(r.get("iteration"), int)}
    if by_iter:
        max_iter = max(by_iter)
        for i, r in by_iter.items():
            if i < 1 or i >= max_iter:
                continue
            if str(r["heuristic_lane"]) == str(r["policy_lane"]):
                continue
            nxt = by_iter.get(i + 1)
            if not nxt:
                continue
            nxt_state = _parse_state_text(str(nxt.get("state_text") or ""))
            forced = int(nxt_state.get("forced_resolve_count", 0) or 0)
            low = int(nxt_state.get("low_coherence_count", 0) or 0)
            nxt_bad = 1 if (forced > 0 or low > 0) else 0
            pl = str(r["policy_lane"])
            disagree_next_bad_by_policy[pl].append(nxt_bad)
            disagree_next_forced_by_policy[pl].append(forced)
            disagree_next_low_by_policy[pl].append(low)

    def mean(xs: List[float]) -> float:
        return float(sum(xs) / len(xs)) if xs else float("nan")

    report = {
        "rows_total": len(rows),
        "rows_valid": len(valid),
        "agreement_rate": (agree / len(valid)) if valid else float("nan"),
        "disagreement_rate": (disagree / len(valid)) if valid else float("nan"),
        "disagreement_matrix": dict(matrix),
        "confidence_agree": {
            "n": len(agree_conf),
            "mean": mean(agree_conf),
            "min": min(agree_conf) if agree_conf else float("nan"),
            "max": max(agree_conf) if agree_conf else float("nan"),
        },
        "confidence_disagree": {
            "n": len(disagree_conf),
            "mean": mean(disagree_conf),
            "min": min(disagree_conf) if disagree_conf else float("nan"),
            "max": max(disagree_conf) if disagree_conf else float("nan"),
            "p25": _percentile(disagree_conf, 0.25) if disagree_conf else float("nan"),
            "p50": _percentile(disagree_conf, 0.50) if disagree_conf else float("nan"),
            "p75": _percentile(disagree_conf, 0.75) if disagree_conf else float("nan"),
        },
        "disagree_next_bad_rate_by_policy_lane": {
            k: mean(v) for k, v in disagree_next_bad_by_policy.items()
        },
        "disagree_next_forced_mean_by_policy_lane": {
            k: mean(v) for k, v in disagree_next_forced_by_policy.items()
        },
        "disagree_next_low_mean_by_policy_lane": {
            k: mean(v) for k, v in disagree_next_low_by_policy.items()
        },
    }

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
