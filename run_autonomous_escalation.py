import argparse
import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict
from datetime import datetime

ROOT = Path("KT_PROD_CLEANROOM")
ARTIFACT_EPOCHS = ROOT / "tools" / "growth" / "artifacts" / "epochs"
PLAN_FILES = {
    "coverage": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_NEXT_AUTO.json",
    "reanchor": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_REANCHOR_CONSTRAINT.json",
    "stabilize": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_STABILIZE.json",
}


def run_plan(plan_path: Path, env: dict) -> None:
    cmd = [
        "python",
        str(ROOT / "tools" / "growth" / "orchestrator" / "epoch_orchestrator.py"),
        "--epoch",
        str(plan_path),
        "--salvage",
    ]
    subprocess.run(cmd, env=env, check=True)


def latest_epoch_root() -> Path:
    roots = [p for p in ARTIFACT_EPOCHS.iterdir() if p.is_dir()]
    return max(roots, key=lambda p: p.stat().st_mtime)


def run_plan_suggester(env: dict) -> Dict[str, any]:
    cmd = [
        "python",
        str(ROOT / "tools" / "growth" / "state" / "plan_suggester.py"),
        "--epochs-dir",
        str(ARTIFACT_EPOCHS),
        "--write-epoch",
        "--append-log",
    ]
    subprocess.run(cmd, env=env, check=True)
    plan = latest_epoch_root() / "plan_suggestion.json"
    return json.loads(plan.read_text(encoding="utf-8"))


def select_plan(recommendation: str) -> str:
    internal = recommendation.get("recommended_lane_internal", "")
    if internal == "REANCHOR":
        return "reanchor"
    if internal == "STABILIZER":
        return "stabilize"
    return "coverage"


def parse_args():
    parser = argparse.ArgumentParser(description="Autonomous escalation run script.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="Number of autonomous epochs to execute.",
    )
    parser.add_argument(
        "--shadow-policy",
        action="store_true",
        help="Enable lane-policy shadow logging (observer-only; no execution authority).",
    )
    parser.add_argument(
        "--policy-log",
        type=Path,
        default=ROOT / "tools" / "growth" / "state" / "lane_policy_comparison.jsonl",
        help="Path to append policy-vs-heuristic audit rows (JSONL).",
    )
    return parser.parse_args()


def _append_jsonl(path: Path, payload: Dict[str, any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")


def _state_text_from_suggestion(suggestion: Dict[str, any]) -> str:
    signals = suggestion.get("signals") or {}
    parts = [
        "KT_STATE_V1",
        f"forced_resolve_count={signals.get('forced_resolve_count', 0)}",
        f"low_coherence_count={signals.get('low_coherence_count', 0)}",
        f"unique_domains={signals.get('unique_domains', 0)}",
        f"unique_subdomains={signals.get('unique_subdomains', 0)}",
        f"entropy_domains={signals.get('entropy_domains', 0.0)}",
        f"hop_entropy_domain={signals.get('hop_entropy_domain', 0.0) or 0.0}",
        f"domain_hop_rate={signals.get('domain_hop_rate', 0.0) or 0.0}",
        f"map_domain_count={signals.get('map_domain_count', 0)}",
    ]
    return "\n".join(parts)


def main() -> None:
    args = parse_args()
    env = os.environ.copy()
    env["KT_LIVE"] = "0"
    env["KT_LIVE_PROOF"] = ""

    shadow_enabled = args.shadow_policy or (env.get("KT_POLICY_SHADOW", "").strip() == "1")
    policy = None
    if shadow_enabled:
        try:
            from KT_PROD_CLEANROOM.tools.growth.state.kt_lane_policy import build_default_policy

            policy = build_default_policy()
        except Exception as exc:
            print(f"[shadow-policy] disabled (could not load policy): {exc}")
            policy = None

    print("=== STEP A: baseline coverage ===")
    run_plan(PLAN_FILES["coverage"], env)

    records = []
    lane_counter = Counter()
    for idx in range(1, args.iterations + 1):
        suggestion = run_plan_suggester(env)
        plan_key = select_plan(suggestion)
        plan_path = PLAN_FILES[plan_key]
        signals = suggestion.get("signals", {})
        record = {
            "iteration": idx,
            "epoch": suggestion.get("epoch_id"),
            "recommended_lane": suggestion.get("recommended_lane"),
            "recommended_lane_internal": suggestion.get("recommended_lane_internal"),
            "forced": signals.get("forced_resolve_count", 0),
            "low_coherence": signals.get("low_coherence_count", 0),
            "entropy": signals.get("entropy_domains", 0.0),
            "plan_run": plan_key,
        }
        print(f"\n=== ITERATION {idx}: suggested {record['recommended_lane']} -> running {plan_key} ===")

        if policy is not None:
            state_text = _state_text_from_suggestion(suggestion)
            try:
                policy_result = policy.predict(state_text)
                _append_jsonl(
                    args.policy_log,
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "iteration": idx,
                        "epoch_id": suggestion.get("epoch_id"),
                        "heuristic_lane": suggestion.get("recommended_lane"),
                        "heuristic_lane_internal": suggestion.get("recommended_lane_internal"),
                        "plan_run": plan_key,
                        "policy_lane": policy_result.get("recommendation"),
                        "policy_confidence": policy_result.get("confidence"),
                        "policy_distribution": policy_result.get("probs"),
                        "policy_used": policy_result.get("policy_used"),
                        "state_text": state_text,
                    },
                )
            except Exception as exc:
                _append_jsonl(
                    args.policy_log,
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "iteration": idx,
                        "epoch_id": suggestion.get("epoch_id"),
                        "heuristic_lane": suggestion.get("recommended_lane"),
                        "heuristic_lane_internal": suggestion.get("recommended_lane_internal"),
                        "plan_run": plan_key,
                        "policy_error": str(exc),
                    },
                )

        run_plan(plan_path, env)
        records.append(record)
        lane_counter[plan_key] += 1

    summary = {
        "runs": len(records),
        "forced_total": sum(r["forced"] for r in records),
        "low_total": sum(r["low_coherence"] for r in records),
        "consecutive_bad_coverage": _consecutive_bad_coverage(records),
    }
    summary["lane_counts"] = dict(lane_counter)
    print("\n=== AUTONOMOUS ESCALATION SUMMARY ===")
    print(json.dumps(summary, indent=2))
    Path("autonomous_escalation_log.json").write_text(json.dumps(records, indent=2))
    print("Details saved to autonomous_escalation_log.json")


def _consecutive_bad_coverage(records):
    max_streak = 0
    current = 0
    for rec in records:
        if rec["plan_run"] == "coverage" and (rec["forced"] > 0 or rec["low_coherence"] > 0):
            current += 1
            max_streak = max(max_streak, current)
        else:
            current = 0
    return max_streak


if __name__ == "__main__":
    main()
