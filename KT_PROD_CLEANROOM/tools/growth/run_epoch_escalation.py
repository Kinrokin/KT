import json
import os
import sys
from pathlib import Path

ROOT = Path("KT_PROD_CLEANROOM")
ARTIFACT_EPOCHS = ROOT / "tools" / "growth" / "artifacts" / "epochs"

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_orchestrator import run_epoch_from_plan

PLAN_FILES = {
    "next": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_NEXT_AUTO.json",
    "reanchor": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_REANCHOR_CONSTRAINT.json",
    "stabilize": ROOT / "tools" / "growth" / "orchestrator" / "examples" / "EPOCH_STABILIZE.json",
}


def find_latest_epoch() -> Path:
    dirs = [p for p in ARTIFACT_EPOCHS.iterdir() if p.is_dir()]
    if not dirs:
        raise RuntimeError("no epoch directories found")
    return max(dirs, key=lambda p: p.stat().st_mtime)


def inspect_micro_steps(epoch_root: Path):
    forced = 0
    low = 0
    steps_seen = 0
    for ms_path in epoch_root.glob("CRU_*/micro_steps.json"):
        try:
            payload = json.loads(ms_path.read_text())
        except Exception:
            continue
        data = payload.get("steps", payload if isinstance(payload, list) else [])
        for step in data:
            steps_seen += 1
            flags = step.get("flags", {}) or {}
            if flags.get("resolve_mode") in ("forced", "partial", "refuse"):
                forced += 1
            if flags.get("coherence_bucket") == "LOW":
                low += 1
    return steps_seen, forced, low


def run_epoch(plan_key: str, env: dict):
    plan_path = PLAN_FILES[plan_key]
    print(f"\n=== RUNNING PLAN {plan_key.upper()} ({plan_path.name}) ===")
    os.environ.update(env)
    run_epoch_from_plan(plan_path=plan_path, resume=False, mode="salvage")


def main():
    env = os.environ.copy()
    env["KT_LIVE"] = "0"
    env["KT_LIVE_PROOF"] = ""

    current_plan = "next"
    bad_streak = 0
    records = []

    for idx in range(1, 31):
        print(f"\n=== ESCALATION RUN {idx}/30 (plan {current_plan}) ===")
        run_epoch(current_plan, env)
        latest = find_latest_epoch()
        steps, forced, low = inspect_micro_steps(latest)
        bad = forced > 0 or low > 0
        record = {
            "run": idx,
            "plan": current_plan,
            "epoch": latest.name,
            "steps": steps,
            "forced": forced,
            "low_coherence": low,
            "bad": bad,
        }
        records.append(record)
        print(
            f"{latest.name}: steps={steps}, forced={forced}, low_coherence={low}, "
            f"bad={bad}"
        )
        if bad:
            bad_streak += 1
        else:
            bad_streak = 0
        if bad_streak >= 2:
            current_plan = "stabilize"
        elif bad_streak == 1:
            current_plan = "reanchor"
        else:
            current_plan = "next"

    summary = {
        "total_runs": len(records),
        "bad_runs": sum(1 for r in records if r["bad"]),
        "forced_total": sum(r["forced"] for r in records),
        "low_total": sum(r["low_coherence"] for r in records),
    }
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    detail_path = Path("epoch_escalation_log.json")
    detail_path.write_text(json.dumps(records, indent=2))
    print(f"Details saved to {detail_path}")


if __name__ == "__main__":
    main()
