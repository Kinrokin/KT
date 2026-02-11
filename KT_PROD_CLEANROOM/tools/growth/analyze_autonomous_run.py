import json
import statistics
from collections import Counter, defaultdict
from math import isfinite
from pathlib import Path

ROOT = Path("KT_PROD_CLEANROOM")
LOG_PATH = Path("autonomous_escalation_log.json")
EPOCHS = ROOT / "tools" / "growth" / "artifacts" / "epochs"
C019_RUNS = ROOT / "tools" / "growth" / "artifacts" / "c019_runs"


def load_records():
    if not LOG_PATH.exists():
        raise FileNotFoundError("autonomous_escalation_log.json missing")
    return json.loads(LOG_PATH.read_text())


def transition_stats(records):
    transitions = Counter()
    prev_plan = None
    for rec in records:
        plan = rec["plan_run"]
        if prev_plan is not None:
            transitions[(prev_plan, plan)] += 1
        prev_plan = plan
    return transitions


def forced_low_distribution(records):
    forced = [rec["forced"] for rec in records]
    low = [rec["low_coherence"] for rec in records]
    return {
        "forced_total": sum(forced),
        "forced_mean": statistics.mean(forced) if forced else 0,
        "low_total": sum(low),
        "low_mean": statistics.mean(low) if low else 0,
    }


def recovery_lengths(records):
    lengths = []
    for idx, rec in enumerate(records):
        if rec["plan_run"] != "coverage":
            continue
        steps = 0
        for future in records[idx + 1 :]:
            steps += 1
            if future["plan_run"] == "reanchor":
                lengths.append(steps)
                break
    return lengths


def entropy_curve(records):
    return [
        {"iteration": rec["iteration"], "plan": rec["plan_run"], "entropy": rec["entropy"]}
        for rec in records
    ]


def find_runner_record(run_id: str) -> Path | None:
    for kernel_dir in C019_RUNS.iterdir():
        candidate = kernel_dir / run_id / "runner_record.json"
        if candidate.exists():
            return candidate
    return None


def duration_stats(records):
    durations_by_plan = defaultdict(list)
    for rec in records:
        epoch_dir = EPOCHS / rec["epoch"]
        try:
            summary = json.loads((epoch_dir / "epoch_summary.json").read_text())
        except Exception:
            continue
        total = 0
        count = 0
        for run in summary.get("runs", []):
            run_id = run.get("run_id")
            if not run_id:
                continue
            record_path = find_runner_record(run_id)
            if not record_path:
                continue
            rr = json.loads(record_path.read_text())
            duration = rr.get("duration_ms")
            if isinstance(duration, (int, float)):
                total += duration
                count += 1
        if count:
            durations_by_plan[rec["plan_run"]].append(total / count)
    summary = {}
    for plan, values in durations_by_plan.items():
        if not values:
            continue
        summary[plan] = {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "pstdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        }
    return summary


def main():
    records = load_records()
    transitions = transition_stats(records)
    forced_low = forced_low_distribution(records)
    recovery = recovery_lengths(records)
    durations = duration_stats(records)

    output = {
        "summary": {
            "total_runs": len(records),
            "lane_transitions": {f"{k[0]}->{k[1]}": v for k, v in transitions.items()},
            "forced/low_distribution": forced_low,
            "recovery_steps": recovery,
            "entropies": entropy_curve(records),
            "duration_stats": durations,
        }
    }

    Path("autonomous_analysis.json").write_text(json.dumps(output, indent=2))
    print("Analysis written to autonomous_analysis.json")


if __name__ == "__main__":
    main()
