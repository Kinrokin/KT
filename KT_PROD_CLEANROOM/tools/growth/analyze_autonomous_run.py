import json
import os
import statistics
from collections import Counter, defaultdict
from math import isfinite
from pathlib import Path

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]


def _growth_artifacts_root() -> Path:
    override = (os.getenv("KT_GROWTH_ARTIFACTS_ROOT") or "").strip()
    if not override:
        return _CLEANROOM_ROOT / "tools" / "growth" / "artifacts"
    root = Path(override)
    if not root.is_absolute():
        root = _CLEANROOM_ROOT / root
    return root.resolve()


def _autonomous_log_path() -> Path:
    return _growth_artifacts_root() / "logs" / "autonomous_escalation_log.json"


def _artifact_epochs_root() -> Path:
    return _growth_artifacts_root() / "epochs"


def _c019_runs_root() -> Path:
    return _growth_artifacts_root() / "c019_runs"


def _analysis_path() -> Path:
    return _growth_artifacts_root() / "reports" / "autonomous_analysis.json"


def load_records():
    log_path = _autonomous_log_path()
    if not log_path.exists():
        raise FileNotFoundError(f"autonomous escalation log missing: {log_path}")
    return json.loads(log_path.read_text())


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
    c019_runs = _c019_runs_root()
    if not c019_runs.is_dir():
        return None
    for kernel_dir in c019_runs.iterdir():
        candidate = kernel_dir / run_id / "runner_record.json"
        if candidate.exists():
            return candidate
    return None


def duration_stats(records):
    durations_by_plan = defaultdict(list)
    epochs = _artifact_epochs_root()
    for rec in records:
        epoch_dir = epochs / rec["epoch"]
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

    analysis_path = _analysis_path()
    analysis_path.parent.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Analysis written to {analysis_path}")


if __name__ == "__main__":
    main()
