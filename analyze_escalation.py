import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path("KT_PROD_CLEANROOM")
EPOCHS = ROOT / "tools" / "growth" / "artifacts" / "epochs"
LOG_PATH = Path("epoch_escalation_log.json")


def entropy(domains):
    if not domains:
        return 0.0
    counts = Counter(domains)
    total = sum(counts.values())
    return -sum((count / total) * math.log(count / total, 2) for count in counts.values() if count)


def micro_stats(epoch_dir):
    micro = []
    for ms in epoch_dir.glob("CRU_*/micro_steps.json"):
        try:
            data = json.loads(ms.read_text())
        except Exception:
            continue
        steps = data.get("steps", data if isinstance(data, list) else [])
        micro.extend(steps)
    domains = [s.get("domain") for s in micro if s.get("domain")]
    return entropy(domains), len(set(domains))


def run():
    records = json.loads(LOG_PATH.read_text())
    stats = {"next": [], "reanchor": [], "stabilize": []}
    for rec in records:
        epoch_dir = EPOCHS / rec["epoch"]
        summary = json.loads((epoch_dir / "epoch_summary.json").read_text())
        fail_closed = summary.get("crucibles_failed_closed", 0) > 0
        ent, uniq = micro_stats(epoch_dir)
        wasted = ent == 0 or uniq < 2
        stats[rec["plan"]].append(
            {
                "fail_closed": fail_closed,
                "entropy": ent,
                "unique_domains": uniq,
                "wasted": wasted,
            }
        )

    for plan, items in stats.items():
        if not items:
            continue
        n = len(items)
        fail_rate = sum(item["fail_closed"] for item in items) / n
        avg_entropy = sum(item["entropy"] for item in items) / n
        wasted = sum(item["wasted"] for item in items)
        print(f"{plan.upper()}: runs={n}, fail_rate={fail_rate:.2f}, avg_entropy={avg_entropy:.3f}, wasted={wasted}")

    entropy_recovery = []
    for idx, rec in enumerate(records):
        if not rec["bad"]:
            continue
        steps = 0
        for future in records[idx + 1 :]:
            steps += 1
            ent, _ = micro_stats(EPOCHS / future["epoch"])
            if ent > 0:
                entropy_recovery.append(steps)
                break
    print("Entropy recovery steps (bad->entropy>0):", entropy_recovery)
    if entropy_recovery:
        print("avg recovery steps:", sum(entropy_recovery) / len(entropy_recovery))

    wasted_total = sum(
        sum(1 for item in stats[plan] if item["wasted"]) for plan in stats if stats[plan]
    )
    print("Total wasted epochs:", wasted_total)


if __name__ == "__main__":
    run()
