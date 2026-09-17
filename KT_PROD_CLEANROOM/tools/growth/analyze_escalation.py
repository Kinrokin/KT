import json
import math
import os
import re
from collections import Counter
from pathlib import Path

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_RESERVED_DEVICE_BASENAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}

def _is_reserved_device_name(value: str) -> bool:
    return value.split(".", 1)[0].upper() in _RESERVED_DEVICE_BASENAMES


def _growth_artifacts_root() -> Path:
    override = (os.getenv("KT_GROWTH_ARTIFACTS_ROOT") or "").strip()
    if not override:
        return _CLEANROOM_ROOT / "tools" / "growth" / "artifacts"
    root = Path(override)
    if not root.is_absolute():
        root = _CLEANROOM_ROOT / root
    return root.resolve()


def _artifact_epochs_root() -> Path:
    return _growth_artifacts_root() / "epochs"


def _epoch_escalation_log_path() -> Path:
    return _growth_artifacts_root() / "logs" / "epoch_escalation_log.json"


def _safe_epoch_dir(epochs_root: Path, value: object) -> Path:
    if (
        not isinstance(value, str)
        or _SAFE_COMPONENT.fullmatch(value) is None
        or value.endswith((".", " "))
        or _is_reserved_device_name(value)
    ):
        raise ValueError("unsafe_epoch_path_component")
    resolved_root = epochs_root.resolve()
    epoch_dir = (resolved_root / value).resolve()
    try:
        epoch_dir.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("unsafe_epoch_path_containment") from exc
    return epoch_dir


def _safe_epoch_evidence(epoch_dir: Path, path: Path) -> Path:
    resolved_epoch = epoch_dir.resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(resolved_epoch)
    except ValueError as exc:
        raise ValueError("unsafe_epoch_evidence_path_containment") from exc
    return candidate


def entropy(domains):
    if not domains:
        return 0.0
    counts = Counter(domains)
    total = sum(counts.values())
    return -sum((count / total) * math.log(count / total, 2) for count in counts.values() if count)


def micro_stats(epoch_dir):
    micro = []
    for ms in epoch_dir.glob("CRU-*/micro_steps.json"):
        evidence_path = _safe_epoch_evidence(epoch_dir, ms)
        try:
            data = json.loads(evidence_path.read_text())
        except Exception:
            continue
        steps = data.get("steps", data if isinstance(data, list) else [])
        micro.extend(steps)
    domains = [s.get("domain") for s in micro if s.get("domain")]
    return entropy(domains), len(set(domains))


def run():
    epochs = _artifact_epochs_root()
    records = json.loads(_epoch_escalation_log_path().read_text())
    stats = {"next": [], "reanchor": [], "stabilize": []}
    for rec in records:
        epoch_dir = _safe_epoch_dir(epochs, rec["epoch"])
        summary_path = _safe_epoch_evidence(epoch_dir, epoch_dir / "epoch_summary.json")
        summary = json.loads(summary_path.read_text())
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
            ent, _ = micro_stats(_safe_epoch_dir(epochs, future["epoch"]))
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
