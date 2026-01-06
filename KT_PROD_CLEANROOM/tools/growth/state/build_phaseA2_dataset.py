import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class PhaseA2BuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class EpochRow:
    root: Path
    epoch_id: str
    lane_actual: str
    unique_domains: int
    unique_subdomains: int
    entropy_domains: float
    top_domain_share: float
    forced_resolve_count: int
    low_coherence_count: int


LANE_COVERAGE = "coverage_lane"
LANE_REANCHOR = "reanchor_lane"
LANE_STABILIZE = "stabilize_lane"
LANE_HOLD_COVERAGE = "hold_coverage_lane"  # NEW in Phase A.2


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PhaseA2BuildError(f"Missing required input: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise PhaseA2BuildError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _read_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return _load_json(path)


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


def _discover_epochs(epochs_dir: Path) -> List[Path]:
    if not epochs_dir.exists():
        raise PhaseA2BuildError(f"epochs dir missing: {epochs_dir.as_posix()} (fail-closed)")
    roots = [p for p in epochs_dir.iterdir() if p.is_dir()]
    if not roots:
        raise PhaseA2BuildError(f"epochs dir empty: {epochs_dir.as_posix()} (fail-closed)")
    return roots


def _mtime_key(path: Path) -> Tuple[float, str]:
    return (path.stat().st_mtime, path.name)


def _lane_from_epoch_id(epoch_id: str) -> str:
    e = (epoch_id or "").upper()
    if e.startswith("EPOCH_REANCHOR_CONSTRAINT"):
        return LANE_REANCHOR
    if e.startswith("EPOCH_STABILIZE"):
        return LANE_STABILIZE
    if e.startswith("EPOCH_NEXT_AUTO") or e.startswith("EPOCH_COVERAGE"):
        return LANE_COVERAGE
    # Fail-closed: unknown lane types should not be silently coerced.
    raise PhaseA2BuildError(f"Unknown epoch_id lane prefix: {epoch_id} (fail-closed)")


def _collect_micro_steps(epoch_root: Path) -> Optional[List[Dict[str, Any]]]:
    steps: List[Dict[str, Any]] = []
    for path in sorted(epoch_root.glob("CRU_*/micro_steps.json"), key=lambda p: p.name):
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
        return steps
    root_micro = _read_optional_json(epoch_root / "micro_steps.json")
    if isinstance(root_micro, dict):
        chunk = root_micro.get("steps")
        if isinstance(chunk, list):
            return [e for e in chunk if isinstance(e, dict)]
    return None


def _count_micro_flags(steps: Optional[List[Dict[str, Any]]]) -> Tuple[int, int]:
    if not steps:
        return (0, 0)
    forced = 0
    low = 0
    for s in steps:
        flags = s.get("flags") or {}
        mode = flags.get("resolve_mode")
        if mode in {"forced", "partial", "unresolved", "refuse"}:
            forced += 1
        if flags.get("coherence_bucket") == "LOW":
            low += 1
    return (forced, low)


def _extract_row(epoch_root: Path) -> EpochRow:
    summary = _load_json(epoch_root / "epoch_summary.json")
    coverage = _load_json(epoch_root / "epoch_coverage.json")
    micro_steps = _collect_micro_steps(epoch_root)

    epoch_id = str(summary.get("epoch_id") or epoch_root.name)
    lane_actual = _lane_from_epoch_id(epoch_id)

    observed = coverage.get("observed") or {}
    counts = observed.get("counts") or {}
    dominance = observed.get("dominance") or {}

    unique_domains = _coerce_int(counts.get("unique_domains"))
    unique_subdomains = _coerce_int(counts.get("unique_subdomains"))
    entropy_domains = _coerce_float(dominance.get("entropy_domains"))
    top_domain_share = _coerce_float(dominance.get("top_domain_share"))

    forced, low = _count_micro_flags(micro_steps)

    return EpochRow(
        root=epoch_root,
        epoch_id=epoch_id,
        lane_actual=lane_actual,
        unique_domains=unique_domains,
        unique_subdomains=unique_subdomains,
        entropy_domains=entropy_domains,
        top_domain_share=top_domain_share,
        forced_resolve_count=forced,
        low_coherence_count=low,
    )


def _entropy_high(row: EpochRow) -> bool:
    return (row.entropy_domains >= 0.80) and (row.unique_domains >= 2)


def _clean(row: EpochRow) -> bool:
    return (row.forced_resolve_count == 0) and (row.low_coherence_count == 0)


def _state_text(row: EpochRow) -> str:
    return "\n".join(
        [
            "KT_STATE_V1",
            f"forced_resolve_count={row.forced_resolve_count}",
            f"low_coherence_count={row.low_coherence_count}",
            f"unique_domains={row.unique_domains}",
            f"unique_subdomains={row.unique_subdomains}",
            f"entropy_domains={row.entropy_domains}",
            f"top_domain_share={row.top_domain_share}",
        ]
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build KT Phase A.2 dataset (label semantics repair; fail-closed).")
    p.add_argument(
        "--epochs-dir",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/artifacts/epochs"),
        help="Epoch artifacts directory (read-only input).",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/bench/kt_phaseA2_dataset.jsonl"),
        help="Output dataset JSONL path.",
    )
    p.add_argument(
        "--label-map-out",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/state/kt_phaseA2_label_map.json"),
        help="Output label map JSON path.",
    )
    p.add_argument(
        "--report-out",
        type=Path,
        default=Path("KT_PROD_CLEANROOM/tools/growth/state/kt_phaseA2_build_report.json"),
        help="Output build report JSON path.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="If >0, only consider the latest N epochs by mtime.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    epochs_dir = args.epochs_dir.resolve()
    roots = _discover_epochs(epochs_dir)
    roots = sorted(roots, key=_mtime_key)
    if args.limit and args.limit > 0:
        roots = roots[-int(args.limit) :]

    if len(roots) < 3:
        raise PhaseA2BuildError("Need >=3 epochs to label using next-epoch observation (fail-closed)")

    rows: List[EpochRow] = []
    skipped: List[Dict[str, Any]] = []
    for r in roots:
        try:
            rows.append(_extract_row(r))
        except Exception as exc:
            skipped.append({"epoch_root": r.as_posix(), "reason": str(exc)})

    if len(rows) < 3:
        raise PhaseA2BuildError("Insufficient readable epochs after extraction (fail-closed)")

    out_path = args.out.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    label_set = {LANE_COVERAGE, LANE_REANCHOR, LANE_STABILIZE, LANE_HOLD_COVERAGE}
    label_list = [LANE_COVERAGE, LANE_REANCHOR, LANE_STABILIZE, LANE_HOLD_COVERAGE]
    label2id = {k: i for i, k in enumerate(label_list)}
    id2label = {str(i): k for i, k in enumerate(label_list)}

    wrote = 0
    relabeled = 0
    counts: Dict[str, int] = {k: 0 for k in label_list}

    # Use next-epoch lane as the base label, then refine coverage->hold_coverage for restraint cases.
    with out_path.open("w", encoding="utf-8", newline="\n") as handle:
        for i in range(len(rows) - 1):
            curr = rows[i]
            nxt = rows[i + 1]

            phaseA_label = nxt.lane_actual
            if phaseA_label not in label_set:
                skipped.append(
                    {
                        "epoch_id": curr.epoch_id,
                        "next_epoch_id": nxt.epoch_id,
                        "reason": f"Unknown next lane: {phaseA_label}",
                    }
                )
                continue

            phaseA2_label = phaseA_label
            relabel_reason = None

            if phaseA_label == LANE_COVERAGE:
                if _entropy_high(curr) and _clean(curr) and _clean(nxt):
                    phaseA2_label = LANE_HOLD_COVERAGE
                    relabel_reason = "entropy_high_clean_and_next_coverage_clean"

            counts[phaseA2_label] = counts.get(phaseA2_label, 0) + 1
            wrote += 1
            if phaseA2_label != phaseA_label:
                relabeled += 1

            record = {
                "schema": "KT_PHASE_A2_DATASET_V1",
                "epoch_id": curr.epoch_id,
                "epoch_root": curr.root.as_posix(),
                "next_epoch_id": nxt.epoch_id,
                "next_epoch_root": nxt.root.as_posix(),
                "phaseA_label": phaseA_label,
                "phaseA2_label": phaseA2_label,
                "relabel_reason": relabel_reason,
                "signals": {
                    "entropy_domains": curr.entropy_domains,
                    "top_domain_share": curr.top_domain_share,
                    "unique_domains": curr.unique_domains,
                    "unique_subdomains": curr.unique_subdomains,
                    "forced_resolve_count": curr.forced_resolve_count,
                    "low_coherence_count": curr.low_coherence_count,
                },
                "next_signals": {
                    "entropy_domains": nxt.entropy_domains,
                    "top_domain_share": nxt.top_domain_share,
                    "unique_domains": nxt.unique_domains,
                    "unique_subdomains": nxt.unique_subdomains,
                    "forced_resolve_count": nxt.forced_resolve_count,
                    "low_coherence_count": nxt.low_coherence_count,
                },
                "state_text": _state_text(curr),
            }
            handle.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

    args.label_map_out.parent.mkdir(parents=True, exist_ok=True)
    args.label_map_out.write_text(
        json.dumps(
            {
                "phase": "PHASE_A2",
                "schema": "KT_LABEL_MAP_V1",
                "label_list": label_list,
                "label2id": label2id,
                "id2label": id2label,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        json.dumps(
            {
                "epochs_dir": epochs_dir.as_posix(),
                "epochs_considered": len(roots),
                "epochs_extracted": len(rows),
                "dataset_out": out_path.as_posix(),
                "rows_written": wrote,
                "rows_relabeled_to_hold_coverage": relabeled,
                "label_counts": counts,
                "skipped": skipped[:200],
                "skipped_count": len(skipped),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(json.dumps({"rows_written": wrote, "rows_relabeled": relabeled, "out": out_path.as_posix()}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PhaseA2BuildError as exc:
        print(str(exc))
        raise SystemExit(2)

