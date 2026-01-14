import argparse
import json
import math
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
    coherence_debt: int
    coherence_budget: float
    coherence_debt_present: bool
    regret_global: Optional[float]
    regret_skip_reason: Optional[str]
    unique_domains: int
    unique_subdomains: int
    entropy_domains: float
    top_domain_share: float
    forced_resolve_count: int
    low_coherence_count: int
    unknown_resolve_count: int
    unknown_coherence_count: int
    micro_present: bool
    entropy_present: bool


LANE_COVERAGE = "coverage_lane"
LANE_REANCHOR = "reanchor_lane"
LANE_STABILIZE = "stabilize_lane"
LANE_HOLD_COVERAGE = "hold_coverage_lane"  # NEW in Phase A.2
POLICY_B_REGISTRY_PATH = Path("KT_PROD_CLEANROOM/tools/growth/state/policy_b_variable_registry.json")


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


def _load_policy_b_registry() -> Dict[str, Any]:
    registry = _load_json(POLICY_B_REGISTRY_PATH)
    if registry.get("schema") != "POLICY_B_VARIABLE_REGISTRY_V1":
        raise PhaseA2BuildError("policy_b_variable_registry.json schema mismatch (fail-closed)")
    if registry.get("version") != 1:
        raise PhaseA2BuildError("policy_b_variable_registry.json version mismatch (fail-closed)")
    return registry


def _policy_b_values(registry: Dict[str, Any]) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for entry in registry.get("variables", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        values[name] = entry.get("policy_b_value")
    for key in ("paradox_handling", "governance_invariants"):
        if key in registry:
            values[key] = registry.get(key)
    return values


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
    if e.startswith("EPOCH_NEXT_AUTO") or e.startswith("EPOCH_COVERAGE") or e.startswith("EPOCH_ACCEPTANCE") or e.startswith("EPOCH_PASS"):
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


def _count_micro_flags(steps: Optional[List[Dict[str, Any]]]) -> Tuple[int, int, int, int]:
    if not steps:
        return (0, 0, 0, 0)
    forced = 0
    low = 0
    unknown_resolve = 0
    unknown_coh = 0
    for s in steps:
        flags = s.get("flags") or {}
        mode = flags.get("resolve_mode")
        if mode in {"forced", "partial", "unresolved", "refuse"}:
            forced += 1
        elif mode in {"unknown", "UNKNOWN", "missing", "MISSING"}:
            unknown_resolve += 1
        if flags.get("coherence_bucket") == "LOW":
            low += 1
        elif flags.get("coherence_bucket") in {"UNKNOWN", "unknown", "MISSING", "missing"}:
            unknown_coh += 1
    return (forced, low, unknown_resolve, unknown_coh)


def _entropy_from_domains(domains: List[str]) -> Tuple[float, float, int]:
    """
    Compute normalized entropy (0..1) and top-domain share from domain sequence.
    Normalization uses log(N) where N is the number of unique domains so that
    entropy=1.0 only when domains are evenly represented.
    """
    if not domains:
        return (0.0, 0.0, 0)
    counts: Dict[str, int] = {}
    for d in domains:
        if not isinstance(d, str):
            continue
        counts[d] = counts.get(d, 0) + 1
    total = sum(counts.values())
    if total == 0:
        return (0.0, 0.0, 0)
    probs = [c / total for c in counts.values()]
    top_share = max(probs)
    if len(counts) == 1:
        return (0.0, top_share, 1)
    h = -sum(p * math.log(p) for p in probs)
    h_norm = h / math.log(len(counts))
    return (float(h_norm), float(top_share), len(counts))


def _extract_row(epoch_root: Path) -> EpochRow:
    summary_path = epoch_root / "epoch_summary.json"
    coverage_path = epoch_root / "epoch_coverage.json"
    summary = _load_json(summary_path)
    coverage = _load_json(coverage_path)
    micro_steps = _collect_micro_steps(epoch_root)
    regret = _read_optional_json(epoch_root / "epoch_regret.json") or {}

    epoch_id = str(summary.get("epoch_id") or epoch_root.name)
    lane_actual = _lane_from_epoch_id(epoch_id)
    coherence_debt_raw = summary.get("coherence_debt")
    coherence_budget_raw = summary.get("coherence_budget")
    coherence_debt_present = (coherence_debt_raw is not None) and (coherence_budget_raw is not None)
    coherence_debt = _coerce_int(coherence_debt_raw) if coherence_debt_raw is not None else -1
    coherence_budget = _coerce_float(coherence_budget_raw) if coherence_budget_raw is not None else -1.0
    regret_global = regret.get("regret_global")
    regret_skip_reason = regret.get("regret_skip_reason")
    try:
        regret_global = float(regret_global) if regret_global is not None else None
    except Exception:
        regret_global = None

    observed = coverage.get("observed") or {}
    counts = observed.get("counts") or {}
    dominance = observed.get("dominance") or {}
    seq = observed.get("sequence") or []

    entropy_present = False
    unique_domains = _coerce_int(counts.get("unique_domains"))
    unique_subdomains = _coerce_int(counts.get("unique_subdomains"))
    entropy_domains = _coerce_float(dominance.get("entropy_domains"))
    top_domain_share = _coerce_float(dominance.get("top_domain_share"))

    forced, low, unk_res, unk_coh = _count_micro_flags(micro_steps)

    # Prefer entropy derived from micro-steps; fall back to coverage sequence if available.
    domain_seq: List[str] = []
    if micro_steps:
        for s in micro_steps:
            dom = s.get("domain")
            if isinstance(dom, str) and dom:
                domain_seq.append(dom)
    if not domain_seq and seq and isinstance(seq, list):
        domain_seq = [str(d) for d in seq if isinstance(d, str)]

    if domain_seq:
        entropy_domains, top_domain_share, unique_domains = _entropy_from_domains(domain_seq)
        entropy_present = True
    elif ("entropy_domains" in dominance) and ("top_domain_share" in dominance):
        entropy_present = True

    return EpochRow(
        root=epoch_root,
        epoch_id=epoch_id,
        lane_actual=lane_actual,
        coherence_debt=coherence_debt,
        coherence_budget=coherence_budget,
        coherence_debt_present=coherence_debt_present,
        regret_global=regret_global,
        regret_skip_reason=regret_skip_reason if isinstance(regret_skip_reason, str) else None,
        unique_domains=unique_domains,
        unique_subdomains=unique_subdomains,
        entropy_domains=entropy_domains,
        top_domain_share=top_domain_share,
        forced_resolve_count=forced,
        low_coherence_count=low,
        unknown_resolve_count=unk_res,
        unknown_coherence_count=unk_coh,
        micro_present=micro_steps is not None,
        entropy_present=entropy_present,
    )


def _entropy_high(row: EpochRow) -> bool:
    # High structural dispersion only when domains are genuinely mixed and no single domain dominates.
    return (row.entropy_domains >= 0.75) and (row.unique_domains >= 2) and (row.top_domain_share <= 0.65)


def _clean(row: EpochRow) -> bool:
    return (
        (row.forced_resolve_count == 0)
        and (row.low_coherence_count == 0)
        and (row.unknown_resolve_count == 0)
        and (row.unknown_coherence_count == 0)
    )


def _state_text(row: EpochRow, policy_b_values: Dict[str, Any]) -> str:
    def _fmt_value(value: Any) -> str:
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return str(value)

    parts = [
        "KT_STATE_V1",
        f"coherence_debt={row.coherence_debt}",
        f"coherence_budget={row.coherence_budget}",
        f"regret_global={-1 if row.regret_global is None else row.regret_global}",
        f"forced_resolve_count={row.forced_resolve_count}",
        f"low_coherence_count={row.low_coherence_count}",
        f"unknown_resolve_count={row.unknown_resolve_count}",
        f"unknown_coherence_count={row.unknown_coherence_count}",
        f"unique_domains={row.unique_domains}",
        f"unique_subdomains={row.unique_subdomains}",
        f"entropy_domains={row.entropy_domains}",
        f"top_domain_share={row.top_domain_share}",
    ]
    for key in sorted(policy_b_values.keys()):
        parts.append(f"policy_b_{key}={_fmt_value(policy_b_values[key])}")
    return "\n".join(parts)


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
    policy_b_registry = _load_policy_b_registry()
    policy_b_values = _policy_b_values(policy_b_registry)
    roots = _discover_epochs(epochs_dir)
    roots = sorted(roots, key=_mtime_key)
    if args.limit and args.limit > 0:
        roots = roots[-int(args.limit) :]

    if len(roots) < 3:
        raise PhaseA2BuildError("Need >=3 epochs to label using next-epoch observation (fail-closed)")

    rows: List[EpochRow] = []
    skipped: List[Dict[str, Any]] = []
    skip_counts: Dict[str, int] = {}

    def skip(reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        skip_counts[reason] = skip_counts.get(reason, 0) + 1
        entry = {"reason": reason}
        if extra:
            entry.update(extra)
        skipped.append(entry)
    for r in roots:
        try:
            row = _extract_row(r)
        except Exception as exc:
            skip("extract_failed", {"epoch_root": r.as_posix(), "detail": str(exc)})
            continue

        if not row.micro_present:
            skip("missing_micro_steps_epoch_i", {"epoch_id": row.epoch_id})
            continue
        if not row.entropy_present:
            skip("ambiguous_entropy_epoch_i", {"epoch_id": row.epoch_id})
            continue
        rows.append(row)

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

            if not nxt.micro_present:
                skip("missing_micro_steps_epoch_i_plus_1", {"epoch_id": curr.epoch_id, "next_epoch_id": nxt.epoch_id})
                continue
            if not nxt.entropy_present:
                skip("ambiguous_entropy_epoch_i_plus_1", {"epoch_id": curr.epoch_id, "next_epoch_id": nxt.epoch_id})
                continue

            phaseA_label = nxt.lane_actual
            if phaseA_label not in label_set:
                skip(
                    "unknown_next_lane",
                    {"epoch_id": curr.epoch_id, "next_epoch_id": nxt.epoch_id, "lane": phaseA_label},
                )
                continue

            phaseA2_label = phaseA_label
            relabel_reason = None
            churn_curr = (
                curr.forced_resolve_count
                + curr.low_coherence_count
                + curr.unknown_resolve_count
                + curr.unknown_coherence_count
            )
            churn_nxt = (
                nxt.forced_resolve_count
                + nxt.low_coherence_count
                + nxt.unknown_resolve_count
                + nxt.unknown_coherence_count
            )
            churn_present = churn_curr >= 1
            churn_next_present = churn_nxt >= 1

            if phaseA_label == LANE_COVERAGE:
                # Hold coverage only when dispersion is genuinely high, current and next epochs are clean,
                # and there is no operational strain (churn) in either epoch.
                if _entropy_high(curr) and _clean(curr) and _clean(nxt) and (not churn_present) and (not churn_next_present):
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
                "policy_b_values": policy_b_values,
                "policy_b_registry_path": POLICY_B_REGISTRY_PATH.as_posix(),
                "phaseA_label": phaseA_label,
                "phaseA2_label": phaseA2_label,
                "relabel_reason": relabel_reason,
                "signals": {
                    "coherence_debt": curr.coherence_debt,
                    "coherence_budget": curr.coherence_budget,
                    "coherence_debt_present": curr.coherence_debt_present,
                    "regret_global": curr.regret_global,
                    "regret_skip_reason": curr.regret_skip_reason,
                    "entropy_domains": curr.entropy_domains,
                    "top_domain_share": curr.top_domain_share,
                    "unique_domains": curr.unique_domains,
                    "unique_subdomains": curr.unique_subdomains,
                    "forced_resolve_count": curr.forced_resolve_count,
                    "low_coherence_count": curr.low_coherence_count,
                    "unknown_resolve_count": curr.unknown_resolve_count,
                    "unknown_coherence_count": curr.unknown_coherence_count,
                    "churn_count": churn_curr,
                    "churn_present": churn_present,
                },
                "next_signals": {
                    "coherence_debt": nxt.coherence_debt,
                    "coherence_budget": nxt.coherence_budget,
                    "coherence_debt_present": nxt.coherence_debt_present,
                    "regret_global": nxt.regret_global,
                    "regret_skip_reason": nxt.regret_skip_reason,
                    "entropy_domains": nxt.entropy_domains,
                    "top_domain_share": nxt.top_domain_share,
                    "unique_domains": nxt.unique_domains,
                    "unique_subdomains": nxt.unique_subdomains,
                    "forced_resolve_count": nxt.forced_resolve_count,
                    "low_coherence_count": nxt.low_coherence_count,
                    "unknown_resolve_count": nxt.unknown_resolve_count,
                    "unknown_coherence_count": nxt.unknown_coherence_count,
                    "churn_count": churn_nxt,
                    "churn_present": churn_next_present,
                },
                "state_text": _state_text(curr, policy_b_values),
            }
            handle.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")

    total_labels = sum(counts.values())
    if total_labels > 0:
        max_share = max(counts.values()) / total_labels
        if max_share > 0.8:
            raise PhaseA2BuildError(
                f"Label collapse detected (fail-closed): max_share={max_share:.3f}, counts={counts}"
            )

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
    if args.report_out.parent:
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
                "skip_counts": skip_counts,
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
