from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SHA256_RX = re.compile(r"^[a-f0-9]{64}$")
REQUIRED_RECEIPT_TYPES = {"TRACE_HEAD_HASH", "LEDGER_ENTRY_HASH"}


class BenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class EpochInputs:
    root: Path
    manifest: Dict[str, Any]
    summary: Dict[str, Any]
    coverage: Dict[str, Any]


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BenchmarkError(f"Missing required input: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise BenchmarkError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _require_epoch_inputs(root: Path) -> EpochInputs:
    manifest_path = root / "epoch_manifest.json"
    summary_path = root / "epoch_summary.json"
    coverage_path = root / "epoch_coverage.json"

    manifest = _load_json(manifest_path)
    summary = _load_json(summary_path)
    coverage = _load_json(coverage_path)

    _assert_receipts_ok(coverage)
    return EpochInputs(root=root, manifest=manifest, summary=summary, coverage=coverage)


def _assert_receipts_ok(coverage: Dict[str, Any]) -> None:
    proof = coverage.get("proof", {})
    receipts = proof.get("receipts", [])
    present = {r.get("type") for r in receipts if isinstance(r, dict)}
    if not REQUIRED_RECEIPT_TYPES.issubset(present):
        missing = REQUIRED_RECEIPT_TYPES - present
        raise BenchmarkError(f"Missing required receipts: {sorted(missing)} (fail-closed)")

    for rec in receipts:
        if not isinstance(rec, dict):
            raise BenchmarkError("Receipt entry is not an object (fail-closed)")
        sha = rec.get("sha256")
        if not isinstance(sha, str) or not SHA256_RX.match(sha):
            raise BenchmarkError("Receipt sha256 missing or invalid (fail-closed)")


def _score_epoch(inputs: EpochInputs) -> Dict[str, Any]:
    summary = inputs.summary
    coverage = inputs.coverage

    total = int(summary.get("crucibles_total", 0))
    passed = int(summary.get("crucibles_passed", 0))
    failed_closed = int(summary.get("crucibles_failed_closed", 0))
    failed = int(summary.get("crucibles_failed", 0))

    pass_rate = (passed / total) if total else 0.0
    failed_closed_rate = (failed_closed / total) if total else 0.0
    failed_rate = (failed / total) if total else 0.0

    observed = coverage.get("observed", {})
    counts = observed.get("counts", {})
    dominance = observed.get("dominance", {})

    return {
        "epoch_id": summary.get("epoch_id"),
        "epoch_hash": summary.get("epoch_hash"),
        "epoch_profile": summary.get("epoch_profile"),
        "epoch_verdict": summary.get("epoch_verdict"),
        "kernel_target": (summary.get("kernel_identity") or {}).get("kernel_target"),
        "crucibles_total": total,
        "crucibles_passed": passed,
        "crucibles_failed_closed": failed_closed,
        "crucibles_failed": failed,
        "pass_rate": round(pass_rate, 6),
        "failed_closed_rate": round(failed_closed_rate, 6),
        "failed_rate": round(failed_rate, 6),
        "coverage": {
            "unique_domains": int(counts.get("unique_domains", 0)),
            "unique_subdomains": int(counts.get("unique_subdomains", 0)),
            "unique_microdomains": int(counts.get("unique_microdomains", 0)),
            "cross_domain_edges": int(counts.get("cross_domain_edges", 0)),
            "mean_graph_distance": float(counts.get("mean_graph_distance", 0.0)),
            "max_graph_distance": int(counts.get("max_graph_distance", 0)),
            "entropy_domains": float(dominance.get("entropy_domains", 0.0)),
            "top_domain_share": float(dominance.get("top_domain_share", 0.0)),
            "top_5_domain_share": float(dominance.get("top_5_domain_share", 0.0)),
        },
        "receipt_proof_ok": True,
    }


def _stability_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    hashes = [r.get("epoch_hash") for r in rows if r.get("epoch_hash")]
    unique_hashes = sorted(set(hashes))
    return {
        "epochs": len(rows),
        "unique_epoch_hashes": len(unique_hashes),
        "all_same": len(unique_hashes) <= 1,
    }


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")


def _append_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True))
            handle.write("\n")


def _discover_epochs(epochs_dir: Path) -> List[Path]:
    if not epochs_dir.exists():
        raise BenchmarkError(f"epochs dir missing: {epochs_dir.as_posix()} (fail-closed)")
    roots = [p for p in epochs_dir.iterdir() if p.is_dir()]
    return sorted(roots, key=lambda p: p.name)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Benchmark scorer (tooling-only, fail-closed).")
    p.add_argument("--epoch-root", action="append", help="Epoch artifact root (repeatable).")
    p.add_argument("--epochs-dir", help="Directory containing epoch artifact roots.")
    p.add_argument("--out", required=True, help="benchmark_summary.json output path.")
    p.add_argument("--timeseries-out", help="Optional append-only timeseries JSONL output path.")
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    epoch_roots: List[Path] = []
    if args.epoch_root:
        epoch_roots.extend(Path(p).resolve() for p in args.epoch_root)
    if args.epochs_dir:
        epoch_roots.extend(_discover_epochs(Path(args.epochs_dir).resolve()))

    if not epoch_roots:
        raise BenchmarkError("No epoch roots provided (fail-closed)")

    epoch_roots = sorted(set(epoch_roots), key=lambda p: p.name)
    inputs = [_require_epoch_inputs(p) for p in epoch_roots]
    rows = [_score_epoch(i) for i in inputs]

    summary = {
        "schema": "BENCHMARK_SUMMARY_V1",
        "epoch_count": len(rows),
        "stability": _stability_summary(rows),
        "epochs": rows,
    }

    _write_json(Path(args.out), summary)

    if args.timeseries_out:
        _append_jsonl(Path(args.timeseries_out), rows)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
