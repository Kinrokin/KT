from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


class LatentTagError(RuntimeError):
    pass


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LatentTagError(f"Missing required input: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise LatentTagError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _read_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return _load_json(path)


def _observability_level(coverage: Dict[str, Any], motion: Optional[Dict[str, Any]]) -> str:
    seq = coverage.get("sequence") or []
    if motion is not None and len(seq) >= 2:
        return "HIGH"
    if len(seq) >= 1:
        return "MED"
    return "LOW"


def _confidence(level: str) -> float:
    return {"HIGH": 0.9, "MED": 0.6, "LOW": 0.3}.get(level, 0.3)


def _derive_tags(summary: Dict[str, Any], coverage: Dict[str, Any], observability: str) -> List[str]:
    tags: List[str] = []
    verdict = summary.get("epoch_verdict")
    profile = summary.get("epoch_profile")

    if profile:
        tags.append(f"PROFILE_{profile}")
    if verdict:
        tags.append(f"VERDICT_{verdict}")

    passed = int(summary.get("crucibles_passed", 0))
    total = int(summary.get("crucibles_total", 0))
    if total > 0 and passed == total:
        tags.append("ALL_PASS")
    elif passed > 0:
        tags.append("PARTIAL_PASS")
    else:
        tags.append("NO_PASS")

    if observability == "LOW":
        tags.append("LOW_OBSERVABILITY")

    dominance = (coverage.get("observed") or {}).get("dominance") or {}
    if float(dominance.get("top_domain_share", 0.0)) >= 0.9:
        tags.append("DOMAIN_DOMINANCE")

    if float(dominance.get("entropy_domains", 0.0)) == 0.0:
        tags.append("ENTROPY_ZERO")

    return sorted(set(tags))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True))
        handle.write("\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Latent tagger (tooling-only, observational).")
    p.add_argument("--epoch-root", action="append", help="Epoch artifact root (repeatable).")
    p.add_argument("--epochs-dir", help="Directory containing epoch artifact roots.")
    p.add_argument("--ledger-out", help="Optional append-only latent tags JSONL path.")
    return p.parse_args()


def _discover_epochs(epochs_dir: Path) -> List[Path]:
    if not epochs_dir.exists():
        raise LatentTagError(f"epochs dir missing: {epochs_dir.as_posix()} (fail-closed)")
    roots = [p for p in epochs_dir.iterdir() if p.is_dir()]
    return sorted(roots, key=lambda p: p.name)


def main() -> int:
    args = _parse_args()
    epoch_roots: List[Path] = []
    if args.epoch_root:
        epoch_roots.extend(Path(p).resolve() for p in args.epoch_root)
    if args.epochs_dir:
        epoch_roots.extend(_discover_epochs(Path(args.epochs_dir).resolve()))

    if not epoch_roots:
        raise LatentTagError("No epoch roots provided (fail-closed)")

    epoch_roots = sorted(set(epoch_roots), key=lambda p: p.name)
    ledger_rows: List[Dict[str, Any]] = []

    for root in epoch_roots:
        summary = _load_json(root / "epoch_summary.json")
        coverage = _load_json(root / "epoch_coverage.json")
        motion = _read_optional(root / "motion_metrics.json")
        transitions = _read_optional(root / "transitions.json")

        observability = _observability_level(coverage, motion)
        payload = {
            "schema": "LATENT_TAGS_V1",
            "epoch_id": summary.get("epoch_id"),
            "epoch_hash": summary.get("epoch_hash"),
            "epoch_profile": summary.get("epoch_profile"),
            "epoch_verdict": summary.get("epoch_verdict"),
            "kernel_target": (summary.get("kernel_identity") or {}).get("kernel_target"),
            "observability_level": observability,
            "confidence": _confidence(observability),
            "tags": _derive_tags(summary, coverage, observability),
            "signals": {
                "crucibles_total": int(summary.get("crucibles_total", 0)),
                "crucibles_passed": int(summary.get("crucibles_passed", 0)),
                "crucibles_failed_closed": int(summary.get("crucibles_failed_closed", 0)),
                "unique_domains": int((coverage.get("observed") or {}).get("counts", {}).get("unique_domains", 0)),
                "entropy_domains": float((coverage.get("observed") or {}).get("dominance", {}).get("entropy_domains", 0.0)),
                "sequence_len": len(coverage.get("sequence") or []),
                "motion_present": motion is not None,
                "transitions_present": transitions is not None,
            },
        }

        _write_json(root / "latent_tags.json", payload)
        ledger_rows.append(payload)

    if args.ledger_out:
        _append_jsonl(Path(args.ledger_out), ledger_rows)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LatentTagError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
