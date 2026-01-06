from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any


def _infer_sequence_len(d: Dict[str, Any]) -> int:
    # Accept multiple representations of the executed sequence:
    # 1) Top-level explicit lengths
    explicit = d.get("sequence_len") or d.get("sequence_length") or d.get("trace_len") or 0
    try:
        explicit_i = int(explicit)
    except Exception:
        explicit_i = 0

    # 2) Top-level sequence list
    seq = d.get("sequence")
    if isinstance(seq, list):
        return max(explicit_i, len(seq))

    # 3) Nested sequence in common locations
    for key in ("coverage", "observed", "metrics", "trace"):
        sub = d.get(key)
        if isinstance(sub, Dict) and isinstance(sub.get("sequence"), list):
            return max(explicit_i, len(sub["sequence"]))

    return explicit_i


@dataclass(frozen=True)
class DreamEntry:
    path: Path
    payload: Dict[str, Any]

    @property
    def sequence_len(self) -> int:
        seq_len = _infer_sequence_len(self.payload)
        if seq_len > 0:
            return seq_len
        # Fallback: derive epoch coverage path from dream location and epoch_id
        epoch_id = self.payload.get("epoch_id")
        if not epoch_id:
            return 0
        # Example dream path: .../artifacts/salvage/<EPOCH_ID>/dream.json
        try:
            # go up two parents to salvage/<EPOCH_ID>, swap salvage -> epochs
            salvage_root = self.path.parent
            epochs_root = salvage_root.parent.parent / "epochs"
            cov_path = epochs_root / epoch_id / "epoch_coverage.json"
            if cov_path.exists():
                cov = json.loads(cov_path.read_text(encoding="utf-8"))
                seq = cov.get("sequence") or []
                if isinstance(seq, list):
                    return len(seq)
        except Exception:
            return 0
        return 0


def _load_dream(path: Path) -> DreamEntry:
    if not path.exists():
        raise FileNotFoundError(f"dream file missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return DreamEntry(path=path, payload=payload)


def _classify(dreams: List[DreamEntry]) -> tuple[List[DreamEntry], List[DreamEntry]]:
    coverage: List[DreamEntry] = []
    gov: List[DreamEntry] = []
    for d in dreams:
        if d.sequence_len > 0:
            coverage.append(d)
        else:
            gov.append(d)
    return coverage, gov


def _coverage_plan(dreams: List[DreamEntry], args: argparse.Namespace) -> Dict[str, Any]:
    if not dreams:
        raise RuntimeError("No coverage-eligible dreams (sequence_len > 0); cannot build coverage plan.")

    crucible_specs = {
        "CRU_COVERAGE_CORE_01": "tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml",
        "CRU_COVERAGE_CORE_02": "tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml",
    }

    return {
        "epoch_id": "EPOCH_NEXT_AUTO",
        "epoch_profile": "COVERAGE",
        "kernel_identity": {"kernel_target": "KERNEL_COVERAGE_BASELINE"},
        "seed": int(args.seed),
        "runner_config": {"template_id": "C019_RUNNER_V1", "args": []},
        "budgets": {
            "epoch_wall_clock_ms": 180000,
            "per_crucible_timeout_ms": 30000,
            "per_crucible_rss_mb": 1536,
        },
        "stop_conditions": {"max_failures": 0},
        "crucible_order": ["CRU_COVERAGE_CORE_01", "CRU_COVERAGE_CORE_02"],
        "crucible_specs": crucible_specs,
    }


def _gov_plan(dreams: List[DreamEntry], args: argparse.Namespace) -> Dict[str, Any]:
    if not dreams:
        return {}
    return {
        "epoch_id": "EPOCH_NEXT_GOV_AUTO",
        "epoch_profile": "GOVERNANCE",
        "kernel_identity": {"kernel_target": "V2_SOVEREIGN"},
        "seed": int(args.seed),
        "runner_config": {"template_id": "C019_RUNNER_V1", "args": []},
        "budgets": {
            "epoch_wall_clock_ms": 120000,
            "per_crucible_timeout_ms": 30000,
            "per_crucible_rss_mb": 1536,
        },
        "stop_conditions": {"max_failures": 1},
        "crucible_order": [],
        "crucible_specs": {},
    }


def _write(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dream compiler (tooling-only, deterministic).")
    p.add_argument("--dream", nargs="+", required=True, help="Paths to dream.json files.")
    p.add_argument("--out", required=True, help="Path to write the coverage epoch plan JSON.")
    p.add_argument("--gov-out", help="Optional path to write a governance/paradox plan JSON.")
    p.add_argument("--seed", default=0, type=int, help="Deterministic seed for generated plans.")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    dreams = [_load_dream(Path(p)) for p in args.dream]
    coverage_dreams, gov_dreams = _classify(dreams)

    coverage_plan = _coverage_plan(coverage_dreams, args)
    _write(Path(args.out), coverage_plan)

    if args.gov_out:
        gov_plan = _gov_plan(gov_dreams, args)
        if gov_plan:
            _write(Path(args.gov_out), gov_plan)

    print(
        json.dumps(
            {
                "coverage_plan": args.out,
                "gov_plan": args.gov_out or None,
                "coverage_dreams": len(coverage_dreams),
                "gov_dreams": len(gov_dreams),
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
