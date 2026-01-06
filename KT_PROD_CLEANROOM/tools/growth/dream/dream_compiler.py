from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class DreamCompileError(RuntimeError):
    pass


@dataclass(frozen=True)
class DreamInput:
    path: Path
    payload: Dict[str, Any]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DreamCompileError(f"Dream file missing: {path.as_posix()} (fail-closed)") from exc
    except Exception as exc:
        raise DreamCompileError(f"Invalid JSON: {path.as_posix()} (fail-closed)") from exc


def _infer_sequence_len(dream: Dict[str, Any], *, repo_root: Path) -> Tuple[int, Dict[str, Any]]:
    # direct
    if isinstance(dream.get("sequence"), list):
        seq = dream.get("sequence") or []
        return len(seq), {"source": "dream.sequence"}

    # common nested locations
    for key in ("coverage", "observed", "metrics", "trace"):
        sub = dream.get(key)
        if isinstance(sub, dict) and isinstance(sub.get("sequence"), list):
            return len(sub["sequence"]), {"source": f"dream.{key}.sequence"}

    # attempt to read epoch_coverage.json if epoch_id is present
    epoch_id = dream.get("epoch_id")
    if isinstance(epoch_id, str):
        cov_path = repo_root / "tools" / "growth" / "artifacts" / "epochs" / epoch_id / "epoch_coverage.json"
        if cov_path.exists():
            cov = _load_json(cov_path)
            seq = cov.get("sequence") or []
            return len(seq), {"source": "epoch_coverage.sequence", "epoch_coverage": cov}

    return 0, {"source": "missing"}


def _coverage_eligible(dream: Dict[str, Any], *, repo_root: Path) -> Tuple[bool, Dict[str, Any]]:
    seq_len, meta = _infer_sequence_len(dream, repo_root=repo_root)
    if seq_len >= 2:
        return True, {"sequence_len": seq_len, **meta}

    cov = meta.get("epoch_coverage")
    if isinstance(cov, dict):
        observed = cov.get("observed", {})
        domains = observed.get("domains", [])
        subdomains = observed.get("subdomains", [])
        dominance = observed.get("dominance", {})
        entropy = float(dominance.get("entropy_domains", 0.0))
        if len(domains) > 1 or len(subdomains) > 1 or entropy > 0.0:
            return True, {"sequence_len": seq_len, "entropy_domains": entropy, **meta}

    return False, {"sequence_len": seq_len, **meta}


def _validate_crucible_path(path: Path) -> None:
    if not path.exists():
        raise DreamCompileError(f"Crucible spec missing: {path.as_posix()} (fail-closed)")


def _build_plan(
    *,
    epoch_id: str,
    epoch_profile: str,
    kernel_target: str,
    seed: int,
    pass_crucible: Path,
    hop_crucible: Path,
) -> Dict[str, Any]:
    return {
        "epoch_id": epoch_id,
        "epoch_profile": epoch_profile,
        "kernel_identity": {"kernel_target": kernel_target},
        "seed": seed,
        "runner_config": {"template_id": "C019_RUNNER_V1", "args": []},
        "budgets": {
            "epoch_wall_clock_ms": 600000,
            "per_crucible_timeout_ms": 30000,
            "per_crucible_rss_mb": 1536,
        },
        "stop_conditions": {"max_failures": 1},
        "crucible_order": ["CRU_COVERAGE_CORE_01", "CRU_COVERAGE_CORE_02"],
        "crucible_specs": {
            "CRU_COVERAGE_CORE_01": pass_crucible.as_posix(),
            "CRU_COVERAGE_CORE_02": hop_crucible.as_posix(),
        },
    }


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Dream compiler (tooling-only, fail-closed).")
    p.add_argument("--dream", action="append", required=True, help="Dream file path (repeatable).")
    p.add_argument("--out", required=True, help="Output epoch plan path.")
    p.add_argument("--gov-out", help="Optional governance plan output path.")
    p.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")
    p.add_argument("--kernel-target", default="KERNEL_COVERAGE_BASELINE", help="Kernel target for coverage plan.")
    p.add_argument(
        "--profile",
        default="COVERAGE_SEED",
        choices=["COVERAGE_SEED", "COVERAGE_MILESTONE", "COVERAGE"],
        help="Epoch profile for the coverage plan.",
    )
    p.add_argument(
        "--pass-crucible",
        default="tools/growth/crucibles/CRU-COVERAGE-HOP-PASS-01.yaml",
        help="Pass-capable crucible spec path (repo-root relative).",
    )
    p.add_argument(
        "--hop-crucible",
        default="tools/growth/crucibles/CRU-COVERAGE-HOP-01.yaml",
        help="Hop/pressure crucible spec path (repo-root relative).",
    )
    p.add_argument(
        "--gov-crucible",
        help="Optional governance crucible spec path when --gov-out is used.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    repo_root = _repo_root()
    dreams = [DreamInput(path=Path(p), payload=_load_json(Path(p))) for p in args.dream]

    coverage_dreams: List[DreamInput] = []
    for d in dreams:
        eligible, meta = _coverage_eligible(d.payload, repo_root=repo_root)
        if eligible:
            coverage_dreams.append(d)

    if not coverage_dreams:
        raise DreamCompileError("No coverage-eligible dreams (sequence_len >= 2) (fail-closed)")

    pass_crucible = (repo_root / args.pass_crucible).resolve()
    hop_crucible = (repo_root / args.hop_crucible).resolve()
    _validate_crucible_path(pass_crucible)
    _validate_crucible_path(hop_crucible)

    coverage_plan = _build_plan(
        epoch_id="EPOCH_NEXT_AUTO",
        epoch_profile=args.profile,
        kernel_target=args.kernel_target,
        seed=args.seed,
        pass_crucible=pass_crucible,
        hop_crucible=hop_crucible,
    )
    _write_json(Path(args.out), coverage_plan)

    if args.gov_out:
        if not args.gov_crucible:
            raise DreamCompileError("--gov-out requires --gov-crucible (fail-closed)")
        gov_crucible = (repo_root / args.gov_crucible).resolve()
        _validate_crucible_path(gov_crucible)
        gov_plan = {
            "epoch_id": "EPOCH_GOV_AUTO",
            "epoch_profile": "GOVERNANCE",
            "kernel_identity": {"kernel_target": "V2_SOVEREIGN"},
            "seed": args.seed,
            "runner_config": {"template_id": "C019_RUNNER_V1", "args": []},
            "budgets": {
                "epoch_wall_clock_ms": 300000,
                "per_crucible_timeout_ms": 30000,
                "per_crucible_rss_mb": 1536,
            },
            "stop_conditions": {"max_failures": 1},
            "crucible_order": ["CRU_GOV_CORE_01"],
            "crucible_specs": {"CRU_GOV_CORE_01": gov_crucible.as_posix()},
        }
        _write_json(Path(args.gov_out), gov_plan)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DreamCompileError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
