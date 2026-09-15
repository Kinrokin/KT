from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from eval_plus_schemas import ExtendedBenchmarkResultSchema, GoldenZoneSchema, compute_paradox_vector


MAX_JSON_BYTES = 512_000
MAX_RUN_RECORDS = 25_000


def _ensure_under_root(*, path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except Exception:
        raise ValueError(f"{label}_not_under_root (fail-closed)")


def _require_regular_file(*, path: Path, root: Path, label: str) -> None:
    """Reject links/reparse points before reading a JSON input below root."""
    _ensure_under_root(path=path, root=root, label=label)
    current = root
    try:
        for part in path.relative_to(root).parts:
            current = current / part
            mode = current.lstat()
            if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
                raise ValueError(f"{label}_link_or_reparse_forbidden (fail-closed)")
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"{label}_not_regular_file (fail-closed)")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label}_unavailable:{exc.__class__.__name__} (fail-closed)")


def _require_json_object(path: Path, *, root: Path, label: str) -> Dict[str, Any]:
    try:
        _require_regular_file(path=path, root=root, label=label)
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("json_too_large (fail-closed)")
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        if "(fail-closed)" in str(exc):
            raise
        raise ValueError(f"read_json_fail:{path.as_posix()}:ValueError") from exc
    except Exception as exc:
        raise ValueError(f"read_json_fail:{path.as_posix()}:{exc.__class__.__name__}")
    if not isinstance(data, dict):
        raise ValueError(f"json_not_object:{path.as_posix()}")
    return dict(data)


def _load_epoch_metrics(
    epoch_dir: Path, *, artifacts_root: Path
) -> Tuple[Dict[str, int], int, int, Dict[str, int], Dict[str, str]]:
    # Epoch dir is expected to contain per-crucible run_record.json files and (optionally) governance_report.json.
    if not epoch_dir.is_dir():
        raise ValueError("epoch_dir_missing_or_not_directory (fail-closed)")
    outcomes: Dict[str, int] = {}
    replay_verified = 0
    replay_total = 0
    governance_types: Dict[str, int] = {}
    kernel_identity: Dict[str, str] = {"kernel_target": "unknown", "kernel_build_id": "unknown"}

    # Kernel identity is bound by epoch manifest if present.
    manifest_path = epoch_dir / "epoch_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("epoch_manifest_missing (fail-closed)")
    em = _require_json_object(manifest_path, root=epoch_dir, label="epoch_manifest")
    kid = em.get("kernel_identity")
    if isinstance(kid, dict) and "kernel_target" in kid:
        kernel_identity["kernel_target"] = str(kid.get("kernel_target"))
        kernel_identity["kernel_build_id"] = str(kid.get("kernel_build_id", "unknown"))

    run_records = sorted(epoch_dir.rglob("run_record.json"))
    if not run_records:
        raise ValueError("epoch_run_records_missing (fail-closed)")
    if len(run_records) > MAX_RUN_RECORDS:
        raise ValueError("too_many_run_records (fail-closed)")

    for run_record in run_records:
        rr = _require_json_object(run_record, root=epoch_dir, label="run_record")
        outcome = str(rr.get("outcome", "ERROR"))
        outcomes[outcome] = outcomes.get(outcome, 0) + 1

        run_id = rr.get("run_id")
        if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
            raise ValueError("invalid_or_missing_run_id_path_component (fail-closed)")
        kernel_target = kernel_identity.get("kernel_target", "unknown")
        if (kernel_target in {".", ".."}
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", kernel_target) is None):
            raise ValueError("invalid_kernel_target_path_component (fail-closed)")
        c019_root = (artifacts_root / "c019_runs").resolve()
        c019_dir = c019_root / kernel_target / run_id
        _ensure_under_root(path=c019_dir, root=c019_root, label="c019_dir")
        if not c019_dir.is_dir():
            raise ValueError("c019_run_dir_missing (fail-closed)")
        rp = c019_dir / "replay_report.json"
        if not rp.is_file():
            raise ValueError("replay_report_missing (fail-closed)")
        replay_total += 1
        replay_obj = _require_json_object(rp, root=c019_root, label="replay_report")
        if str(replay_obj.get("status", "")).upper() == "PASS":
            replay_verified += 1
        gp = c019_dir / "governance_report.json"
        if gp.exists():
            gov_obj = _require_json_object(gp, root=c019_root, label="governance_report")
            types = gov_obj.get("types") or []
            if isinstance(types, list):
                for t in types:
                    if isinstance(t, str):
                        governance_types[t] = governance_types.get(t, 0) + 1

    return outcomes, replay_verified, replay_total, governance_types, kernel_identity


def main() -> int:
    ap = argparse.ArgumentParser(description="C023+ Eval Harness Plus (tooling-only; no kernel invocation)")
    ap.add_argument("--epoch-dir", required=True, help="Path to an epoch artifacts directory")
    ap.add_argument("--epoch-id", required=True, help="Epoch identifier (label only)")
    ap.add_argument("--golden-metric", default="replay_consistency", help="Metric name to gate (default: replay_consistency)")
    ap.add_argument("--golden-min", type=float, default=0.0, help="Golden zone min (default: 0.0)")
    ap.add_argument("--golden-max", type=float, default=1.0, help="Golden zone max (default: 1.0)")
    ap.add_argument("--out", required=True, help="Output JSON path (append-only external discipline)")
    ap.add_argument("--allow-existing", action="store_true", help="If output exists, validate it matches computed result and exit 0")
    args = ap.parse_args()

    epoch_input = Path(os.path.abspath(args.epoch_dir))
    out_path = Path(args.out).resolve()
    cleanroom_root = Path(__file__).resolve().parents[3]
    override = (os.getenv("KT_GROWTH_ARTIFACTS_ROOT") or "").strip()
    artifacts_root = Path(override) if override else cleanroom_root / "tools" / "growth" / "artifacts"
    if not artifacts_root.is_absolute():
        artifacts_root = cleanroom_root / artifacts_root
    artifacts_root = artifacts_root.resolve()
    allowed_epochs_root = (artifacts_root / "epochs").resolve()
    _ensure_under_root(path=epoch_input, root=allowed_epochs_root, label="epoch_dir")
    if epoch_input.parent != allowed_epochs_root:
        raise ValueError("epoch_dir_not_direct_child (fail-closed)")
    if os.path.lexists(epoch_input):
        mode = epoch_input.lstat()
        if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
            raise ValueError("epoch_dir_link_or_reparse_forbidden (fail-closed)")
    epoch_dir = epoch_input.resolve()
    _ensure_under_root(path=epoch_dir, root=allowed_epochs_root, label="epoch_dir")

    outcomes, replay_verified, replay_total, gov_types, kernel_identity = _load_epoch_metrics(
        epoch_dir, artifacts_root=artifacts_root
    )
    paradox = compute_paradox_vector(
        outcomes=outcomes,
        replay_verified=replay_verified,
        replay_total=replay_total,
        governance_types=gov_types,
    )

    score = float(paradox.axes.get(args.golden_metric, 0.0))
    golden = GoldenZoneSchema.evaluate(metric=str(args.golden_metric), score=score, min_val=float(args.golden_min), max_val=float(args.golden_max))

    # Drift is optional; not computed unless a baseline is provided (future extension).
    result = ExtendedBenchmarkResultSchema.from_parts(
        epoch_id=str(args.epoch_id),
        kernel_identity=kernel_identity,
        paradox=paradox,
        drift=None,
        golden_zone=golden,
    )

    # Fail-closed: never overwrite an existing output file.
    if out_path.exists():
        if not args.allow_existing:
            raise SystemExit("refuse_overwrite (fail-closed)")
        existing = _require_json_object(out_path, root=out_path.parent, label="existing_output")
        ExtendedBenchmarkResultSchema.validate(existing)
        computed = result.to_dict()
        if existing.get("result_hash") != computed.get("result_hash"):
            raise SystemExit("existing_output_hash_mismatch (fail-closed)")
        return 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
