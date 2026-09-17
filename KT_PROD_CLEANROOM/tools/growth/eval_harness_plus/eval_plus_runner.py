from __future__ import annotations

import argparse
import errno
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

from eval_plus_schemas import (
    ALLOWED_OUTCOMES,
    ExtendedBenchmarkResultSchema,
    GoldenZoneSchema,
    compute_paradox_vector,
)


MAX_JSON_BYTES = 512_000
MAX_RUN_RECORDS = 25_000
_RESERVED_DEVICE_BASENAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


def _unique_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key} (fail-closed)")
        result[key] = value
    return result


def _ensure_under_root(*, path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except Exception:
        raise ValueError(f"{label}_not_under_root (fail-closed)")


def _reject_nonportable_path_components(*, path: Path, label: str) -> None:
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    for part in path.parts:
        if part in {".", ".."}:
            continue
        if (":" in part or "\\" in part or part.endswith((".", " "))
                or part.split(".", 1)[0].upper() in reserved):
            raise ValueError(f"{label}_nonportable_path_component (fail-closed)")


def _reject_parent_components(*, path: Path, label: str) -> None:
    if any(part == ".." for part in path.parts):
        raise ValueError(f"{label}_parent_component_forbidden (fail-closed)")


def _reject_link_or_reparse_components(*, path: Path, label: str) -> None:
    """Reject every existing linked component before a trusted root is resolved."""
    _reject_parent_components(path=path, label=label)
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current = current / part
            if not os.path.lexists(current):
                break
            mode = current.lstat()
            if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
                raise ValueError(f"{label}_link_or_reparse_forbidden (fail-closed)")
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"{label}_unavailable:{exc.__class__.__name__} (fail-closed)")


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


def _open_anchored_regular_file(*, path: Path, root: Path, label: str) -> int:
    """Open a regular file through an O_NOFOLLOW directory-descriptor walk."""
    _ensure_under_root(path=path, root=root, label=label)
    if os.name == "nt" or not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise ValueError(f"{label}_secure_read_unavailable (fail-closed)")
    relative = path.relative_to(root)
    if not relative.parts:
        raise ValueError(f"{label}_not_regular_file (fail-closed)")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(root.resolve(), directory_flags)
    try:
        try:
            for component in relative.parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            descriptor = os.open(
                relative.parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(f"{label}_link_or_reparse_forbidden (fail-closed)") from exc
            raise
    finally:
        os.close(directory_fd)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise ValueError(f"{label}_not_regular_file (fail-closed)")
    return descriptor


def _require_json_object(path: Path, *, root: Path, label: str) -> Dict[str, Any]:
    descriptor = -1
    try:
        descriptor = _open_anchored_regular_file(path=path, root=root, label=label)
        opened = os.fstat(descriptor)
        if opened.st_size > MAX_JSON_BYTES:
            raise ValueError("json_too_large (fail-closed)")

        # Retain and read the descriptor opened relative to the trusted root.
        # No pathname is consulted after the anchored open, so ancestor swaps
        # cannot redirect the bytes being verified. The identity recheck also
        # turns a post-open replacement into an explicit fail-closed result.
        _require_regular_file(path=path, root=root, label=label)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError(f"{label}_path_changed_during_open (fail-closed)")
        payload = bytearray()
        while len(payload) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_JSON_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_JSON_BYTES:
            raise ValueError("json_too_large (fail-closed)")
        after = os.fstat(descriptor)
        if any(
            getattr(after, field) != getattr(opened, field)
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise ValueError(f"{label}_changed_during_read (fail-closed)")
        data = json.loads(
            bytes(payload).decode("utf-8"),
            object_pairs_hook=_unique_json_keys,
        )
    except ValueError as exc:
        if "(fail-closed)" in str(exc):
            raise
        raise ValueError(f"read_json_fail:{path.as_posix()}:ValueError") from exc
    except Exception as exc:
        raise ValueError(f"read_json_fail:{path.as_posix()}:{exc.__class__.__name__}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
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
    if not isinstance(kid, dict):
        raise ValueError("invalid_or_missing_kernel_identity (fail-closed)")
    kernel_target = kid.get("kernel_target")
    kernel_build_id = kid.get("kernel_build_id")
    if (not isinstance(kernel_target, str) or not kernel_target.strip()
            or not isinstance(kernel_build_id, str) or not kernel_build_id.strip()):
        raise ValueError("invalid_or_missing_kernel_identity_fields (fail-closed)")
    kernel_identity["kernel_target"] = kernel_target
    kernel_identity["kernel_build_id"] = kernel_build_id

    run_records = sorted(epoch_dir.rglob("run_record.json"))
    if not run_records:
        raise ValueError("epoch_run_records_missing (fail-closed)")
    if len(run_records) > MAX_RUN_RECORDS:
        raise ValueError("too_many_run_records (fail-closed)")

    for run_record in run_records:
        rr = _require_json_object(run_record, root=epoch_dir, label="run_record")
        outcome = rr.get("outcome")
        if not isinstance(outcome, str) or outcome not in ALLOWED_OUTCOMES:
            raise ValueError("invalid_or_missing_run_outcome (fail-closed)")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1

        run_id = rr.get("run_id")
        if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{64}", run_id) is None:
            raise ValueError("invalid_or_missing_run_id_path_component (fail-closed)")
        kernel_target = kernel_identity.get("kernel_target", "unknown")
        if (kernel_target in {".", ".."} or kernel_target.endswith((".", " "))
                or kernel_target.split(".", 1)[0].upper() in _RESERVED_DEVICE_BASENAMES
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", kernel_target) is None):
            raise ValueError("invalid_kernel_target_path_component (fail-closed)")
        c019_root_input = artifacts_root / "c019_runs"
        _reject_link_or_reparse_components(path=c019_root_input, label="c019_root")
        c019_root = c019_root_input.resolve()
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
        if os.path.lexists(gp):
            gov_obj = _require_json_object(gp, root=c019_root, label="governance_report")
            types = gov_obj.get("types") or []
            if isinstance(types, list):
                for t in types:
                    if isinstance(t, str):
                        governance_types[t] = governance_types.get(t, 0) + 1

    return outcomes, replay_verified, replay_total, governance_types, kernel_identity


def _exclusive_write_output(*, path: Path, serialized: str) -> None:
    'Create an output exactly once using a descriptor-anchored parent walk.'
    absolute = Path(os.path.abspath(path))
    _reject_nonportable_path_components(path=absolute, label="output")
    parent = absolute.parent
    if os.name == "nt" or not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise ValueError("secure_output_creation_unavailable (fail-closed)")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current_fd = os.open(absolute.anchor or os.sep, flags)
    try:
        for part in parent.parts[1:]:
            if part in {".", ".."}:
                raise ValueError("output_parent_component_forbidden (fail-closed)")
            try:
                os.mkdir(part, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        leaf_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(absolute.name, leaf_flags, 0o600, dir_fd=current_fd)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(serialized)
    finally:
        os.close(current_fd)

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

    epoch_argument = Path(args.epoch_dir)
    out_argument = Path(args.out)
    _reject_nonportable_path_components(path=epoch_argument, label="epoch_dir")
    _reject_parent_components(path=epoch_argument, label="epoch_dir")
    _reject_nonportable_path_components(path=out_argument, label="output")
    _reject_link_or_reparse_components(path=out_argument, label="output")
    epoch_input = Path(os.path.abspath(epoch_argument))
    out_input = Path(os.path.abspath(out_argument))
    out_path = out_input.resolve()
    cleanroom_root = Path(__file__).resolve().parents[3]
    override = (os.getenv("KT_GROWTH_ARTIFACTS_ROOT") or "").strip()
    artifacts_root_input = Path(override) if override else cleanroom_root / "tools" / "growth" / "artifacts"
    if not artifacts_root_input.is_absolute():
        artifacts_root_input = cleanroom_root / artifacts_root_input
    _reject_link_or_reparse_components(path=artifacts_root_input, label="artifacts_root")
    artifacts_root = artifacts_root_input.resolve()
    epochs_root_input = artifacts_root / "epochs"
    _reject_link_or_reparse_components(path=epochs_root_input, label="epochs_root")
    allowed_epochs_root = epochs_root_input.resolve()
    _ensure_under_root(path=epoch_input, root=allowed_epochs_root, label="epoch_dir")
    if epoch_input.parent != allowed_epochs_root:
        raise ValueError("epoch_dir_not_direct_child (fail-closed)")
    if os.path.lexists(epoch_input):
        mode = epoch_input.lstat()
        if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 0x400:
            raise ValueError("epoch_dir_link_or_reparse_forbidden (fail-closed)")
    epoch_dir = epoch_input.resolve()
    _ensure_under_root(path=epoch_dir, root=allowed_epochs_root, label="epoch_dir")
    epoch_id = args.epoch_id
    if (not isinstance(epoch_id, str) or epoch_id in {".", ".."}
            or epoch_id.endswith((".", " "))
            or epoch_id.split(".", 1)[0].upper() in _RESERVED_DEVICE_BASENAMES
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", epoch_id) is None):
        raise ValueError("invalid_epoch_id_label (fail-closed)")
    if epoch_id != epoch_dir.name:
        raise ValueError("epoch_id_directory_mismatch (fail-closed)")

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
        epoch_id=epoch_id,
        kernel_identity=kernel_identity,
        paradox=paradox,
        drift=None,
        golden_zone=golden,
    )

    # Fail-closed: atomically claim a new output path. Exclusive creation keeps
    # concurrent evaluators from both observing an absent path and overwriting
    # one another.
    computed = result.to_dict()
    serialized = json.dumps(
        computed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ) + "\n"
    try:
        _exclusive_write_output(path=out_path, serialized=serialized)
        return 0
    except FileExistsError:
        if not args.allow_existing:
            raise SystemExit("refuse_overwrite (fail-closed)")
        existing = _require_json_object(out_path, root=out_path.parent, label="existing_output")
        ExtendedBenchmarkResultSchema.validate(existing)
        if existing.get("result_hash") != computed.get("result_hash"):
            raise SystemExit("existing_output_hash_mismatch (fail-closed)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
