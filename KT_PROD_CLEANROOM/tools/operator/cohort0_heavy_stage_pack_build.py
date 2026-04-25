from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from policy_c.dataset_export import export_dataset
from policy_c.sweep_runner import run_sweep
from tools.operator.titanium_common import repo_root, utc_now_compact_z, write_json_stable


FORGE_REGISTRY_REL = Path("KT_PROD_CLEANROOM/tools/operator/config/forge_cohort0_registry.json")
DEFAULT_STAGE_FOLDER_NAME = "kt-chaos-a-heavy-stage"
DEFAULT_STAGE_PACK_SCHEMA_ID = "kt.operator.cohort0_stage_pack_manifest.v1"
FIXED_ZIP_DT = (1980, 1, 1, 0, 0, 0)
PRESSURE_AXES = ("time", "universe", "language", "hop", "step", "paradox", "puzzle")
PRESSURE_LEVELS = (0.0, 0.12, 0.24)
MIN_LINES_PER_DATASET = 768


@dataclass(frozen=True)
class RoleSpec:
    role_name: str
    selector: Callable[[Mapping[str, Any]], bool]
    lens: str
    instruction: str


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _remove_if_exists(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _assert_under(parent: Path, path: Path, *, label: str) -> None:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError as exc:
        raise RuntimeError(f"FAIL_CLOSED: {label} escapes {parent.as_posix()}: {path.as_posix()}") from exc


def _build_policy_c_plan(*, export_root: Path) -> Dict[str, Any]:
    weights = {axis: round(1.0 / len(PRESSURE_AXES), 6) for axis in PRESSURE_AXES}
    runs: List[Dict[str, Any]] = []
    for idx, combo in enumerate(itertools.product(PRESSURE_LEVELS, repeat=len(PRESSURE_AXES)), start=1):
        axis_map = {axis: float(level) for axis, level in zip(PRESSURE_AXES, combo)}
        run_id = f"run_{idx:04d}"
        epoch_id = f"epoch_{idx:04d}"
        runs.append(
            {
                "run_id": run_id,
                "tags": {axis: f"{axis_map[axis]:.2f}" for axis in PRESSURE_AXES},
                "epoch_plan": {
                    "epoch_id": epoch_id,
                    "pressure_tensor": {
                        "schema_id": "kt.policy_c.pressure_tensor.v1",
                        "axes": {
                            axis: {"intensity": axis_map[axis], "enabled": True}
                            for axis in PRESSURE_AXES
                        },
                        "projection": {
                            "rule": "weighted_sum",
                            "weights": weights,
                            "clamp_min": 0.0,
                            "clamp_max": 1.0,
                        },
                        "invariants": {
                            "reversible": True,
                            "isolated": True,
                            "no_cross_axis_bleed": True,
                        },
                    },
                },
            }
        )
    baseline_run_id = "run_0001"
    return {
        "schema_id": "kt.policy_c.sweep_plan.v1",
        "sweep_id": f"cohort0_heavy_stage_{utc_now_compact_z()}",
        "baseline_epoch_id": baseline_run_id,
        "max_runs": len(runs),
        "seed": 4242,
        "export": {"export_root": export_root.as_posix()},
        "runs": runs,
    }


def _coerce_record_to_text(record: Any) -> str:
    if isinstance(record, str):
        return record.strip()
    if not isinstance(record, dict):
        return json.dumps(record, sort_keys=True, ensure_ascii=True)
    for key in ("text", "prompt", "input", "output", "completion"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return json.dumps(record, sort_keys=True, ensure_ascii=True)


def _coerce_raw_dataset(*, raw_dataset_path: Path, output_path: Path) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total_lines = 0
    coerced_lines = 0
    failed_lines = 0
    with raw_dataset_path.open("r", encoding="utf-8") as src, output_path.open("w", encoding="utf-8", newline="\n") as dst:
        for total_lines, raw_line in enumerate(src, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                text = _coerce_record_to_text(obj)
            except Exception:
                failed_lines += 1
                continue
            if not text.strip():
                failed_lines += 1
                continue
            dst.write(json.dumps({"text": text.strip()}, sort_keys=True, ensure_ascii=True) + "\n")
            coerced_lines += 1
    return {
        "total_lines": total_lines,
        "coerced_lines": coerced_lines,
        "failed_lines": failed_lines,
    }


def _role_specs() -> Dict[str, RoleSpec]:
    return {
        "lobe.alpha.v1": RoleSpec(
            role_name="alpha",
            selector=lambda row: True,
            lens="broad-shared-pressure",
            instruction="Synthesize the full pressure field and preserve multi-axis context without collapsing ambiguity.",
        ),
        "lobe.architect.v1": RoleSpec(
            role_name="architect",
            selector=lambda row: len(row["nonzero_axes"]) >= 3 or row["dominant_axis"] in {"hop", "step", "universe"},
            lens="structure-design",
            instruction="Turn the pressure state into a stable structure plan, naming dependencies, boundaries, and reversible sequencing.",
        ),
        "lobe.beta.v1": RoleSpec(
            role_name="beta",
            selector=lambda row: row["source_rank"] % 2 == 1,
            lens="variant-branching",
            instruction="Explore alternate branches, preserve experimental space, and state what should be tried next under bounded risk.",
        ),
        "lobe.child.v1": RoleSpec(
            role_name="child",
            selector=lambda row: row["pressure_scalar"] <= 0.5 or len(row["nonzero_axes"]) <= 3,
            lens="simple-explanation",
            instruction="Explain the state simply, compressing the scenario into the smallest faithful plan a downstream worker could follow.",
        ),
        "lobe.critic.v1": RoleSpec(
            role_name="critic",
            selector=lambda row: row["status"] != "PASS" or bool(row["reason_codes"]),
            lens="failure-diagnosis",
            instruction="Interrogate the failure surface, point out the weak joints, and make the objection explicit.",
        ),
        "lobe.p1.v1": RoleSpec(
            role_name="p1",
            selector=lambda row: row["source_rank"] % 2 == 0,
            lens="partition-one",
            instruction="Work partition one only, favoring the left-side slice of the pressure field and preserving shard identity.",
        ),
        "lobe.p2.v1": RoleSpec(
            role_name="p2",
            selector=lambda row: row["source_rank"] % 2 == 1,
            lens="partition-two",
            instruction="Work partition two only, favoring the right-side slice of the pressure field and preserving shard identity.",
        ),
        "lobe.scout.v1": RoleSpec(
            role_name="scout",
            selector=lambda row: row["dominant_intensity"] >= 0.7 or len(row["nonzero_axes"]) <= 2,
            lens="frontier-scan",
            instruction="Scan the edge case, identify the frontier condition, and call out what makes the scenario unusual or informative.",
        ),
        "lobe.auditor.v1": RoleSpec(
            role_name="auditor",
            selector=lambda row: True,
            lens="governance-audit",
            instruction="Verify bindings, hashes, status, invariants, and whether the scenario remains lawful under the declared rules.",
        ),
        "lobe.censor.v1": RoleSpec(
            role_name="censor",
            selector=lambda row: row["status"] != "PASS" or row["axis_intensities"].get("paradox", 0.0) > 0.0 or row["axis_intensities"].get("puzzle", 0.0) > 0.0,
            lens="boundary-control",
            instruction="Surface the guardrails, disallowed transitions, and containment requirements before any action proceeds.",
        ),
        "lobe.muse.v1": RoleSpec(
            role_name="muse",
            selector=lambda row: row["axis_intensities"].get("language", 0.0) > 0.0 or row["axis_intensities"].get("paradox", 0.0) > 0.0 or row["axis_intensities"].get("time", 0.0) > 0.0,
            lens="creative-analogy",
            instruction="Reframe the same state into a memorable creative analogy while keeping the governing facts intact.",
        ),
        "lobe.quant.v1": RoleSpec(
            role_name="quant",
            selector=lambda row: True,
            lens="numeric-summary",
            instruction="Reduce the scenario to measurable quantities, ranking axes by contribution and making the scalar story explicit.",
        ),
        "lobe.strategist.v1": RoleSpec(
            role_name="strategist",
            selector=lambda row: row["pressure_scalar"] >= 0.45 or len(row["nonzero_axes"]) >= 4,
            lens="campaign-planning",
            instruction="Choose the next move, sequence it, state the blocker, and explain how this scenario changes campaign posture.",
        ),
    }


def _compact_payload(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "run_id": row["run_id"],
        "epoch_id": row["epoch_id"],
        "status": row["status"],
        "reason_codes": row["reason_codes"],
        "pressure_scalar": row["pressure_scalar"],
        "dominant_axis": row["dominant_axis"],
        "dominant_intensity": row["dominant_intensity"],
        "nonzero_axes": row["nonzero_axes"],
        "axis_intensities": row["axis_intensities"],
        "projection_hash": row["projection_hash"],
        "summary_hash": row["summary_hash"],
        "drift_hash": row["drift_hash"],
    }


def _render_text(*, adapter_id: str, spec: RoleSpec, row: Mapping[str, Any]) -> str:
    enabled = ", ".join(f"{axis}:{row['axis_intensities'][axis]:.2f}" for axis in row["nonzero_axes"]) or "none"
    reasons = ", ".join(row["reason_codes"]) if row["reason_codes"] else "NONE"
    payload = json.dumps(_compact_payload(row), sort_keys=True, ensure_ascii=True)
    return (
        f"adapter_id={adapter_id}; role={spec.role_name}; lens={spec.lens}; "
        f"instruction={spec.instruction} "
        f"status={row['status']}; reason_codes={reasons}; "
        f"pressure_scalar={row['pressure_scalar']:.6f}; "
        f"dominant_axis={row['dominant_axis']}:{row['dominant_intensity']:.2f}; "
        f"enabled_axes={enabled}; "
        f"invariants=reversible:{str(row['invariants']['reversible']).lower()},"
        f"isolated:{str(row['invariants']['isolated']).lower()},"
        f"no_cross_axis_bleed:{str(row['invariants']['no_cross_axis_bleed']).lower()}; "
        f"source_payload={payload}"
    )


def _load_source_records(records_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for idx, raw_line in enumerate(records_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        record = json.loads(raw_line)
        pressure_path = Path(str(record["pressure_tensor_ref"]["path"])).resolve()
        summary_path = Path(str(record["epoch_summary_ref"]["path"])).resolve()
        drift_path = Path(str(record["drift_report_ref"]["path"])).resolve()
        pressure = _load_json(pressure_path)
        summary = _load_json(summary_path)
        drift = _load_json(drift_path)
        axis_intensities = {
            axis: float(cfg["intensity"]) if bool(cfg["enabled"]) else 0.0
            for axis, cfg in pressure["axes"].items()
        }
        nonzero_axes = [axis for axis in PRESSURE_AXES if axis_intensities.get(axis, 0.0) > 0.0]
        dominant_axis = max(PRESSURE_AXES, key=lambda axis: (axis_intensities.get(axis, 0.0), axis))
        dominant_intensity = float(axis_intensities.get(dominant_axis, 0.0))
        row = {
            "source_rank": idx,
            "record_id": _sha256_text(_canonical_json(record)),
            "run_id": str(record["run_id"]),
            "epoch_id": str(record["epoch_id"]),
            "status": str(record["labels"]["status"]),
            "reason_codes": list(record["labels"].get("reason_codes", [])),
            "pressure_scalar": float(summary["pressure_scalar"]),
            "projection_hash": str(summary["projection_hash"]),
            "axis_intensities": axis_intensities,
            "nonzero_axes": nonzero_axes,
            "dominant_axis": dominant_axis,
            "dominant_intensity": dominant_intensity,
            "pressure_hash": str(record["pressure_tensor_ref"]["hash"]),
            "summary_hash": str(record["epoch_summary_ref"]["hash"]),
            "drift_hash": str(record["drift_report_ref"]["hash"]),
            "invariants": dict(pressure["invariants"]),
        }
        rows.append(row)
    rows.sort(key=lambda row: row["record_id"])
    return rows


def _select_rows(*, adapter_id: str, rows: Sequence[Dict[str, Any]], spec: RoleSpec) -> List[Dict[str, Any]]:
    selected = [row for row in rows if spec.selector(row)]
    if len(selected) >= MIN_LINES_PER_DATASET:
        return selected
    seen = {row["record_id"] for row in selected}
    for row in rows:
        if row["record_id"] in seen:
            continue
        selected.append(row)
        seen.add(row["record_id"])
        if len(selected) >= MIN_LINES_PER_DATASET:
            break
    if not selected:
        raise RuntimeError(f"FAIL_CLOSED: no rows selected for {adapter_id}")
    return selected


def _write_dataset_file(*, path: Path, adapter_id: str, spec: RoleSpec, rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    line_count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            payload = {
                "text": _render_text(adapter_id=adapter_id, spec=spec, row=row),
                "adapter_id": adapter_id,
                "source_record_id": row["record_id"],
                "source_status": row["status"],
                "source_reason_codes": row["reason_codes"],
                "pressure_scalar": row["pressure_scalar"],
                "dominant_axis": row["dominant_axis"],
            }
            handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True) + "\n")
            line_count += 1
    return {
        "adapter_id": adapter_id,
        "path": path,
        "sha256": _sha256_file(path),
        "bytes": int(path.stat().st_size),
        "line_count": line_count,
        "role_name": spec.role_name,
        "lens": spec.lens,
    }


def _stage_file_entries(stage_root: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(p for p in stage_root.rglob("*") if p.is_file()):
        entries.append(
            {
                "path": path.relative_to(stage_root).as_posix(),
                "sha256": _sha256_file(path),
                "bytes": int(path.stat().st_size),
            }
        )
    return entries


def _write_stage_zip(stage_root: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zip_path.open("wb") as handle:
        with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(p for p in stage_root.rglob("*") if p.is_file()):
                rel = path.relative_to(stage_root.parent).as_posix()
                zi = zipfile.ZipInfo(rel, date_time=FIXED_ZIP_DT)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = (0o644 & 0xFFFF) << 16
                zf.writestr(zi, path.read_bytes())


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    root = repo_root()
    onedrive_root = root.parent.resolve()
    kt_stage_root = (onedrive_root / "KT_FORGE_STAGE").resolve()
    kaggle_stage_pack_root = (kt_stage_root / "kaggle_stage_pack").resolve()
    default_stage_root = (kaggle_stage_pack_root / DEFAULT_STAGE_FOLDER_NAME).resolve()
    default_mirror = (kt_stage_root / "input_root_heavy").resolve()
    default_zip = (kaggle_stage_pack_root / f"{DEFAULT_STAGE_FOLDER_NAME}.zip").resolve()
    default_stage_manifest = (kaggle_stage_pack_root / "cohort0_chaos_a_heavy_stage_pack_manifest.json").resolve()
    default_receipt = (kaggle_stage_pack_root / "cohort0_chaos_a_heavy_stage_build_receipt.json").resolve()

    ap = argparse.ArgumentParser(description="Build the real heavier Cohort-0 Chaos A stage pack on OneDrive.")
    ap.add_argument("--stage-root", default=default_stage_root.as_posix())
    ap.add_argument("--mirror-input-root", default=default_mirror.as_posix())
    ap.add_argument("--zip-path", default=default_zip.as_posix())
    ap.add_argument("--stage-manifest-path", default=default_stage_manifest.as_posix())
    ap.add_argument("--receipt-path", default=default_receipt.as_posix())
    ap.add_argument("--force", action="store_true", help="Replace any existing stage-pack outputs.")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    onedrive_root = root.parent.resolve()
    kt_stage_root = (onedrive_root / "KT_FORGE_STAGE").resolve()
    kaggle_stage_pack_root = (kt_stage_root / "kaggle_stage_pack").resolve()

    stage_root = Path(str(args.stage_root)).expanduser().resolve()
    mirror_input_root = Path(str(args.mirror_input_root)).expanduser().resolve()
    zip_path = Path(str(args.zip_path)).expanduser().resolve()
    stage_manifest_path = Path(str(args.stage_manifest_path)).expanduser().resolve()
    receipt_path = Path(str(args.receipt_path)).expanduser().resolve()

    for label, path in (
        ("stage_root", stage_root),
        ("mirror_input_root", mirror_input_root),
        ("zip_path", zip_path),
        ("stage_manifest_path", stage_manifest_path),
        ("receipt_path", receipt_path),
    ):
        _assert_under(kt_stage_root, path, label=label)

    if not args.force:
        for path in (stage_root, mirror_input_root, zip_path, stage_manifest_path, receipt_path):
            if path.exists():
                raise RuntimeError(f"FAIL_CLOSED: output already exists, rerun with --force: {path.as_posix()}")

    for path in (stage_root, mirror_input_root, zip_path, stage_manifest_path, receipt_path):
        _remove_if_exists(path)

    build_id = utc_now_compact_z()
    sweep_export_root = (root / "KT_PROD_CLEANROOM" / "exports" / "policy_c" / f"cohort0_heavy_stage_{build_id}").resolve()
    _assert_under((root / "KT_PROD_CLEANROOM" / "exports" / "policy_c").resolve(), sweep_export_root, label="sweep_export_root")
    _remove_if_exists(sweep_export_root)
    sweep_export_root.mkdir(parents=True, exist_ok=True)

    plan = _build_policy_c_plan(export_root=sweep_export_root)
    plan_path = (sweep_export_root / "policy_c_sweep_plan.json").resolve()
    write_json_stable(plan_path, plan)

    run_sweep(plan_path=plan_path, out_root=sweep_export_root)
    sweep_result_path = (sweep_export_root / "policy_c_sweep_result.json").resolve()
    dataset_export_root = (sweep_export_root / "dataset_export").resolve()
    dataset_export_root.mkdir(parents=True, exist_ok=True)
    export_manifest = export_dataset(sweep_result_path=sweep_result_path, out_root=dataset_export_root)

    raw_dataset_path = Path(str(export_manifest["records_path"])).resolve()
    coerced_dataset_path = (dataset_export_root / "dataset_coerced.jsonl").resolve()
    coercion_stats = _coerce_raw_dataset(raw_dataset_path=raw_dataset_path, output_path=coerced_dataset_path)

    derived_rows = _load_source_records(raw_dataset_path)
    if len(derived_rows) < MIN_LINES_PER_DATASET:
        raise RuntimeError(
            f"FAIL_CLOSED: source record count too small for heavy pack: {len(derived_rows)} < {MIN_LINES_PER_DATASET}"
        )

    forge_registry = _load_json((root / FORGE_REGISTRY_REL).resolve())
    adapter_rows = forge_registry.get("adapters")
    if not isinstance(adapter_rows, list) or len(adapter_rows) != 13:
        raise RuntimeError("FAIL_CLOSED: forge registry does not contain exactly 13 adapters")

    role_specs = _role_specs()
    stage_root.mkdir(parents=True, exist_ok=True)
    (stage_root / "snapshots" / "cohort0" / "base_snapshot").mkdir(parents=True, exist_ok=True)
    (stage_root / "snapshots" / "cohort0" / "base_snapshot" / "SNAPSHOT.txt").write_text(
        "COHORT0_STAGED_BASE_SNAPSHOT_V1\n",
        encoding="utf-8",
        newline="\n",
    )

    dataset_manifest_entries: List[Dict[str, Any]] = []
    dataset_receipts: List[Dict[str, Any]] = []
    for row in adapter_rows:
        adapter_id = str(row["adapter_id"]).strip()
        spec = role_specs.get(adapter_id)
        if spec is None:
            raise RuntimeError(f"FAIL_CLOSED: no role spec defined for {adapter_id}")
        selected_rows = _select_rows(adapter_id=adapter_id, rows=derived_rows, spec=spec)
        dataset_path = (stage_root / "datasets" / adapter_id / "failures.jsonl").resolve()
        receipt = _write_dataset_file(path=dataset_path, adapter_id=adapter_id, spec=spec, rows=selected_rows)
        dataset_receipts.append(receipt)
        dataset_manifest_entries.append(
            {
                "adapter_id": adapter_id,
                "dataset_relpath": f"datasets/{adapter_id}/failures.jsonl",
                "sha256": receipt["sha256"],
            }
        )

    dataset_manifest = {"entries": dataset_manifest_entries}
    write_json_stable((stage_root / "datasets" / "cohort0_dataset_manifest.json").resolve(), dataset_manifest)

    _remove_if_exists(mirror_input_root)
    shutil.copytree(stage_root, mirror_input_root)

    stage_entries = _stage_file_entries(stage_root)
    stage_manifest = {
        "schema_id": DEFAULT_STAGE_PACK_SCHEMA_ID,
        "package_root": stage_root.as_posix(),
        "file_count": len(stage_entries),
        "entries": stage_entries,
    }
    write_json_stable(stage_manifest_path, stage_manifest)

    _write_stage_zip(stage_root, zip_path)
    zip_sha = _sha256_file(zip_path)

    receipt = {
        "schema_id": "kt.operator.cohort0_heavy_stage_build_receipt.v1",
        "status": "PASS",
        "build_id": build_id,
        "repo_root": root.as_posix(),
        "source_sweep_export_root": sweep_export_root.as_posix(),
        "source_plan_path": plan_path.as_posix(),
        "source_sweep_result_path": sweep_result_path.as_posix(),
        "source_dataset_manifest_path": (dataset_export_root / "kt_policy_c_dataset_manifest_v1.json").as_posix(),
        "source_raw_dataset_path": raw_dataset_path.as_posix(),
        "source_raw_dataset_sha256": _sha256_file(raw_dataset_path),
        "source_coerced_dataset_path": coerced_dataset_path.as_posix(),
        "source_coerced_dataset_sha256": _sha256_file(coerced_dataset_path),
        "source_record_count": len(derived_rows),
        "coercion_stats": coercion_stats,
        "stage_root": stage_root.as_posix(),
        "mirror_input_root": mirror_input_root.as_posix(),
        "zip_path": zip_path.as_posix(),
        "zip_sha256": zip_sha,
        "stage_manifest_path": stage_manifest_path.as_posix(),
        "dataset_receipts": [
            {
                "adapter_id": item["adapter_id"],
                "role_name": item["role_name"],
                "lens": item["lens"],
                "line_count": item["line_count"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
                "path": item["path"].as_posix(),
            }
            for item in dataset_receipts
        ],
    }
    write_json_stable(receipt_path, receipt)

    print("COHORT0_HEAVY_STAGE_PACK_PASS")
    print(f"STAGE_ROOT={stage_root.as_posix()}")
    print(f"MIRROR_INPUT_ROOT={mirror_input_root.as_posix()}")
    print(f"ZIP_PATH={zip_path.as_posix()}")
    print(f"ZIP_SHA256={zip_sha}")
    print(f"SOURCE_RECORD_COUNT={len(derived_rows)}")
    for item in dataset_receipts:
        print(
            f"DATASET {item['adapter_id']} lines={item['line_count']} bytes={item['bytes']} sha256={item['sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
