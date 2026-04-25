from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_EVIDENCE_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_stronger_cycle_evidence_packet.json"
DEFAULT_EXECUTION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_stronger_cycle_chaos_a_execution_receipt.json"
DEFAULT_RUN_LABEL = "cohort0_stronger_cycle_chaos_a"


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"FAIL_CLOSED: unable to resolve git HEAD rc={exc.returncode}") from exc


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_tree(root: Path) -> Dict[str, Any]:
    if not root.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing hash root: {root.as_posix()}")
    files = [p for p in root.rglob("*") if p.is_file()]
    files.sort(key=lambda p: p.relative_to(root).as_posix())
    entries = [
        {
            "path": p.relative_to(root).as_posix(),
            "sha256": _sha256_file(p),
            "bytes": int(p.stat().st_size),
        }
        for p in files
    ]
    return {
        "root": root.as_posix(),
        "file_count": int(len(entries)),
        "entries": entries,
        "root_hash": hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest(),
    }


def _subprocess_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    py_entries = [
        str((root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()),
        str((root / "KT_PROD_CLEANROOM").resolve()),
    ]
    existing = str(env.get("PYTHONPATH", "")).strip()
    if existing:
        py_entries.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(py_entries)
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _validate_evidence_packet(packet: Dict[str, Any], *, current_head: str) -> Tuple[str, Path, Path]:
    if str(packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence packet must PASS")
    if str(packet.get("evidence_posture", "")).strip() != "STRONGER_CYCLE_EVIDENCE_READY__CHAOS_A_HYPERTRAINING_CHAOS_B_BOUND":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence posture mismatch")
    if str(packet.get("next_lawful_move", "")).strip() != "EXECUTE_CHAOS_A_ON_NEW_AUTHORITATIVE_HEAD_WITH_REAL_STAGE_INPUTS":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence packet next_lawful_move mismatch")

    subject_head = str(packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence packet subject_head missing")
    if current_head == subject_head:
        raise RuntimeError("FAIL_CLOSED: Chaos A requires a new authoritative head distinct from the current proof head")

    stage_refs = packet.get("stage_asset_refs") if isinstance(packet.get("stage_asset_refs"), dict) else {}
    contract_ref = str(stage_refs.get("chaos_round_a_contract_ref", "")).strip()
    registry_ref = str(stage_refs.get("chaos_round_a_registry_ref", "")).strip()
    if not contract_ref or not registry_ref:
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence packet missing Chaos A stage refs")
    return subject_head, Path(contract_ref).resolve(), Path(registry_ref).resolve()


def _validate_stage_input_root(stage_input_root: Path) -> Dict[str, Any]:
    base_snapshot = (stage_input_root / "snapshots" / "cohort0" / "base_snapshot").resolve()
    dataset_manifest = (stage_input_root / "datasets" / "cohort0_dataset_manifest.json").resolve()
    if not base_snapshot.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing staged base snapshot: {base_snapshot.as_posix()}")
    if not dataset_manifest.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing staged dataset manifest: {dataset_manifest.as_posix()}")
    manifest = _load_json_required(dataset_manifest, label="cohort0 dataset manifest")
    entries = manifest.get("entries") if isinstance(manifest.get("entries"), list) else []
    if len(entries) != 13:
        raise RuntimeError("FAIL_CLOSED: staged dataset manifest must contain exactly 13 entries")
    for row in entries:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: staged dataset manifest entry must be object")
        rel = str(row.get("dataset_relpath", "")).strip()
        adapter_id = str(row.get("adapter_id", "")).strip()
        if not rel or not adapter_id:
            raise RuntimeError("FAIL_CLOSED: staged dataset manifest entry missing adapter_id/dataset_relpath")
        path = (stage_input_root / rel).resolve()
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing staged dataset file for {adapter_id}: {path.as_posix()}")
    return {
        "base_snapshot_path": base_snapshot,
        "base_snapshot_hash_tree": _hash_tree(base_snapshot),
        "dataset_manifest_path": dataset_manifest,
        "dataset_manifest_sha256": _sha256_file(dataset_manifest),
    }


def _validate_base_model_dir(base_model_dir: Path) -> Dict[str, Any]:
    config_path = (base_model_dir / "config.json").resolve()
    if not config_path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: base_model_dir missing config.json: {config_path.as_posix()}")
    if (base_model_dir / "adapter_config.json").exists():
        raise RuntimeError("FAIL_CLOSED: base_model_dir must be a base model, not an adapter directory")
    weight_candidates = list(base_model_dir.glob("*.safetensors")) + list(base_model_dir.glob("pytorch_model*.bin")) + list(base_model_dir.glob("*.bin"))
    if not weight_candidates:
        raise RuntimeError(f"FAIL_CLOSED: base_model_dir missing weight files: {base_model_dir.as_posix()}")
    return {
        "config_path": config_path,
        "model_hash_tree": _hash_tree(base_model_dir),
    }


def _validate_external_artifact_root(root: Path, artifact_root: Path) -> Path:
    if not artifact_root.is_absolute():
        raise RuntimeError("FAIL_CLOSED: external artifact root must be absolute")
    resolved = artifact_root.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return resolved
    raise RuntimeError("FAIL_CLOSED: external artifact root must be outside the repo tree")


def _run_chaos_a(
    *,
    root: Path,
    registry_path: Path,
    stage_input_root: Path,
    base_model_dir: Path,
    external_artifact_root: Path,
    transcript_path: Path,
) -> Path:
    cmd = [
        sys.executable,
        "-m",
        "tools.operator.forge_cohort0",
        "--registry",
        str(registry_path),
        "--input-root",
        str(stage_input_root),
        "--artifact-root",
        str(external_artifact_root),
        "--mode",
        "full",
        "--base-model-dir",
        str(base_model_dir),
        "--enable-real-engine",
        "--run-label",
        DEFAULT_RUN_LABEL,
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(root),
        env=_subprocess_env(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.write_text(proc.stdout if proc.stdout.endswith("\n") else proc.stdout + "\n", encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: Chaos A forge execution failed rc={proc.returncode}")
    return (external_artifact_root / DEFAULT_RUN_LABEL).resolve()


def _validate_run_root(run_root: Path) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    required_top = [
        run_root / "discovery_receipt.json",
        run_root / "preflight_receipt.json",
        run_root / "run_summary.json",
        run_root / "run_manifest.json",
        run_root / "adapter_registry.json",
        run_root / "adapter_lineage_manifest.json",
    ]
    for path in required_top:
        if not path.is_file():
            raise RuntimeError(f"FAIL_CLOSED: missing Chaos A top-level artifact: {path.as_posix()}")

    run_summary = _load_json_required(run_root / "run_summary.json", label="Chaos A run_summary")
    run_manifest = _load_json_required(run_root / "run_manifest.json", label="Chaos A run_manifest")
    if str(run_summary.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Chaos A run_summary status must PASS")
    if str(run_manifest.get("verdict", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Chaos A run_manifest verdict must PASS")
    if int(run_summary.get("adapter_count", 0)) != 13 or int(run_summary.get("fail_count", -1)) != 0:
        raise RuntimeError("FAIL_CLOSED: Chaos A run_summary adapter_count/fail_count mismatch")

    adapter_ids = run_manifest.get("adapter_ids") if isinstance(run_manifest.get("adapter_ids"), list) else []
    if len(adapter_ids) != 13:
        raise RuntimeError("FAIL_CLOSED: Chaos A run_manifest must contain exactly 13 adapter_ids")

    receipt_rows: List[Dict[str, Any]] = []
    source_eval_stub_count = 0
    for adapter_id in adapter_ids:
        adapter_root = (run_root / "adapters" / str(adapter_id)).resolve()
        bundle = adapter_root / "adapter_bundle.zip"
        training_path = adapter_root / "adapter_training_receipt.json"
        reload_path = adapter_root / "adapter_reload_receipt.json"
        eval_path = adapter_root / "adapter_eval_receipt.json"
        for path in (bundle, training_path, reload_path, eval_path):
            if not path.is_file():
                raise RuntimeError(f"FAIL_CLOSED: missing Chaos A adapter artifact/receipt: {path.as_posix()}")

        training = _load_json_required(training_path, label=f"{adapter_id} training receipt")
        reload = _load_json_required(reload_path, label=f"{adapter_id} reload receipt")
        eval_receipt = _load_json_required(eval_path, label=f"{adapter_id} eval receipt")
        bundle_bytes = int(bundle.stat().st_size)
        bundle_sha = _sha256_file(bundle)

        if str(training.get("status", "")).strip() != "PASS":
            raise RuntimeError(f"FAIL_CLOSED: training receipt not PASS for {adapter_id}")
        if str(training.get("engine", "")).strip() != "hf_lora":
            raise RuntimeError(f"FAIL_CLOSED: training engine must be hf_lora for {adapter_id}")
        if str(training.get("training_mode", "")).strip() != "lora":
            raise RuntimeError(f"FAIL_CLOSED: training mode must be lora for {adapter_id}")
        if int(training.get("artifact_bytes", 0)) != bundle_bytes or str(training.get("artifact_sha256", "")).strip() != bundle_sha:
            raise RuntimeError(f"FAIL_CLOSED: training artifact binding mismatch for {adapter_id}")
        if str(reload.get("status", "")).strip() != "PASS" or int(reload.get("reloaded_member_count", 0)) <= 0:
            raise RuntimeError(f"FAIL_CLOSED: reload receipt invalid for {adapter_id}")
        if str(eval_receipt.get("status", "")).strip() != "PASS" or int(eval_receipt.get("eval_case_count", 0)) <= 0:
            raise RuntimeError(f"FAIL_CLOSED: eval receipt invalid for {adapter_id}")

        source_eval_stub = bool(eval_receipt.get("source_eval_stub"))
        source_eval_stub_count += int(source_eval_stub)
        receipt_rows.append(
            {
                "adapter_id": str(adapter_id),
                "artifact_path": bundle.as_posix(),
                "artifact_sha256": bundle_sha,
                "artifact_bytes": bundle_bytes,
                "training_receipt_ref": training_path.as_posix(),
                "reload_receipt_ref": reload_path.as_posix(),
                "eval_receipt_ref": eval_path.as_posix(),
                "eval_case_count": int(eval_receipt.get("eval_case_count", 0)),
                "baseline_eval_score": float(eval_receipt.get("baseline_eval_score", 0.0)),
                "source_eval_stub": source_eval_stub,
            }
        )

    return run_summary, run_manifest, receipt_rows


def _build_execution_receipt(
    *,
    current_head: str,
    proof_head: str,
    evidence_packet_path: Path,
    contract_path: Path,
    registry_path: Path,
    stage_input_root: Path,
    stage_input_summary: Dict[str, Any],
    base_model_dir: Path,
    base_model_summary: Dict[str, Any],
    external_artifact_root: Path,
    run_root: Path,
    transcript_path: Path,
    run_summary: Dict[str, Any],
    run_manifest: Dict[str, Any],
    receipt_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    artifact_bytes = [int(row["artifact_bytes"]) for row in receipt_rows]
    eval_counts = [int(row["eval_case_count"]) for row in receipt_rows]
    source_eval_stub_count = int(sum(1 for row in receipt_rows if bool(row["source_eval_stub"])))
    return {
        "schema_id": "kt.operator.cohort0_stronger_cycle_chaos_a_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": current_head,
        "source_proof_head": proof_head,
        "same_head_distinct_from_proof_line": current_head != proof_head,
        "execution_posture": "CHAOS_A_EXECUTED__INDIVIDUAL_HYPERTRAINING_REQUIRED",
        "claim_boundary": (
            "This receipt proves only that Chaos Round A executed on a new head with real staged inputs through the sanctioned Cohort-0 real-engine forge surface. "
            "It does not reopen B04.R6, Gate E, Gate F, router authority, or commercialization."
        ),
        "source_stronger_cycle_evidence_packet_ref": evidence_packet_path.as_posix(),
        "source_chaos_round_a_contract_ref": contract_path.as_posix(),
        "source_chaos_round_a_registry_ref": registry_path.as_posix(),
        "stage_input_root": stage_input_root.as_posix(),
        "stage_input_base_snapshot_root_hash": str(stage_input_summary["base_snapshot_hash_tree"]["root_hash"]),
        "stage_input_dataset_manifest_ref": str(stage_input_summary["dataset_manifest_path"].as_posix()),
        "stage_input_dataset_manifest_sha256": str(stage_input_summary["dataset_manifest_sha256"]),
        "base_model_dir": base_model_dir.as_posix(),
        "base_model_root_hash": str(base_model_summary["model_hash_tree"]["root_hash"]),
        "external_artifact_root": external_artifact_root.as_posix(),
        "chaos_a_run_root": run_root.as_posix(),
        "chaos_a_transcript_ref": transcript_path.as_posix(),
        "registry_id": str(run_summary.get("registry_id", "")).strip(),
        "adapter_count": int(run_summary.get("adapter_count", 0)),
        "hf_lora_adapter_count": len(receipt_rows),
        "artifact_bytes_min": int(min(artifact_bytes) if artifact_bytes else 0),
        "artifact_bytes_max": int(max(artifact_bytes) if artifact_bytes else 0),
        "eval_case_count_min": int(min(eval_counts) if eval_counts else 0),
        "eval_case_count_max": int(max(eval_counts) if eval_counts else 0),
        "source_eval_stub_count": source_eval_stub_count,
        "chaos_a_eval_boundary": "Chaos A receipts may still reflect stub-origin eval receipts from forge_cohort0; non-stub eval emission remains downstream in the stronger-cycle chain.",
        "run_manifest_ref": (run_root / "run_manifest.json").as_posix(),
        "run_summary_ref": (run_root / "run_summary.json").as_posix(),
        "adapter_receipt_entries": receipt_rows,
        "next_lawful_move": "EXECUTE_13_INDIVIDUAL_HYPERTRAINING_LANES_ON_CHAOS_A_SUBSTRATE",
    }


def run_chaos_a_execution_tranche(
    *,
    evidence_packet_path: Path,
    stage_input_root: Path,
    base_model_dir: Path,
    external_artifact_root: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
    existing_run_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)
    authoritative_evidence_path, evidence_packet = _resolve_authoritative(
        root,
        evidence_packet_path.resolve(),
        "authoritative_stronger_cycle_evidence_packet_ref",
        "cohort0 stronger cycle evidence packet",
    )
    proof_head, contract_path, registry_path = _validate_evidence_packet(evidence_packet, current_head=current_head)
    _ = _load_json_required(contract_path, label="Chaos A execution contract")
    _ = _load_json_required(registry_path, label="Chaos A forge registry")

    stage_input_summary = _validate_stage_input_root(stage_input_root.resolve())
    base_model_summary = _validate_base_model_dir(base_model_dir.resolve())
    external_artifact_root = _validate_external_artifact_root(root, external_artifact_root.resolve())

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_stronger_cycle_chaos_a_current_head").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    transcript_path = (target_root / "cohort0_stronger_cycle_chaos_a_execution.log").resolve()

    if existing_run_root is not None:
        run_root = existing_run_root.resolve()
        transcript_path.write_text("EXISTING_RUN_ROOT_BIND_ONLY\n", encoding="utf-8")
    else:
        run_root = _run_chaos_a(
            root=root,
            registry_path=registry_path,
            stage_input_root=stage_input_root.resolve(),
            base_model_dir=base_model_dir.resolve(),
            external_artifact_root=external_artifact_root,
            transcript_path=transcript_path,
        )

    run_summary, run_manifest, receipt_rows = _validate_run_root(run_root)
    receipt = _build_execution_receipt(
        current_head=current_head,
        proof_head=proof_head,
        evidence_packet_path=authoritative_evidence_path,
        contract_path=contract_path,
        registry_path=registry_path,
        stage_input_root=stage_input_root.resolve(),
        stage_input_summary=stage_input_summary,
        base_model_dir=base_model_dir.resolve(),
        base_model_summary=base_model_summary,
        external_artifact_root=external_artifact_root,
        run_root=run_root,
        transcript_path=transcript_path,
        run_summary=run_summary,
        run_manifest=run_manifest,
        receipt_rows=receipt_rows,
    )

    authoritative_receipt_path = (target_root / "cohort0_stronger_cycle_chaos_a_execution_receipt.json").resolve()
    write_json_stable(authoritative_receipt_path, receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_receipt = dict(receipt)
    tracked_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_CHAOS_A_EXECUTION_RECEIPT"
    tracked_receipt["authoritative_chaos_a_execution_receipt_ref"] = authoritative_receipt_path.as_posix()
    tracked_receipt_path = (reports_root / Path(DEFAULT_EXECUTION_RECEIPT_REL).name).resolve()
    write_json_stable(tracked_receipt_path, tracked_receipt)

    return {
        "chaos_a_execution_receipt": receipt,
        "tracked_chaos_a_execution_receipt": tracked_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Execute and bind Chaos Round A on the stronger-cycle branch.")
    ap.add_argument("--evidence-packet", default=DEFAULT_EVIDENCE_PACKET_REL)
    ap.add_argument("--stage-input-root", required=True)
    ap.add_argument("--base-model-dir", required=True)
    ap.add_argument("--external-artifact-root", required=True)
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <repo>/tmp/cohort0_stronger_cycle_chaos_a_current_head",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    ap.add_argument(
        "--existing-run-root",
        default="",
        help="Optional existing Chaos A run root for bind-only mode (used for testing).",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_chaos_a_execution_tranche(
        evidence_packet_path=_resolve_path(root, str(args.evidence_packet)),
        stage_input_root=_resolve_path(root, str(args.stage_input_root)),
        base_model_dir=_resolve_path(root, str(args.base_model_dir)),
        external_artifact_root=_resolve_path(root, str(args.external_artifact_root)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
        existing_run_root=_resolve_path(root, str(args.existing_run_root)) if str(args.existing_run_root).strip() else None,
    )
    receipt = payload["chaos_a_execution_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "execution_posture": receipt["execution_posture"],
                "adapter_count": receipt["adapter_count"],
                "source_eval_stub_count": receipt["source_eval_stub_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
