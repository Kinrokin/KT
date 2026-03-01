from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from schemas.schema_files import schema_version_hash
from tools.security.pack_guard_scan import scan_pack_and_write
from tools.training.fl3_factory.manifests import sha256_file
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.run_protocol_generator import verify_run_protocol_pair

from tools.delivery.redaction import apply_redactions, load_redaction_rules
from tools.delivery.template_renderer import render_template_file


MANIFEST_SCHEMA_FILE = "fl3/kt.delivery_pack_manifest.v1.json"


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail_if_nonempty_dir(path: Path, *, label: str) -> None:
    if path.exists():
        if not path.is_dir():
            raise FL3ValidationError(f"{label} must be a directory (fail-closed): {path.as_posix()}")
        if any(path.iterdir()):
            raise FL3ValidationError(f"{label} already exists and is non-empty (fail-closed): {path.as_posix()}")


def _iter_files_sorted(root: Path) -> Tuple[Path, ...]:
    files: List[Path] = []
    for p in root.rglob("*"):
        if p.is_file():
            files.append(p)
    files.sort(key=lambda p: p.relative_to(root).as_posix())
    return tuple(files)


def _safe_copy_tree_with_redaction(
    *,
    src_root: Path,
    dst_root: Path,
    redact_exts: Set[str],
    protected_relpaths: Set[str],
    rules: Iterable[Any],
) -> Set[str]:
    """
    Copy src_root into dst_root. Redact text files by extension unless protected.
    Returns set of relative paths (POSIX) that were redacted.
    """
    redacted: Set[str] = set()
    src_root = src_root.resolve()
    dst_root = dst_root.resolve()
    dst_root.mkdir(parents=True, exist_ok=True)

    for src in _iter_files_sorted(src_root):
        if src.is_symlink():
            raise FL3ValidationError(f"Refusing to copy symlink (fail-closed): {src.as_posix()}")
        rel = src.relative_to(src_root).as_posix()
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        if rel in protected_relpaths:
            shutil.copy2(src, dst)
            continue

        ext = src.suffix.lower()
        if ext in redact_exts:
            text = src.read_text(encoding="utf-8", errors="replace")
            out, _counts = apply_redactions(text=text, rules=rules)
            if out != text:
                redacted.add(rel)
            with dst.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(out)
                if not out.endswith("\n"):
                    handle.write("\n")
            continue

        shutil.copy2(src, dst)

    return redacted


def _build_delivery_manifest(
    *,
    run_id: str,
    bundle_root_hash: str,
    run_protocol_json_hash: str,
    redaction_rules_version: str,
    delivery_root: Path,
    redacted_relpaths: Set[str],
) -> Dict[str, Any]:
    created_at = _utc_now_z()

    files: List[Dict[str, Any]] = []
    for p in _iter_files_sorted(delivery_root):
        rel = p.relative_to(delivery_root).as_posix()
        if rel == "delivery_pack_manifest.json":
            continue  # avoid recursion
        digest = sha256_file(p)
        files.append(
            {
                "path": rel,
                "sha256": digest,
                "bytes": int(p.stat().st_size),
                "redacted": rel in redacted_relpaths,
            }
        )

    obj: Dict[str, Any] = {
        "schema_id": "kt.delivery_pack_manifest.v1",
        "schema_version_hash": schema_version_hash(MANIFEST_SCHEMA_FILE),
        "delivery_pack_id": "",
        "run_id": run_id,
        "bundle_root_hash": bundle_root_hash,
        "run_protocol_json_hash": run_protocol_json_hash,
        "redaction_rules_version": redaction_rules_version,
        "files": files,
        "created_at": created_at,
        "notes": None,
    }
    obj["delivery_pack_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "delivery_pack_id"}})
    validate_schema_bound_object(obj)
    return obj


def write_delivery_pack_manifest(*, delivery_root: Path, manifest: Dict[str, Any]) -> Path:
    out_path = delivery_root / "delivery_pack_manifest.json"
    text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    try:
        with out_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise FL3ValidationError("Refusing to overwrite delivery_pack_manifest.json (fail-closed)") from exc
    return out_path


def _zip_dir(*, src_dir: Path, zip_path: Path) -> None:
    try:
        with zipfile.ZipFile(zip_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for p in _iter_files_sorted(src_dir):
                rel = p.relative_to(src_dir).as_posix()
                zf.write(p, arcname=rel)
    except FileExistsError as exc:
        raise FL3ValidationError(f"Refusing to overwrite existing zip (fail-closed): {zip_path.as_posix()}") from exc


def _zip_sha256(zip_path: Path) -> str:
    return _sha256_bytes(zip_path.read_bytes())


def generate_delivery_pack(*, evidence_dir: Path, out_dir: Path) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))
    evidence_dir = evidence_dir.resolve()
    out_dir = out_dir.resolve()

    # Verify run_protocol pair exists and is canonical.
    run_protocol = verify_run_protocol_pair(
        json_path=evidence_dir / "run_protocol.json",
        md_path=evidence_dir / "RUN_PROTOCOL.md",
    )

    # Evidence packs must carry secret scan artifacts and they must PASS.
    evidence_secret_report_path = evidence_dir / "secret_scan_report.json"
    evidence_secret_summary_path = evidence_dir / "secret_scan_summary.json"
    evidence_secret_report = json.loads(evidence_secret_report_path.read_text(encoding="utf-8"))
    evidence_secret_summary = json.loads(evidence_secret_summary_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(evidence_secret_report)
    validate_schema_bound_object(evidence_secret_summary)
    if str(evidence_secret_summary.get("report_hash")) != str(evidence_secret_report.get("report_hash")):
        raise FL3ValidationError("FAIL_CLOSED: evidence secret_scan_summary.report_hash mismatch")
    if str(evidence_secret_summary.get("status")) != str(evidence_secret_report.get("status")):
        raise FL3ValidationError("FAIL_CLOSED: evidence secret_scan_summary.status mismatch")
    if str(run_protocol.get("secret_scan_result")) != str(evidence_secret_report.get("status")):
        raise FL3ValidationError("FAIL_CLOSED: run_protocol.secret_scan_result mismatch vs evidence secret scan")
    if str(evidence_secret_report.get("status")) != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: evidence secret scan status={evidence_secret_report.get('status')}")
    run_id = str(run_protocol.get("run_id", "")).strip()
    if not run_id:
        raise FL3ValidationError("run_protocol.run_id missing (fail-closed)")
    bundle_root_hash = str(run_protocol.get("bundle_root_hash", "")).strip()
    if len(bundle_root_hash) != 64:
        raise FL3ValidationError("run_protocol.bundle_root_hash missing/invalid (fail-closed)")

    pack_root = out_dir / f"KT_DELIVERY_{run_id}"
    zip_path = out_dir / f"KT_DELIVERY_{run_id}.zip"
    sha_path = Path(str(zip_path) + ".sha256")

    _fail_if_nonempty_dir(pack_root, label="delivery pack root")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy evidence into delivery root (client-safe surfaces redacted).
    rules_version, rules = load_redaction_rules(repo_root=repo_root)
    redact_exts = {".txt", ".md", ".log"}
    protected = {
        "evidence/run_protocol.json",
        "evidence/RUN_PROTOCOL.md",
        "evidence/secret_scan_report.json",
        "evidence/secret_scan_summary.json",
        "evidence/replay_receipt.json",
        "evidence/replay.sh",
        "evidence/replay.ps1",
    }
    evidence_dst = pack_root / "evidence"
    redacted = _safe_copy_tree_with_redaction(
        src_root=evidence_dir,
        dst_root=evidence_dst,
        redact_exts=redact_exts,
        protected_relpaths={p.replace("evidence/", "", 1) for p in protected if p.startswith("evidence/")},
        rules=rules,
    )
    # Map redacted relpaths into delivery-root relpaths (prefix evidence/).
    redacted_relpaths: Set[str] = {f"evidence/{p}" for p in redacted}

    # Derived client-facing docs.
    templates_dir = (Path(__file__).resolve().parent / "templates").resolve()
    reports_dir = pack_root / "reports"
    dashboard_dir = pack_root / "dashboard"
    reports_dir.mkdir(parents=True, exist_ok=True)
    dashboard_dir.mkdir(parents=True, exist_ok=True)

    adapter_id = ""
    adapters = run_protocol.get("active_adapters")
    if isinstance(adapters, list) and adapters:
        a0 = adapters[0] if isinstance(adapters[0], dict) else {}
        adapter_id = str(a0.get("adapter_id", "")).strip()

    mapping = {
        "RUN_ID": run_id,
        "LANE_ID": str(run_protocol.get("lane_id", "")),
        "TIMESTAMP_UTC": str(run_protocol.get("timestamp_utc", "")),
        "BASE_MODEL_ID": str(run_protocol.get("base_model_id", "")),
        "ADAPTER_ID": adapter_id or "<unknown>",
        "BUNDLE_ROOT_HASH": bundle_root_hash,
        "SECRET_SCAN_RESULT": str(run_protocol.get("secret_scan_result", "")),
        "REPLAY_COMMAND": str(run_protocol.get("replay_command", "")),
        "EXEC_ENV_HASH": str(run_protocol.get("execution_environment_hash", "")),
        "GOV_PHASE_HASH": str(run_protocol.get("governed_phase_start_hash", "")),
        "DETERMINISM_MODE": str(run_protocol.get("determinism_mode", "")),
        "IO_GUARD_STATUS": str(run_protocol.get("io_guard_status", "")),
        "NOTES": "See evidence/ for full receipts. This pack is redacted for client safety.",
    }

    def _render_and_write(rel_out: str, tmpl: str) -> None:
        text = render_template_file(template_path=templates_dir / tmpl, mapping=mapping)
        redacted_text, _counts = apply_redactions(text=text, rules=rules)
        if redacted_text != text:
            redacted_relpaths.add(rel_out)
        out_path = pack_root / rel_out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(redacted_text + "\n", encoding="utf-8")

    _render_and_write("reports/KT_EXEC_SUMMARY.md", "KT_EXEC_SUMMARY.md.tmpl")
    _render_and_write("reports/KT_TECHNICAL_REPORT.md", "KT_TECHNICAL_REPORT.md.tmpl")
    _render_and_write("reports/KT_GOV_RECOMMENDATIONS.md", "KT_GOV_RECOMMENDATIONS.md.tmpl")
    _render_and_write("dashboard/KT_DASHBOARD.html", "KT_DASHBOARD.html.tmpl")

    # Secret scan the final delivery directory (fail-closed).
    report, _summary = scan_pack_and_write(pack_root=pack_root, out_dir=pack_root, run_id=run_id, lane_id="DELIVERY_PACK")
    status = str(report.get("status", "ERROR"))
    if status != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: delivery pack secret scan status={status}")

    # Build + write schema-bound delivery manifest (excludes itself to avoid recursion).
    manifest = _build_delivery_manifest(
        run_id=run_id,
        bundle_root_hash=bundle_root_hash,
        run_protocol_json_hash=str(run_protocol.get("run_protocol_json_hash", "")),
        redaction_rules_version=rules_version,
        delivery_root=pack_root,
        redacted_relpaths=redacted_relpaths,
    )
    _ = write_delivery_pack_manifest(delivery_root=pack_root, manifest=manifest)

    # Zip the delivery directory and emit a sha256 sidecar.
    _zip_dir(src_dir=pack_root, zip_path=zip_path)
    zip_sha = _zip_sha256(zip_path)
    try:
        with sha_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(zip_sha + "\n")
    except FileExistsError as exc:
        raise FL3ValidationError("Refusing to overwrite delivery zip sha256 sidecar (fail-closed)") from exc

    return {
        "status": "PASS",
        "run_id": run_id,
        "delivery_dir": pack_root.as_posix(),
        "zip_path": zip_path.as_posix(),
        "zip_sha256": zip_sha,
        "redaction_rules_version": rules_version,
        "redacted_files": sorted(redacted_relpaths),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate a client-safe delivery zip from a sealed evidence pack (fail-closed).")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    result = generate_delivery_pack(evidence_dir=Path(args.evidence_dir), out_dir=Path(args.out_dir))
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(str(exc)) from exc
