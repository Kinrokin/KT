from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_change_receipt_schema import validate_fl3_change_receipt
from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.fl3_suite_registry_schema import validate_fl3_suite_registry
from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.verification.attestation_hmac import env_key_name_for_key_id, sign_hmac
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


_CHANGE_RECEIPT_SCHEMA_ID = "kt.change_receipt.v1"
_CHANGE_RECEIPT_SCHEMA_FILE = "fl3/kt.change_receipt.v1.json"


def _utc_now_compact_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _git(*, repo_root: Path, args: Sequence[str]) -> str:
    try:
        out = subprocess.check_output(["git", *args], cwd=str(repo_root), text=True)
    except subprocess.CalledProcessError as exc:
        raise FL3ValidationError(f"FAIL_CLOSED: git failed: {' '.join(args)} rc={exc.returncode}") from exc
    return (out or "").strip()


def _assert_clean_worktree(*, repo_root: Path) -> None:
    out = _git(repo_root=repo_root, args=["status", "--porcelain=v1"])
    if out.strip():
        raise FL3ValidationError("FAIL_CLOSED: repo is not clean (git status --porcelain=v1 non-empty)")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_env_fingerprint(env_name: str) -> str:
    v = os.environ.get(env_name, "")
    return hashlib.sha256((v or "").encode("utf-8")).hexdigest() if v else ""


def _must_get_env_key(*, key_id: str) -> bytes:
    env_name = env_key_name_for_key_id(key_id)
    key_val = os.environ.get(env_name)
    if not key_val:
        raise FL3ValidationError(f"BLOCKED_BY_MISSING_INPUTS:[{env_name}]")
    return key_val.encode("utf-8")


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def _update_hmac_signoff_in_place(*, signoff: Dict[str, Any], key_bytes: bytes) -> None:
    key_id = str(signoff.get("key_id", "")).strip()
    payload_hash = str(signoff.get("payload_hash", "")).strip()
    if not key_id or not payload_hash:
        raise FL3ValidationError("FAIL_CLOSED: malformed signoff (missing key_id/payload_hash)")

    sig, fp = sign_hmac(key_bytes=key_bytes, key_id=key_id, payload_hash=payload_hash)

    # Enforce HMAC-only field set (fail-closed).
    signoff.pop("simulated_signature", None)
    signoff.pop("pki_signature_b64", None)
    signoff.pop("pki_cert_fingerprint_sha256", None)

    signoff["attestation_mode"] = "HMAC"
    signoff["hmac_signature"] = sig
    signoff["hmac_key_fingerprint"] = fp
    signoff["signoff_id"] = sha256_hex_of_obj(signoff, drop_keys={"created_at", "signoff_id"})


def _suite_registry_expected_fingerprints(registry: Dict[str, Any]) -> Dict[str, str]:
    suites = registry.get("suites") if isinstance(registry.get("suites"), list) else []
    fps: Dict[str, str] = {}
    for row in suites:
        if not isinstance(row, dict):
            continue
        signoffs = row.get("signoffs") if isinstance(row.get("signoffs"), list) else []
        for s in signoffs:
            if not isinstance(s, dict):
                continue
            if str(s.get("attestation_mode", "")).strip().upper() != "HMAC":
                continue
            kid = str(s.get("key_id", "")).strip().upper()
            fp = str(s.get("hmac_key_fingerprint", "")).strip()
            if not kid or len(fp) != 64:
                continue
            if kid in fps and fps[kid] != fp:
                raise FL3ValidationError(f"FAIL_CLOSED: inconsistent hmac_key_fingerprint for key_id={kid}")
            fps[kid] = fp
    return fps


def _reseal_suite_registry_hmac(*, repo_root: Path) -> Tuple[str, str]:
    """
    Reseals KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json using current env HMAC keys.

    Returns: (old_suite_registry_id, new_suite_registry_id)
    """
    suite_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITE_REGISTRY_FL3.json").resolve()
    reg = _read_json_dict(suite_path, name="suite_registry")
    validate_fl3_suite_registry(reg)
    if str(reg.get("attestation_mode", "")).strip().upper() != "HMAC":
        raise FL3ValidationError("FAIL_CLOSED: suite registry must be HMAC for canonical lane reseal")
    old_id = str(reg.get("suite_registry_id", "")).strip()

    suites = reg.get("suites") if isinstance(reg.get("suites"), list) else []
    for row in suites:
        if not isinstance(row, dict):
            raise FL3ValidationError("FAIL_CLOSED: suite registry suites[] must contain objects")
        signoffs = row.get("signoffs") if isinstance(row.get("signoffs"), list) else None
        if not isinstance(signoffs, list) or len(signoffs) < 2:
            raise FL3ValidationError("FAIL_CLOSED: suite entry signoffs missing/invalid")
        for s in signoffs:
            if not isinstance(s, dict):
                raise FL3ValidationError("FAIL_CLOSED: suite signoff must be object")
            kid = str(s.get("key_id", "")).strip()
            key_bytes = _must_get_env_key(key_id=kid)
            _update_hmac_signoff_in_place(signoff=s, key_bytes=key_bytes)
        signoffs.sort(key=lambda x: (str(x.get("key_id", "")).strip(), str(x.get("signoff_id", "")).strip()))

    # Optional: refresh created_at to reseal time (not part of hash surface).
    reg["created_at"] = reg.get("created_at") or _utc_now_iso_z()

    # suite_registry_id binds to signoffs (hash surface) but drops created_at and suite_registry_id itself.
    reg["suite_registry_id"] = sha256_hex_of_obj(reg, drop_keys={"created_at", "suite_registry_id"})
    validate_fl3_suite_registry(reg)

    _write_json(suite_path, reg)
    new_id = str(reg.get("suite_registry_id", "")).strip()
    return old_id, new_id


def _sync_law_bundle_sha(*, repo_root: Path) -> Tuple[str, str]:
    """
    Recompute and update LAW_BUNDLE_FL3.sha256 from the current worktree.
    Returns: (old_pinned_hash, new_hash)
    """
    sha_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").resolve()
    old = sha_path.read_text(encoding="utf-8").strip() if sha_path.exists() else ""

    bundle = load_law_bundle(repo_root=repo_root)
    new_hash = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
    desired = new_hash + "\n"
    if old.strip() != new_hash:
        sha_path.parent.mkdir(parents=True, exist_ok=True)
        sha_path.write_text(desired, encoding="utf-8", newline="\n")
    return old.strip(), new_hash


def _ensure_law_amendment_hmac(*, repo_root: Path, bundle_hash: str) -> Path:
    # Import locally to keep this epic focused and avoid incidental side effects.
    from tools.verification.derive_fl4_seal_artifacts import _ensure_law_amendment_present  # noqa: PLC0415

    amend = _ensure_law_amendment_present(repo_root=repo_root, bundle_hash=bundle_hash, write=True, attestation_mode="HMAC")
    if amend is None:
        raise FL3ValidationError("FAIL_CLOSED: failed to ensure LAW_AMENDMENT (unexpected)")
    return Path(amend).resolve()


def _run_logged(
    *,
    repo_root: Path,
    run_root: Path,
    name: str,
    cmd: Sequence[str],
    env: Dict[str, str],
    allow_nonzero: bool = False,
) -> Tuple[int, str, Path]:
    p = subprocess.run(
        list(cmd),
        cwd=str(repo_root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out = p.stdout or ""
    log_path = (run_root / "transcripts" / f"{name}.log").resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_worm(path=log_path, text=out if out.endswith("\n") else out + "\n", label=f"{name}.log")
    rc = int(p.returncode)
    if rc != 0 and not allow_nonzero:
        raise FL3ValidationError(f"FAIL_CLOSED: command failed: {name} rc={rc} cmd={' '.join(cmd)}")
    return rc, out, log_path


def _base_env(*, repo_root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _update_operator_profile_pins(*, repo_root: Path, new_law_hash: str, new_suite_registry_id: str, new_receipt_path: str) -> None:
    kt_cli_path = (repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "kt_cli.py").resolve()
    text = kt_cli_path.read_text(encoding="utf-8")

    t1 = re.sub(r'law_bundle_hash="[^"]{64}"', f'law_bundle_hash="{new_law_hash}"', text, count=1)
    if t1 == text:
        raise FL3ValidationError("FAIL_CLOSED: unable to update kt_cli law_bundle_hash pin (no match)")
    t2 = re.sub(r'suite_registry_id="[^"]{64}"', f'suite_registry_id="{new_suite_registry_id}"', t1, count=1)
    if t2 == t1:
        raise FL3ValidationError("FAIL_CLOSED: unable to update kt_cli suite_registry_id pin (no match)")

    # authoritative_reseal_receipt is an evidence pointer; update it to the new post receipt.
    t3 = re.sub(
        r'authoritative_reseal_receipt=\([\s\S]*?\)\s*,\s*router_policy_ref=',
        f'authoritative_reseal_receipt=("{new_receipt_path}"),\n    router_policy_ref=',
        t2,
        count=1,
        flags=re.MULTILINE,
    )
    if t3 == t2:
        raise FL3ValidationError("FAIL_CLOSED: unable to update kt_cli authoritative_reseal_receipt pin")

    kt_cli_path.write_text(t3, encoding="utf-8", newline="\n")


def _mint_change_receipt(
    *,
    repo_root: Path,
    out_path: Path,
    actor: str,
    phase: str,
    phase_id: str,
    files_checked: List[Tuple[str, str]],
    outcome: str,
    notes: str,
) -> Dict[str, Any]:
    rows = [{"path": p, "sha256": sh} for p, sh in sorted(files_checked, key=lambda x: x[0])]
    receipt: Dict[str, Any] = {
        "schema_id": _CHANGE_RECEIPT_SCHEMA_ID,
        "schema_version_hash": schema_version_hash(_CHANGE_RECEIPT_SCHEMA_FILE),
        "change_id": "",
        "actor": str(actor).strip(),
        "phase": str(phase).strip().lower(),
        "phase_id": str(phase_id).strip(),
        "timestamp_utc": _utc_now_iso_z(),
        "files_checked": rows,
        "outcome": str(outcome).strip().upper(),
        "notes": str(notes),
    }
    receipt["change_id"] = _sha256_text(_canonical_json({k: v for k, v in receipt.items() if k != "change_id"}))
    validate_fl3_change_receipt(receipt)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    except FileExistsError as exc:
        raise FL3ValidationError(f"FAIL_CLOSED: refusing to overwrite receipt: {out_path.as_posix()}") from exc

    _ = _read_json_dict(out_path, name="change_receipt_written")
    return receipt


def _require_pre_sweep(*, run_root: Path) -> Path:
    sweeps = (run_root / "sweeps").resolve()
    if not sweeps.exists():
        raise FL3ValidationError("BLOCKED_BY_MISSING_INPUTS:[sweeps/PRE_*/sweep_summary.json]")
    candidates = sorted(sweeps.glob("PRE_*/sweep_summary.json"))
    if not candidates:
        raise FL3ValidationError("BLOCKED_BY_MISSING_INPUTS:[sweeps/PRE_*/sweep_summary.json]")
    return candidates[-1].resolve()


def _git_commit_all(*, repo_root: Path, message: str) -> str:
    _ = subprocess.check_call(["git", "add", "-A"], cwd=str(repo_root))
    _ = subprocess.check_call(["git", "commit", "-m", message], cwd=str(repo_root))
    return _git(repo_root=repo_root, args=["rev-parse", "HEAD"])


@dataclass(frozen=True)
class EpicPaths:
    run_root: Path
    reports_dir: Path


def _mk_epic_paths(*, repo_root: Path, run_root: Path) -> EpicPaths:
    rr = run_root
    if not rr.is_absolute():
        rr = (repo_root / rr).resolve()
    rr.mkdir(parents=True, exist_ok=True)
    reports = (rr / "reports").resolve()
    (rr / "transcripts").mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    return EpicPaths(run_root=rr, reports_dir=reports)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "EPIC: Reseal SUITE_REGISTRY_FL3.json under rotated HMAC keys and "
            "update dependent law pins + receipts (fail-closed)."
        )
    )
    ap.add_argument("--epic-id", default="EPIC_HMAC_RESEAL_V1", help="Epic id used in receipts and sweep ids.")
    ap.add_argument(
        "--run-root",
        default="",
        help="Run root under KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/. If omitted, a new timestamped root is used.",
    )
    ap.add_argument("--actor", default="kt-operator", help="Actor string for kt.change_receipt.v1.")
    ap.add_argument(
        "--branch",
        default="",
        help="Branch to create/switch to before committing. Default: ops/<epic-id>-<utc>.",
    )
    ap.add_argument("--no-commit", action="store_true", help="Do not git commit. Leaves working tree dirty (not recommended).")
    ap.add_argument("--skip-post", action="store_true", help="Skip POST sweep + readiness + canonical_hmac certify.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    epic_id = str(args.epic_id).strip() or "EPIC_HMAC_RESEAL_V1"

    env_fp_a = _sha256_env_fingerprint("KT_HMAC_KEY_SIGNER_A")
    env_fp_b = _sha256_env_fingerprint("KT_HMAC_KEY_SIGNER_B")
    if not env_fp_a or not env_fp_b:
        raise FL3ValidationError("BLOCKED_BY_MISSING_INPUTS:[KT_HMAC_KEY_SIGNER_A,KT_HMAC_KEY_SIGNER_B]")

    _assert_clean_worktree(repo_root=repo_root)
    old_head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

    default_root = (
        repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs" / "KT_OPERATOR" / f"{_utc_now_compact_z()}_{epic_id}"
    )
    run_root = Path(str(args.run_root).strip()) if str(args.run_root).strip() else default_root
    paths = _mk_epic_paths(repo_root=repo_root, run_root=run_root)

    pre_summary_path = _require_pre_sweep(run_root=paths.run_root)
    pre_summary_sha = sha256_file_canonical(pre_summary_path)

    suite_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITE_REGISTRY_FL3.json").resolve()
    law_sha_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").resolve()
    old_suite_sha = sha256_file_canonical(suite_path)
    old_law_sha = sha256_file_canonical(law_sha_path) if law_sha_path.exists() else ""

    reg = _read_json_dict(suite_path, name="suite_registry_pre")
    validate_fl3_suite_registry(reg)
    pinned_fps = _suite_registry_expected_fingerprints(reg)
    keys_already_match = bool(
        pinned_fps.get("SIGNER_A") == env_fp_a and pinned_fps.get("SIGNER_B") == env_fp_b and env_fp_a and env_fp_b
    )
    if keys_already_match:
        raise FL3ValidationError(
            "FAIL_CLOSED: env HMAC key fingerprints already match SUITE_REGISTRY pins; "
            "rotation not detected. Run rotate_hmac_keys.ps1 first, then rerun this epic."
        )

    if not bool(args.no_commit):
        branch = str(args.branch).strip() or f"ops/{epic_id.lower()}-{_utc_now_compact_z()}"
        _ = subprocess.check_call(["git", "switch", "-c", branch], cwd=str(repo_root))
        _assert_clean_worktree(repo_root=repo_root)

    old_suite_id, new_suite_id = _reseal_suite_registry_hmac(repo_root=repo_root)
    new_suite_sha = sha256_file_canonical(suite_path)

    old_law_hash, new_law_hash = _sync_law_bundle_sha(repo_root=repo_root)
    new_law_sha = sha256_file_canonical(law_sha_path)

    env = _base_env(repo_root=repo_root)
    _rc_law, out_law, _log = _run_logged(
        repo_root=repo_root,
        run_root=paths.run_root,
        name="law_bundle_change_receipt",
        cmd=[sys.executable, "-m", "tools.verification.law_bundle_change_receipt", "--old-ref", old_head],
        env=env,
    )
    change_receipt_path = Path(str(out_law).strip().splitlines()[-1]).resolve()
    if not change_receipt_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: law_bundle_change_receipt tool did not emit a valid path")
    change_receipt_sha = sha256_file_canonical(change_receipt_path)

    amend_path = _ensure_law_amendment_hmac(repo_root=repo_root, bundle_hash=new_law_hash)
    amend_sha = sha256_file_canonical(amend_path)

    receipts_dir = (repo_root / "KT_PROD_CLEANROOM" / "06_ARCHIVE_VAULT" / "receipts").resolve()
    pre_receipt_path = receipts_dir / f"KT_CHANGE_RECEIPT_{epic_id}_PRE_{_utc_now_compact_z()}.json"
    _ = _mint_change_receipt(
        repo_root=repo_root,
        out_path=pre_receipt_path,
        actor=str(args.actor),
        phase="pre",
        phase_id=epic_id,
        files_checked=[
            ("KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256", old_law_sha),
            ("KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json", old_suite_sha),
            (str(pre_summary_path.relative_to(repo_root)).replace("\\", "/"), pre_summary_sha),
        ],
        outcome="PASS",
        notes=(
            f"{epic_id} PRE: baseline sweep before HMAC reseal. "
            f"old_head={old_head} old_law_bundle_hash={old_law_hash} old_suite_registry_id={old_suite_id} "
            f"env_fp_a={env_fp_a} env_fp_b={env_fp_b}"
        ),
    )
    pre_receipt_sha = sha256_file_canonical(pre_receipt_path)

    post_receipt_path = receipts_dir / f"KT_CHANGE_RECEIPT_{epic_id}_POST_{_utc_now_compact_z()}.json"

    _update_operator_profile_pins(
        repo_root=repo_root,
        new_law_hash=new_law_hash,
        new_suite_registry_id=new_suite_id,
        new_receipt_path=str(post_receipt_path.relative_to(repo_root)).replace("\\", "/"),
    )

    new_head = old_head
    if bool(args.no_commit):
        new_head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])
    else:
        new_head = _git_commit_all(
            repo_root=repo_root,
            message=f"ops: HMAC reseal suite registry + law pins ({epic_id})",
        )
        _assert_clean_worktree(repo_root=repo_root)

    post_summary_path: Optional[Path] = None
    post_summary_sha: Optional[str] = None
    readiness_verdict: str = ""
    readiness_json_rel: Optional[str] = None
    certify_verdict: str = ""
    certify_run_dir: Optional[Path] = None

    if not bool(args.skip_post):
        sweep_id_post = f"POST_{epic_id}"
        _rc_post, _out_post, _ = _run_logged(
            repo_root=repo_root,
            run_root=paths.run_root,
            name="run_sweep_audit_post",
            cmd=[
                sys.executable,
                "-m",
                "tools.verification.run_sweep_audit",
                "--run-root",
                str(paths.run_root),
                "--sweep-id",
                sweep_id_post,
            ],
            env=env,
        )
        _ = _rc_post
        post_summary_path = (paths.run_root / "sweeps" / sweep_id_post / "sweep_summary.json").resolve()
        if not post_summary_path.exists():
            raise FL3ValidationError("FAIL_CLOSED: missing POST sweep_summary.json (unexpected)")
        post_summary_sha = sha256_file_canonical(post_summary_path)

        readiness_root = (paths.run_root / "readiness_grade").resolve()
        rc_rg, out_rg, _ = _run_logged(
            repo_root=repo_root,
            run_root=paths.run_root,
            name="readiness_grade",
            cmd=[sys.executable, "-m", "tools.operator.readiness_grade", "--profile", "v1", "--run-root", str(readiness_root)],
            env=env,
            allow_nonzero=True,
        )
        readiness_verdict = (out_rg.strip().splitlines()[-1] if out_rg.strip() else f"RC={rc_rg}")
        readiness_json = (readiness_root / "reports" / "readiness_grade.json").resolve()
        readiness_json_rel = str(readiness_json.relative_to(repo_root)).replace("\\", "/") if readiness_json.exists() else None

        certify_root = (paths.run_root / "certify_canonical_hmac").resolve()
        rc_cc, out_cc, _ = _run_logged(
            repo_root=repo_root,
            run_root=paths.run_root,
            name="certify_canonical_hmac",
            cmd=[
                sys.executable,
                "-m",
                "tools.operator.kt_cli",
                "--profile",
                "v1",
                "--run-root",
                str(certify_root),
                "certify",
                "--lane",
                "canonical_hmac",
            ],
            env=env,
        )
        _ = rc_cc
        certify_verdict = out_cc.strip().splitlines()[-1] if out_cc.strip() else "MISSING_VERDICT"
        certify_run_dir = certify_root

    post_files: List[Tuple[str, str]] = [
        ("KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256", new_law_sha),
        ("KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json", new_suite_sha),
        (str(change_receipt_path.relative_to(repo_root)).replace("\\", "/"), change_receipt_sha),
        (str(amend_path.relative_to(repo_root)).replace("\\", "/"), amend_sha),
        (str(pre_receipt_path.relative_to(repo_root)).replace("\\", "/"), pre_receipt_sha),
    ]
    if post_summary_path and post_summary_sha:
        post_files.append((str(post_summary_path.relative_to(repo_root)).replace("\\", "/"), post_summary_sha))

    _ = _mint_change_receipt(
        repo_root=repo_root,
        out_path=post_receipt_path,
        actor=str(args.actor),
        phase="post",
        phase_id=epic_id,
        files_checked=post_files,
        outcome="PASS",
        notes=(
            f"{epic_id} POST: HMAC reseal completed. "
            f"old_head={old_head} new_head={new_head} old_law_bundle_hash={old_law_hash} new_law_bundle_hash={new_law_hash} "
            f"old_suite_registry_id={old_suite_id} new_suite_registry_id={new_suite_id} "
            f"env_fp_a={env_fp_a} env_fp_b={env_fp_b} "
            f"readiness_verdict={readiness_verdict} certify_verdict={certify_verdict}"
        ),
    )

    report: Dict[str, Any] = {
        "schema_id": "kt.operator.epic_hmac_reseal_report.unbound.v1",
        "created_utc": _utc_now_iso_z(),
        "epic_id": epic_id,
        "git": {"old_head": old_head, "new_head": new_head},
        "hmac_key_fingerprints": {"SIGNER_A": env_fp_a, "SIGNER_B": env_fp_b},
        "suite_registry": {
            "path": "KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json",
            "old_suite_registry_id": old_suite_id,
            "new_suite_registry_id": new_suite_id,
            "old_sha256": old_suite_sha,
            "new_sha256": new_suite_sha,
        },
        "law_bundle": {
            "path": "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
            "old_pinned_hash": old_law_hash,
            "new_hash": new_law_hash,
            "old_sha256": old_law_sha,
            "new_sha256": new_law_sha,
            "change_receipt_path": str(change_receipt_path.relative_to(repo_root)).replace("\\", "/"),
            "change_receipt_sha256": change_receipt_sha,
            "law_amendment_path": str(amend_path.relative_to(repo_root)).replace("\\", "/"),
            "law_amendment_sha256": amend_sha,
        },
        "sweeps": {
            "pre_summary_path": str(pre_summary_path.relative_to(repo_root)).replace("\\", "/"),
            "pre_summary_sha256": pre_summary_sha,
            "post_summary_path": (str(post_summary_path.relative_to(repo_root)).replace("\\", "/") if post_summary_path else None),
            "post_summary_sha256": post_summary_sha,
        },
        "operator_runs": {
            "readiness_verdict": readiness_verdict,
            "readiness_grade_json": readiness_json_rel,
            "certify_verdict": certify_verdict,
            "certify_run_dir": (str(certify_run_dir.relative_to(repo_root)).replace("\\", "/") if certify_run_dir else None),
        },
        "receipts": {
            "pre_receipt_path": str(pre_receipt_path.relative_to(repo_root)).replace("\\", "/"),
            "post_receipt_path": str(post_receipt_path.relative_to(repo_root)).replace("\\", "/"),
        },
        "run_root": str(paths.run_root.relative_to(repo_root)).replace("\\", "/"),
    }
    report_path = (paths.reports_dir / f"{epic_id}_E2E_REPORT_{_utc_now_compact_z()}.json").resolve()
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"STEP_COMPLETE:{epic_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        msg = str(exc)
        if msg.startswith(("BLOCKED_BY_MISSING_INPUTS:", "FAIL_CLOSED:", "AWAITING_OPERATOR_APPROVAL:")):
            print(msg)
        else:
            print(f"FAIL_CLOSED:{msg}")
        raise SystemExit(2) from exc
