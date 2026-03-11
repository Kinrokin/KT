from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import (
    canonical_file_sha256,
    load_json,
    make_run_dir,
    repo_root,
    utc_now_iso_z,
    write_failure_artifacts,
    write_json_worm,
)


def _registry_path(root: Path) -> Path:
    return (root / "KT_PROD_CLEANROOM" / "governance" / "pin_registry.json").resolve()


def _manifest_path(root: Path) -> Path:
    return (root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").resolve()


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(root), text=True).strip()


def _git_lines(root: Path, *args: str) -> List[str]:
    output = _git(root, *args)
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _resolve_repo_path(root: Path, relpath: str) -> Path:
    path = (root / str(relpath)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required path: {path.as_posix()}")
    return path


def _hash_target(root: Path, target_name: str, target_cfg: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(target_cfg.get("mode", "")).strip()
    if mode == "canonical_json":
        path = _resolve_repo_path(root, str(target_cfg["path"]))
        digest = canonical_file_sha256(path)
        return {"target": target_name, "mode": mode, "path": path.as_posix(), "sha256": digest}
    if mode == "locator_bundle":
        locator = _resolve_repo_path(root, str(target_cfg["locator_path"]))
        locator_obj = load_json(locator)
        files = locator_obj.get("files")
        if not isinstance(files, list) or not files:
            raise RuntimeError(f"FAIL_CLOSED: locator bundle missing files: {locator.as_posix()}")
        entries: List[Dict[str, str]] = []
        for rel in sorted(str(x) for x in files):
            file_path = _resolve_repo_path(root, rel)
            digest = canonical_file_sha256(file_path) if file_path.suffix.lower() == ".json" else hashlib.sha256(file_path.read_bytes()).hexdigest()
            entries.append({"path": rel.replace("\\", "/"), "sha256": digest})
        bundle = {"files": entries, "locator_path": str(target_cfg["locator_path"]).replace("\\", "/"), "mode": mode}
        digest = sha256_hex(canonicalize_bytes(bundle))
        return {"target": target_name, "mode": mode, "path": locator.as_posix(), "sha256": digest, "entries": entries}
    raise RuntimeError(f"FAIL_CLOSED: unsupported pin target mode={mode!r} target={target_name}")


def compute_all_targets(root: Path) -> Dict[str, Dict[str, Any]]:
    registry = load_json(_registry_path(root))
    targets = registry.get("targets")
    if not isinstance(targets, dict):
        raise RuntimeError("FAIL_CLOSED: pin_registry.targets missing or invalid")
    out: Dict[str, Dict[str, Any]] = {}
    for name in sorted(targets.keys()):
        cfg = targets[name]
        if not isinstance(cfg, dict):
            raise RuntimeError(f"FAIL_CLOSED: invalid target config for {name}")
        out[name] = _hash_target(root, str(name), cfg)
    return out


def _subject_scope(root: Path, registry: Dict[str, Any]) -> Dict[str, Any]:
    targets = registry.get("targets")
    if not isinstance(targets, dict):
        raise RuntimeError("FAIL_CLOSED: pin_registry.targets missing or invalid")
    return {
        "kind": "candidate_tracked_worktree_required_pin_targets_only",
        "branch_ref": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "validated_head_sha": _git(root, "rev-parse", "HEAD"),
        "required_pin_targets": sorted(str(name) for name in targets.keys()),
        "tracked_delta_paths": _git_lines(root, "diff", "--name-only"),
        "excluded_untracked_paths": _git_lines(root, "ls-files", "--others", "--exclude-standard"),
        "excluded_generated_run_globs": ["KT_PROD_CLEANROOM/exports/_runs/**"],
        "excludes_untracked_from_pin_inputs": True,
        "excludes_generated_runs_from_pin_inputs": True,
        "pin_inputs_are_explicit_registry_targets_only": True,
    }


def _verify_hmac_sig(*, manifest_sha256: str, signer: str, sig_file: Path) -> Dict[str, Any]:
    sig_obj = load_json(sig_file)
    if str(sig_obj.get("signer", "")).strip() != signer:
        raise RuntimeError(f"FAIL_CLOSED: signature signer mismatch for {signer}")
    if str(sig_obj.get("manifest_sha256", "")).strip() != manifest_sha256:
        raise RuntimeError(f"FAIL_CLOSED: signature manifest sha mismatch for {signer}")
    env_var = "KT_HMAC_KEY_SIGNER_A" if signer == "OP1" else "KT_HMAC_KEY_SIGNER_B"
    key = str(__import__("os").environ.get(env_var, "")).strip()
    if not key:
        raise RuntimeError(f"FAIL_CLOSED: missing env key for signer {signer}: {env_var}")
    expected = hmac.new(key.encode("utf-8"), manifest_sha256.encode("utf-8"), hashlib.sha256).hexdigest()
    actual = str(sig_obj.get("hmac_sha256", "")).strip()
    if not hmac.compare_digest(expected, actual):
        raise RuntimeError(f"FAIL_CLOSED: hmac signature mismatch for {signer}")
    return {"signer": signer, "sig_file": sig_file.as_posix(), "status": "PASS"}


def _cmd_compute(*, run_dir: Path, target_name: str) -> int:
    root = repo_root()
    registry = load_json(_registry_path(root))
    computed = compute_all_targets(root)
    if target_name and target_name != "all":
        if target_name not in computed:
            raise RuntimeError(f"FAIL_CLOSED: unknown target={target_name}")
        selected = {target_name: computed[target_name]}
    else:
        selected = computed
    subject_scope = _subject_scope(root, registry)
    report = {
        "schema_id": "kt.operator.hashpin_results.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": subject_scope["branch_ref"],
        "validated_head_sha": subject_scope["validated_head_sha"],
        "subject_scope": subject_scope,
        "targets": selected,
    }
    receipt = {
        "schema_id": "kt.operator.hashpin_receipt.v1",
        "generated_utc": report["generated_utc"],
        "branch_ref": report["branch_ref"],
        "validated_head_sha": report["validated_head_sha"],
        "subject_scope_kind": subject_scope["kind"],
        "target_count": len(selected),
        "status": "PASS",
    }
    write_json_worm(run_dir / "reports" / "hashpin_results.json", report, label="hashpin_results.json")
    write_json_worm(run_dir / "reports" / "hashpin_receipt.json", receipt, label="hashpin_receipt.json")
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0


def _cmd_verify_required_pins(*, run_dir: Path) -> int:
    root = repo_root()
    registry = load_json(_registry_path(root))
    manifest = load_json(_manifest_path(root))
    computed = compute_all_targets(root)
    subject_scope = _subject_scope(root, registry)
    failures: List[str] = []
    checked: List[Dict[str, Any]] = []
    for pin in registry.get("required_pins", []):
        if not isinstance(pin, dict):
            continue
        target = str(pin.get("target", "")).strip()
        pin_id = str(pin.get("pin_id", "")).strip()
        expected = computed[target]["sha256"]
        manifest_field = str(pin.get("manifest_field", "")).strip()
        registry_sha = str(pin.get("current_sha256", "")).strip()
        status = str(pin.get("status", "")).strip()
        manifest_sha = str(manifest.get(manifest_field, "")).strip()
        if status != "PINNED":
            failures.append(f"{pin_id}:status={status or 'MISSING'}")
        if registry_sha != expected:
            failures.append(f"{pin_id}:registry_sha_mismatch")
        if manifest_sha != expected:
            failures.append(f"{pin_id}:manifest_sha_mismatch")
        checked.append({"pin_id": pin_id, "target": target, "expected_sha256": expected, "status": status})
    report = {
        "schema_id": "kt.operator.hashpin_verification.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": subject_scope["branch_ref"],
        "validated_head_sha": subject_scope["validated_head_sha"],
        "subject_scope": subject_scope,
        "checked": checked,
        "status": "PASS" if not failures else "FAIL",
    }
    if failures:
        report["failures"] = failures
    write_json_worm(run_dir / "reports" / "hashpin_verification.json", report, label="hashpin_verification.json")
    if failures:
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.hashpin.verify_required_pins",
            failure_name="PIN_MISSING",
            message="; ".join(failures),
            next_actions=[
                "python -m tools.operator.hashpin compute --target all",
                "Update KT_PROD_CLEANROOM/governance/pin_registry.json current_sha256/status.",
                "Update KT_PROD_CLEANROOM/governance/governance_manifest.json pinned fields.",
            ],
        )
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 0


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT hash pin compute/verify.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap_compute = sub.add_parser("compute")
    ap_compute.add_argument("--target", default="all")
    ap_compute.add_argument("--run-root", default="")
    ap_verify = sub.add_parser("verify-required-pins")
    ap_verify.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="hashpin", requested_run_root=str(getattr(args, "run_root", "")))
    try:
        if args.cmd == "compute":
            return _cmd_compute(run_dir=run_dir, target_name=str(args.target))
        return _cmd_verify_required_pins(run_dir=run_dir)
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id=f"program.hashpin.{str(args.cmd).replace('-', '_')}",
            failure_name="PIN_MISSING",
            message=str(exc),
            next_actions=["Inspect reports/hashpin_results.json or reports/hashpin_verification.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
