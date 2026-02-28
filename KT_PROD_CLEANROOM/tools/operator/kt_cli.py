from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_suite_registry_schema import validate_fl3_suite_registry
from tools.delivery.delivery_linter import lint_delivery_dir
from tools.delivery.generate_delivery_pack import generate_delivery_pack
from tools.security.pack_guard_scan import scan_pack_and_write
from tools.training.fl3_factory.io import write_schema_object
from tools.training.fl3_factory.manifests import build_hash_manifest, sha256_file
from tools.verification.fl3_canonical import repo_root_from, sha256_json
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle
from tools.verification.replay_script_generator import write_replay_artifacts
from tools.verification.run_protocol_generator import build_run_protocol, write_run_protocol_pair
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_bytes_worm, write_text_worm


@dataclass(frozen=True)
class V1Profile:
    name: str
    sealed_commit: str
    sealed_tag: str
    law_bundle_hash: str
    suite_registry_id: str
    determinism_expected_root_hash: str
    authoritative_reseal_receipt: str
    router_policy_ref: str
    router_demo_suite_ref: str


V1 = V1Profile(
    name="v1",
    sealed_commit="7b7f6e71d43c0aa60d4bc91be47e679491883871",
    sealed_tag="KT_V1_SEALED_20260217",
    law_bundle_hash="cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906",
    suite_registry_id="e7a37cdc2a84b042dc1f594d1f84b4ba0a843c49de4925a06e6117fbac1eff17",
    determinism_expected_root_hash="c574cd28deba7020b1ff41f249c02f403cbe8e045cb961222183880977bdb10e",
    authoritative_reseal_receipt=(
        "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/receipts/"
        "KT_CHANGE_RECEIPT_EPIC24_V1_RESEAL_UNDER_CURRENT_LAW_FIX_POST_CANONICAL_HMAC_20260217T225856Z.json"
    ),
    router_policy_ref="KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_POLICY_HAT_V1.json",
    router_demo_suite_ref="KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_DEMO_SUITE_V1.json",
)


def _utc_now_compact_z() -> str:
    # Microseconds included to avoid collisions in operator workflows.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runs_root(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()


def _seal_mode_tests_root(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_tmp" / "tests").resolve()


def _default_run_dir(*, repo_root: Path, cmd_name: str) -> Path:
    return (_runs_root(repo_root) / "KT_OPERATOR" / f"{_utc_now_compact_z()}_{cmd_name}").resolve()


def _assert_under_runs_root(*, repo_root: Path, path: Path) -> None:
    target = path.resolve()
    allowed = [_runs_root(repo_root)]
    if os.environ.get("KT_SEAL_MODE") == "1":
        allowed.append(_seal_mode_tests_root(repo_root))
    for rr in allowed:
        try:
            target.relative_to(rr)
            return
        except Exception:
            continue
    allowed_s = ", ".join(r.as_posix() for r in allowed)
    raise FL3ValidationError(f"FAIL_CLOSED: run_root must be under one of: {allowed_s} (got {target.as_posix()})")


def _mk_run_dir(*, repo_root: Path, cmd_name: str, requested_run_root: Optional[str]) -> Path:
    if requested_run_root:
        run_dir = Path(str(requested_run_root)).expanduser()
        if not run_dir.is_absolute():
            run_dir = (repo_root / run_dir).resolve()
        _assert_under_runs_root(repo_root=repo_root, path=run_dir)
    else:
        run_dir = _default_run_dir(repo_root=repo_root, cmd_name=cmd_name)
        _assert_under_runs_root(repo_root=repo_root, path=run_dir)

    if run_dir.exists():
        # WORM semantics: never reuse a non-empty directory.
        has_any = any(run_dir.iterdir())
        if has_any:
            raise FL3ValidationError(f"FAIL_CLOSED: run_root collision (non-empty): {run_dir.as_posix()}")
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


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

def _maybe_assert_clean_worktree(*, repo_root: Path, allow_dirty: bool) -> None:
    if allow_dirty:
        return
    _assert_clean_worktree(repo_root=repo_root)


def _base_env(*, repo_root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    # Drop obvious cloud/network credential surfaces to keep operator runs inert.
    for name in list(env.keys()):
        if name.startswith(("AWS_", "AZURE_", "GCP_", "OPENAI_")):
            env.pop(name, None)
    env["PYTHONPATH"] = str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(
        repo_root / "KT_PROD_CLEANROOM"
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run_cmd(
    *,
    repo_root: Path,
    run_dir: Path,
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
    log_path = (run_dir / "transcripts" / f"{name}.log").resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_worm(path=log_path, text=out if out.endswith("\n") else out + "\n", label=f"{name}.log")
    rc = int(p.returncode)
    if rc != 0 and not allow_nonzero:
        raise FL3ValidationError(f"FAIL_CLOSED: command failed: {name} rc={rc} cmd={' '.join(cmd)}")
    return rc, out, log_path


def _keys_presence_len() -> Dict[str, Dict[str, int | bool]]:
    out: Dict[str, Dict[str, int | bool]] = {}
    for k in ("KT_HMAC_KEY_SIGNER_A", "KT_HMAC_KEY_SIGNER_B"):
        v = os.environ.get(k)
        out[k] = {"present": bool(v), "length": (len(v) if v else 0)}
    return out


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)

def _copy_tree_worm(*, src_root: Path, dst_root: Path, label: str) -> None:
    src_root = src_root.resolve()
    dst_root = dst_root.resolve()
    if not src_root.exists() or not src_root.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: missing source dir for evidence copy: {src_root.as_posix()}")
    dst_root.mkdir(parents=True, exist_ok=True)

    paths: List[Path] = []
    for p in src_root.rglob("*"):
        if not p.is_file():
            continue
        if p.is_symlink():
            raise FL3ValidationError(f"FAIL_CLOSED: refusing to copy symlink into evidence: {p.as_posix()}")
        paths.append(p)
    paths.sort(key=lambda p: p.relative_to(src_root).as_posix())

    for p in paths:
        rel = p.relative_to(src_root).as_posix()
        out_path = (dst_root / rel).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        write_bytes_worm(path=out_path, data=p.read_bytes(), label=f"{label}:{rel}")


def _emit_delivery_bundle_canonical_hmac(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    head: str,
    sweep_id: str,
    sweep_sha256: str,
    verdict_line: str,
) -> Dict[str, Any]:
    """
    Build an evidence pack + client-safe delivery zip inside the certify run root.

    This is intentionally "boring":
      - evidence/ carries run_protocol + secret scan + replay wrappers + a small core set of artifacts.
      - delivery/ uses the existing delivery pack generator (redaction + manifest + zip + sha256).
      - hashes/ records sha256 receipts for critical artifacts.
    """
    run_id = run_dir.name
    lane_id = "KT_OPERATOR_CANONICAL_HMAC"

    reports_dir = (run_dir / "reports").resolve()
    hashes_dir = (run_dir / "hashes").resolve()
    delivery_out_dir = (run_dir / "delivery").resolve()
    evidence_dir = (run_dir / "evidence").resolve()
    core_dir = (evidence_dir / "core").resolve()

    reports_dir.mkdir(parents=True, exist_ok=True)
    hashes_dir.mkdir(parents=True, exist_ok=True)
    delivery_out_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    core_dir.mkdir(parents=True, exist_ok=True)

    # Client replay notes (safe to emit before final verdict is written).
    client_readme = "\n".join(
        [
            "# KT Client Replay Instructions",
            "",
            "This bundle is WORM evidence produced by the KT operator factory lane.",
            "",
            "## What this proves",
            "- Pinned V1 anchors verified (sealed tag/commit, law bundle hash, suite registry id, determinism anchor).",
            f"- Canonical certification sweep `{sweep_id}` completed with PASS.",
            "",
            "## How to replay (mechanical)",
            "1) Obtain this repository at the pinned sealed tag/commit referenced in the delivery pack reports.",
            "2) Unzip the delivery zip to a folder.",
            "3) From the delivery pack root, run one of:",
            "   - `bash evidence/replay.sh`",
            "   - `powershell -File evidence/replay.ps1`",
            "",
            "Replay is fail-closed and validates the delivery manifest against the filesystem.",
            "",
            "## What is excluded",
            "- No client proprietary data is embedded in canonical repo surfaces.",
            "- No gated/dual-use payloads are embedded; only hash references are permitted on canonical surfaces.",
            "",
        ]
    )
    write_text_worm(path=run_dir / "client_README.md", text=client_readme, label="client_README.md")

    # Evidence core: minimal provenance + sweep artifacts + transcripts.
    for name in ("git_head.txt", "git_status.txt", "env_keys.json"):
        src = (run_dir / name).resolve()
        if not src.exists():
            raise FL3ValidationError(f"FAIL_CLOSED: missing required provenance artifact: {src.as_posix()}")
        write_bytes_worm(path=core_dir / name, data=src.read_bytes(), label=f"evidence:{name}")

    sweep_src = (run_dir / "sweeps" / sweep_id).resolve()
    sweep_dst = (core_dir / "sweeps" / sweep_id).resolve()
    _copy_tree_worm(src_root=sweep_src, dst_root=sweep_dst, label="evidence:sweep")

    transcripts_src = (run_dir / "transcripts").resolve()
    transcripts_dst = (core_dir / "transcripts").resolve()
    _copy_tree_worm(src_root=transcripts_src, dst_root=transcripts_dst, label="evidence:transcripts")

    # Write an evidence hash manifest over the core/ subtree (excludes run_protocol/secret_scan/replay to avoid recursion).
    entries: List[Dict[str, str]] = []
    core_files: List[Path] = []
    for p in core_dir.rglob("*"):
        if p.is_file():
            core_files.append(p)
    core_files.sort(key=lambda p: p.relative_to(evidence_dir).as_posix())
    for p in core_files:
        rel = p.relative_to(evidence_dir).as_posix()
        entries.append({"path": rel, "sha256": sha256_file(p)})
    if not entries:
        raise FL3ValidationError("FAIL_CLOSED: evidence core is empty (unexpected)")
    parent_hash = sha256_json({"run_id": run_id, "lane_id": lane_id})
    hash_manifest = build_hash_manifest(entries=entries, parent_hash=parent_hash)
    _ = write_schema_object(path=evidence_dir / "hash_manifest.json", obj=hash_manifest)
    bundle_root_hash = str(hash_manifest.get("root_hash", "")).strip()

    # Replay artifacts inside evidence/ (both bash + ps1 wrappers + receipt).
    replay_command = "python -m tools.delivery.delivery_linter --delivery-dir ."
    _sh_path, _ps1_path, _receipt_path, replay_hashes = write_replay_artifacts(
        out_dir=evidence_dir,
        replay_command=replay_command,
        run_id=run_id,
        lane_id=lane_id,
        notes="Replay verifies delivery_pack_manifest.json vs filesystem (fail-closed).",
    )
    # Also copy replay scripts to run root for operator convenience.
    for name in ("replay.sh", "replay.ps1", "replay_receipt.json"):
        src = (evidence_dir / name).resolve()
        write_bytes_worm(path=run_dir / name, data=src.read_bytes(), label=f"operator_replay:{name}")

    # Secret scan evidence pack (must PASS).
    secret_report, secret_summary = scan_pack_and_write(pack_root=evidence_dir, out_dir=evidence_dir, run_id=run_id, lane_id="EVIDENCE")
    secret_status = str(secret_report.get("status", "ERROR"))
    if secret_status != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: evidence secret scan status={secret_status}")

    # Run protocol (JSON + derived markdown), binding the evidence bundle root hash and replay wrapper hash.
    env_hash = sha256_json(
        {
            "python": sys.version,
            "platform": platform.platform(),
            "executable": Path(sys.executable).name,
        }
    )
    governed_phase_start_hash = sha256_json(
        {
            "head": head,
            "sealed_commit": profile.sealed_commit,
            "law_bundle_hash": profile.law_bundle_hash,
            "suite_registry_id": profile.suite_registry_id,
            "determinism_expected_root_hash": profile.determinism_expected_root_hash,
        }
    )
    law_bundle = load_law_bundle(repo_root=repo_root)
    law_ids = [str(l.get("law_id")) for l in law_bundle.get("laws", []) if isinstance(l, dict) and l.get("law_id")]
    protocol = build_run_protocol(
        {
            "run_id": run_id,
            "lane_id": lane_id,
            "timestamp_utc": _utc_now_iso_z(),
            "determinism_mode": "PRACTICAL",
            "execution_environment_hash": env_hash,
            "governed_phase_start_hash": governed_phase_start_hash,
            "io_guard_status": "BYPASS",
            "base_model_id": str(os.environ.get("KT_BASE_MODEL_ID") or "KT_V1_BASELINE_UNSPECIFIED"),
            "active_adapters": [
                {
                    "adapter_id": str(os.environ.get("KT_ADAPTER_ID") or "BASELINE"),
                    "adapter_hash": str(os.environ.get("KT_ADAPTER_HASH") or profile.determinism_expected_root_hash),
                }
            ],
            "active_laws": sorted([x for x in law_ids if x]),
            "replay_command": replay_command,
            "replay_script_hash": str(replay_hashes.get("replay_script_hash", "")),
            "secret_scan_result": secret_status,
            "bundle_root_hash": bundle_root_hash,
            "notes": f"Operator certify canonical_hmac evidence bundle; sweep_id={sweep_id} sweep_summary_sha256={sweep_sha256}",
        }
    )
    write_run_protocol_pair(out_dir=evidence_dir, protocol=protocol)

    # Generate the client delivery pack zip (fail-closed) and lint it.
    delivery_result = generate_delivery_pack(evidence_dir=evidence_dir, out_dir=delivery_out_dir)
    if str(delivery_result.get("status")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: delivery pack generator did not PASS (unexpected)")
    delivery_dir = Path(str(delivery_result["delivery_dir"])).resolve()
    lint_report = lint_delivery_dir(delivery_dir=delivery_dir)
    _write_json_worm(path=delivery_out_dir / "delivery_lint_report.json", obj=lint_report, label="delivery_lint_report.json")
    if str(lint_report.get("status")) != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: delivery linter status={lint_report.get('status')}")

    # Write a run-root delivery manifest (operator-side index) + zip sha receipt under hashes/.
    zip_path = Path(str(delivery_result["zip_path"])).resolve()
    zip_sha = str(delivery_result.get("zip_sha256", "")).strip()
    if len(zip_sha) != 64:
        raise FL3ValidationError("FAIL_CLOSED: delivery zip sha missing/invalid (unexpected)")
    write_text_worm(path=hashes_dir / (zip_path.name + ".sha256"), text=zip_sha + "\n", label="delivery_zip.sha256")

    delivery_manifest = {
        "schema_id": "kt.operator.delivery_manifest.unbound.v1",
        "profile": profile.name,
        "lane": "canonical_hmac",
        "run_id": run_id,
        "head": head,
        "pins": {
            "sealed_tag": profile.sealed_tag,
            "sealed_commit": profile.sealed_commit,
            "law_bundle_hash": profile.law_bundle_hash,
            "suite_registry_id": profile.suite_registry_id,
            "determinism_expected_root_hash": profile.determinism_expected_root_hash,
        },
        "sweep": {
            "sweep_id": sweep_id,
            "sweep_summary_sha256": sweep_sha256,
        },
        "verdict": verdict_line,
        "evidence_dir": evidence_dir.as_posix(),
        "delivery_dir": delivery_dir.as_posix(),
        "delivery_zip": {"path": zip_path.as_posix(), "sha256": zip_sha},
        "replay_command": replay_command,
    }
    _write_json_worm(path=delivery_out_dir / "delivery_manifest.json", obj=delivery_manifest, label="delivery_manifest.json")

    return {"evidence_dir": evidence_dir.as_posix(), "delivery": delivery_result, "delivery_manifest": delivery_manifest}


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def cmd_status(*, repo_root: Path, profile: V1Profile, run_dir: Path, allow_dirty: bool) -> int:
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])
    tag_sha = _git(repo_root=repo_root, args=["rev-list", "-n", "1", profile.sealed_tag])
    if tag_sha != profile.sealed_commit:
        raise FL3ValidationError(
            f"FAIL_CLOSED: sealed tag does not resolve to sealed_commit. tag={profile.sealed_tag} got={tag_sha}"
        )

    bundle = load_law_bundle(repo_root=repo_root)
    computed_law = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
    pinned_law = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()
    if computed_law != pinned_law or computed_law != profile.law_bundle_hash:
        raise FL3ValidationError(
            "FAIL_CLOSED: law bundle hash mismatch. "
            f"computed={computed_law} pinned={pinned_law} expected={profile.law_bundle_hash}"
        )

    suite_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITE_REGISTRY_FL3.json").resolve()
    suite_obj = _load_json(suite_path)
    validate_fl3_suite_registry(suite_obj)
    suite_id = str(suite_obj.get("suite_registry_id", "")).strip()
    mode = str(suite_obj.get("attestation_mode", "")).strip().upper()
    if suite_id != profile.suite_registry_id:
        raise FL3ValidationError(
            f"FAIL_CLOSED: suite_registry_id mismatch. expected={profile.suite_registry_id} got={suite_id}"
        )
    if mode != "HMAC":
        raise FL3ValidationError(f"FAIL_CLOSED: suite registry attestation_mode must be HMAC (got {mode!r})")

    det_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL4_DETERMINISM_ANCHOR.v1.json").resolve()
    det_obj = _load_json(det_path)
    got_det = str(det_obj.get("expected_determinism_root_hash", "")).strip()
    if got_det != profile.determinism_expected_root_hash:
        raise FL3ValidationError(
            f"FAIL_CLOSED: determinism anchor mismatch. expected={profile.determinism_expected_root_hash} got={got_det}"
        )

    status_report = {
        "schema_id": "kt.operator.status_report.unbound.v1",
        "profile": profile.name,
        "sealed_commit": profile.sealed_commit,
        "sealed_tag": profile.sealed_tag,
        "head": head,
        "head_matches_sealed_commit": head == profile.sealed_commit,
        "tag_resolves_to": tag_sha,
        "sealed_tag_resolves_ok": tag_sha == profile.sealed_commit,
        "law_bundle_hash": computed_law,
        "suite_registry_id": suite_id,
        "suite_registry_attestation_mode": mode,
        "determinism_expected_root_hash": got_det,
        "authoritative_reseal_receipt": profile.authoritative_reseal_receipt,
        "allow_dirty": bool(allow_dirty),
        "hmac_keys": _keys_presence_len(),
        "status": "PASS",
    }

    _write_json_worm(path=run_dir / "status_report.json", obj=status_report, label="status_report.json")

    verdict = (
        f"KT_STATUS_PASS cmd=status profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} sealed_commit={profile.sealed_commit} tag={profile.sealed_tag} "
        f"law={computed_law} suite={suite_id} determinism={got_det}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def _is_expected_ci_meta_fail(output: str) -> bool:
    o = (output or "").lower()
    return "kt_hmac_key_signer" in o or "missing kt_hmac_key_signer" in o or "missing kt_hmac" in o


def cmd_certify_ci_sim(*, repo_root: Path, profile: V1Profile, run_dir: Path, allow_dirty: bool) -> int:
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])
    env = _base_env(repo_root=repo_root)

    steps: List[Dict[str, Any]] = []

    def step(name: str, cmd: Sequence[str], *, step_env: Dict[str, str], allow_nonzero: bool = False) -> Tuple[int, str]:
        rc, out, log_path = _run_cmd(
            repo_root=repo_root, run_dir=run_dir, name=name, cmd=cmd, env=step_env, allow_nonzero=allow_nonzero
        )
        steps.append({"name": name, "cmd": list(cmd), "rc": rc, "log": str(log_path.relative_to(run_dir)).replace("\\", "/")})
        return rc, out

    pytest_env = dict(env)
    pytest_env.pop("KT_CANONICAL_LANE", None)
    pytest_env.pop("KT_ATTESTATION_MODE", None)
    step("pytest_cleanroom", ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/tests"], step_env=pytest_env)
    step("pytest_temple", ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests"], step_env=pytest_env)
    step("pytest_verification", ["python", "-m", "pytest", "-q", "KT_PROD_CLEANROOM/tools/verification/tests"], step_env=pytest_env)

    # CI simulation: canonical lane flagged but keys absent and attestation_mode NONE.
    ci_env = dict(env)
    ci_env["KT_CANONICAL_LANE"] = "1"
    ci_env["KT_ATTESTATION_MODE"] = "NONE"
    ci_env.pop("KT_HMAC_KEY_SIGNER_A", None)
    ci_env.pop("KT_HMAC_KEY_SIGNER_B", None)
    rc_ci, out_ci = step(
        "meta_evaluator_ci_sim",
        ["python", "-m", "tools.verification.fl3_meta_evaluator"],
        step_env=ci_env,
        allow_nonzero=True,
    )
    if rc_ci == 0 or not _is_expected_ci_meta_fail(out_ci):
        raise FL3ValidationError("FAIL_CLOSED: CI meta-evaluator simulation did not fail as expected (keys must be absent)")

    # Pins recheck (in-process, official primitives).
    bundle = load_law_bundle(repo_root=repo_root)
    computed_law = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
    pinned_law = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()
    if computed_law != pinned_law or computed_law != profile.law_bundle_hash:
        raise FL3ValidationError(
            "FAIL_CLOSED: law bundle hash mismatch. "
            f"computed={computed_law} pinned={pinned_law} expected={profile.law_bundle_hash}"
        )

    # Validators (client-of-tools).
    step(
        "validate_receipts",
        ["python", "-m", "tools.verification.validate_receipts", "--out-dir", str(run_dir)],
        step_env=dict(env),
    )
    step(
        "validate_work_orders",
        ["python", "-m", "tools.verification.validate_work_orders", "--run-root", str(run_dir)],
        step_env=dict(env),
    )
    step(
        "validate_council_packet",
        ["python", "-m", "tools.verification.validate_council_packet_v1", "--out-dir", str(run_dir)],
        step_env=dict(env),
    )

    report = {
        "schema_id": "kt.operator.certify_report.unbound.v1",
        "profile": profile.name,
        "lane": "ci_sim",
        "head": head,
        "allow_dirty": bool(allow_dirty),
        "law_bundle_hash": computed_law,
        "suite_registry_id": profile.suite_registry_id,
        "steps": steps,
        "status": "PASS",
        "notes": "CI simulation PASS: meta-evaluator failed as expected with keys absent; batteries/validators PASS.",
    }
    _write_json_worm(path=run_dir / "certify_report.json", obj=report, label="certify_report.json")

    verdict = (
        f"KT_CERTIFY_PASS cmd=certify lane=ci_sim profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} law={computed_law} suite={profile.suite_registry_id} meta_ci_sim=EXPECTED_FAIL"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def cmd_certify_canonical_hmac(*, repo_root: Path, profile: V1Profile, run_dir: Path, allow_dirty: bool) -> int:
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])
    keys = _keys_presence_len()
    if not keys["KT_HMAC_KEY_SIGNER_A"]["present"] or not keys["KT_HMAC_KEY_SIGNER_B"]["present"]:
        raise FL3ValidationError(
            "FAIL_CLOSED: missing HMAC keys for canonical lane. "
            "NEXT_ACTION: set KT_HMAC_KEY_SIGNER_A and KT_HMAC_KEY_SIGNER_B in local env (do not paste values)."
        )

    env = _base_env(repo_root=repo_root)
    env["KT_CANONICAL_LANE"] = "1"
    # run_sweep_audit will set KT_ATTESTATION_MODE and enforce CI sim behavior itself.
    _ = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="run_sweep_audit",
        cmd=["python", "-m", "tools.verification.run_sweep_audit", "--run-root", str(run_dir), "--sweep-id", "CANONICAL_HMAC"],
        env=env,
    )

    summary_path = (run_dir / "sweeps" / "CANONICAL_HMAC" / "sweep_summary.json").resolve()
    if not summary_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing sweep_summary.json after sweep (unexpected)")
    sweep_sha = _sha256_file(summary_path)
    write_text_worm(
        path=run_dir / "sweep_summary.sha256",
        text=f"sha256 {sweep_sha}  {summary_path.as_posix()}\n",
        label="sweep_summary.sha256",
    )

    verdict = (
        f"KT_CERTIFY_PASS cmd=certify lane=canonical_hmac profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} law={profile.law_bundle_hash} suite={profile.suite_registry_id} sweep_sha256={sweep_sha}"
    )

    _ = _emit_delivery_bundle_canonical_hmac(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        sweep_id="CANONICAL_HMAC",
        sweep_sha256=sweep_sha,
        verdict_line=verdict,
    )

    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    write_text_worm(path=run_dir / "reports" / "one_line_verdict.txt", text=verdict + "\n", label="one_line_verdict.txt")
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def cmd_hat_demo(*, repo_root: Path, profile: V1Profile, run_dir: Path, allow_dirty: bool) -> int:
    env = _base_env(repo_root=repo_root)

    policy = (repo_root / profile.router_policy_ref).resolve()
    suite = (repo_root / profile.router_demo_suite_ref).resolve()
    if not policy.exists() or not suite.exists():
        raise FL3ValidationError(
            "FAIL_CLOSED: missing router hat demo inputs. "
            "NEXT_ACTION: ensure AUDITS/ROUTER policy and suite exist (or implement EPIC_HAT_01)."
        )

    out_dir = (run_dir / "hat_demo").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"{profile.name}_{_utc_now_compact_z()}"
    _ = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="hat_demo",
        cmd=[
            "python",
            "-m",
            "tools.router.run_router_hat_demo",
            "--policy",
            str(policy),
            "--suite",
            str(suite),
            "--run-id",
            run_id,
            "--out-dir",
            str(out_dir),
        ],
        env=env,
    )

    report_path = out_dir / "router_run_report.json"
    if not report_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing router_run_report.json (unexpected)")

    report = _load_json(report_path)
    verdict = (
        f"KT_HAT_DEMO_PASS cmd=hat-demo profile={profile.name} allow_dirty={int(bool(allow_dirty))} run_id={run_id} "
        f"router_run_report_id={str(report.get('router_run_report_id','')).strip()}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def cmd_mve_run(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    pack_manifest: str,
    adapter_id: str,
    seed: int,
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    env = _base_env(repo_root=repo_root)
    out_dir = run_dir / "mve_run"
    out_dir.mkdir(parents=True, exist_ok=False)

    args = [
        "-m",
        "tools.eval.mve_runner",
        "--pack-manifest",
        pack_manifest,
        "--adapter-id",
        adapter_id,
        "--seed",
        str(int(seed)),
        "--law-bundle-hash-in-force",
        profile.law_bundle_hash,
        "--out-dir",
        str(out_dir),
    ]
    _rc, out, _log_path = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="mve_runner",
        cmd=[sys.executable, *args],
        env=env,
    )

    mve_summary_path = (out_dir / "mve" / "mve_summary.json").resolve()
    if not mve_summary_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing mve/mve_summary.json (unexpected)")

    _write_json_worm(
        path=run_dir / "mve_run_report.json",
        obj={
            "schema_id": "kt.operator_mve_run_report.v1",
            "profile": profile.name,
            "pack_manifest": pack_manifest,
            "adapter_id": adapter_id,
            "seed": int(seed),
            "out_dir": str(out_dir),
            "runner_rc": int(_rc),
            "mve_summary_path": mve_summary_path.as_posix(),
        },
        label="mve_run_report.json",
    )
    write_text_worm(path=run_dir / "mve_runner_output.txt", text=out if out.endswith("\n") else out + "\n", label="mve_runner_output.txt")

    if int(_rc) != 0:
        raise FL3ValidationError("FAIL_CLOSED: mve_runner failed")

    verdict = (
        f"KT_MVE_RUN_PASS cmd=mve-run profile={profile.name} allow_dirty={int(bool(allow_dirty))} run_id={run_dir.name} "
        f"pack_manifest={pack_manifest} adapter_id={adapter_id} seed={int(seed)} out_dir={out_dir}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def cmd_titan_run(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    pack_manifest: str,
    adapter_id: str,
    seed: int,
    invariants_file: str,
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    env = _base_env(repo_root=repo_root)

    out_dir = run_dir / "titan_run"
    out_dir.mkdir(parents=True, exist_ok=False)

    # 1) MVE-1 runner
    mve_args = [
        "-m",
        "tools.eval.mve_runner",
        "--mode",
        "mve1",
        "--pack-manifest",
        pack_manifest,
        "--adapter-id",
        adapter_id,
        "--seed",
        str(int(seed)),
        "--law-bundle-hash-in-force",
        profile.law_bundle_hash,
        "--out-dir",
        str(out_dir),
    ]
    if invariants_file.strip():
        mve_args += ["--invariants-file", invariants_file]

    mve_rc, mve_out, _mve_log_path = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="titan_mve_runner",
        cmd=[sys.executable, *mve_args],
        env=env,
    )
    if int(mve_rc) != 0:
        raise FL3ValidationError("FAIL_CLOSED: titan mve_runner failed")

    mve_dir = (out_dir / "mve").resolve()
    fitness_path = (mve_dir / "multiversal_fitness.json").resolve()
    if not fitness_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing mve/multiversal_fitness.json (unexpected)")

    # 2) Temporal fitness gate (writes to a WORM subdir; may return rc=2 if regression detected)
    temporal_out_dir = (out_dir / "titan" / "temporal").resolve()
    temporal_rc, _temporal_out, _temporal_log_path = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="temporal_fitness_ledger",
        cmd=[
            sys.executable,
            "-m",
            "tools.eval.temporal_fitness_ledger",
            "--fitness-record",
            str(fitness_path),
            "--run-id",
            str(run_dir.name),
            "--out-dir",
            str(temporal_out_dir),
        ],
        env=env,
        allow_nonzero=True,
    )

    temporal_gate_path = (temporal_out_dir / "temporal_fitness_gate.json").resolve()
    if not temporal_gate_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing temporal_fitness_gate.json (unexpected)")

    # 3) Titan promotion dependency graph (always rc=0; fail-closed on missing artifacts)
    gate_out_dir = (out_dir / "titan" / "promotion_gate").resolve()
    gate_rc, _gate_out, _gate_log_path = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="titan_promotion_gate",
        cmd=[
            sys.executable,
            "-m",
            "tools.eval.titan_promotion_gate",
            "--mve-dir",
            str(mve_dir),
            "--temporal-gate",
            str(temporal_gate_path),
            "--run-id",
            str(run_dir.name),
            "--out-dir",
            str(gate_out_dir),
        ],
        env=env,
    )
    if int(gate_rc) != 0:
        raise FL3ValidationError("FAIL_CLOSED: titan_promotion_gate failed")

    titan_gate_path = (gate_out_dir / "titan_promotion_gate.json").resolve()
    if not titan_gate_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing titan_promotion_gate.json (unexpected)")

    # 4) Admission record (rc=2 if blocked; still produces record)
    admission_out_dir = (out_dir / "admission").resolve()
    admission_rc, _admission_out, _admission_log_path = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="mve_admission_gate",
        cmd=[
            sys.executable,
            "-m",
            "tools.eval.mve_admission_gate",
            "--mode",
            "mve1",
            "--mve-dir",
            str(mve_dir),
            "--titan-gate",
            str(titan_gate_path),
            "--out-dir",
            str(admission_out_dir),
        ],
        env=env,
        allow_nonzero=True,
    )

    admission_record_path = (admission_out_dir / "mve_admission_record.json").resolve()
    if not admission_record_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing mve_admission_record.json (unexpected)")

    rec = _load_json(admission_record_path)
    status = str(rec.get("status", "")).strip() or "UNKNOWN"
    promotion_blocked = bool(_load_json(titan_gate_path).get("promotion_blocked", True))

    _write_json_worm(
        path=run_dir / "titan_run_report.json",
        obj={
            "schema_id": "kt.operator_titan_run_report.v1",
            "profile": profile.name,
            "pack_manifest": pack_manifest,
            "adapter_id": adapter_id,
            "seed": int(seed),
            "out_dir": str(out_dir),
            "mve_rc": int(mve_rc),
            "temporal_rc": int(temporal_rc),
            "gate_rc": int(gate_rc),
            "admission_rc": int(admission_rc),
            "admission_status": status,
            "promotion_blocked": bool(promotion_blocked),
            "paths": {
                "mve_dir": mve_dir.as_posix(),
                "temporal_gate_path": temporal_gate_path.as_posix(),
                "titan_gate_path": titan_gate_path.as_posix(),
                "admission_record_path": admission_record_path.as_posix(),
            },
        },
        label="titan_run_report.json",
    )
    write_text_worm(
        path=run_dir / "titan_run_output.txt",
        text=mve_out if mve_out.endswith("\n") else mve_out + "\n",
        label="titan_run_output.txt",
    )

    verdict_kind = "PASS" if (status == "PASS" and (not promotion_blocked)) else "BLOCKED"
    verdict = (
        f"KT_TITAN_RUN_{verdict_kind} cmd=titan-run profile={profile.name} allow_dirty={int(bool(allow_dirty))} run_id={run_dir.name} "
        f"pack_manifest={pack_manifest} adapter_id={adapter_id} seed={int(seed)} admission_status={status} promotion_blocked={int(bool(promotion_blocked))}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def cmd_report(*, repo_root: Path, profile: V1Profile, run_dir: Path, target_run: str, allow_dirty: bool) -> int:
    env = _base_env(repo_root=repo_root)

    target = Path(str(target_run)).expanduser()
    if not target.is_absolute():
        target = (repo_root / target).resolve()
    if not target.exists() or not target.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: --run must be an existing directory (got {target.as_posix()})")

    # Render a minimal report from known artifacts.
    found: Dict[str, Any] = {"target_run": target.as_posix(), "files": {}, "notes": []}

    verdict_path = target / "verdict.txt"
    if verdict_path.exists():
        found["files"]["verdict.txt"] = verdict_path.as_posix()
    else:
        found["notes"].append("missing verdict.txt")

    sweeps_dir = target / "sweeps"
    sweep_summaries: List[str] = []
    if sweeps_dir.exists():
        for p in sorted(sweeps_dir.rglob("sweep_summary.json")):
            sweep_summaries.append(p.as_posix())
    if sweep_summaries:
        found["files"]["sweep_summary.json"] = sweep_summaries
    else:
        found["notes"].append("no sweep_summary.json found under sweeps/")

    hat_report = target / "hat_demo" / "router_run_report.json"
    if hat_report.exists():
        found["files"]["hat_demo/router_run_report.json"] = hat_report.as_posix()
        try:
            rr = _load_json(hat_report)
            found["files"]["hat_demo/router_run_report_id"] = str(rr.get("router_run_report_id", "")).strip()
        except Exception:  # noqa: BLE001
            found["notes"].append("hat_demo/router_run_report.json unreadable")

    out_json = run_dir / "report_render.json"
    _write_json_worm(path=out_json, obj=found, label="report_render.json")

    out_txt = run_dir / "report_render.txt"
    lines = [f"KT REPORT profile={profile.name}", f"target_run={target.as_posix()}"]
    if verdict_path.exists():
        lines.append("verdict=" + verdict_path.read_text(encoding="utf-8", errors="replace").strip())
    if sweep_summaries:
        lines.append("sweep_summaries=" + ",".join(sweep_summaries))
    if hat_report.exists():
        lines.append("hat_demo_router_run_report=" + hat_report.as_posix())
        if isinstance(found["files"].get("hat_demo/router_run_report_id"), str) and found["files"]["hat_demo/router_run_report_id"]:
            lines.append("hat_demo_router_run_report_id=" + str(found["files"]["hat_demo/router_run_report_id"]))
    if found["notes"]:
        lines.append("notes=" + "; ".join(str(x) for x in found["notes"]))
    write_text_worm(path=out_txt, text="\n".join(lines) + "\n", label="report_render.txt")

    verdict = (
        f"KT_REPORT_PASS cmd=report profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"target_run={target.as_posix()}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT operator CLI (client-of-tools; WORM evidence under exports/_runs).")
    ap.add_argument("--profile", default="v1", choices=["v1"], help="Operator profile (default: v1).")
    ap.add_argument("--run-root", default="", help="Optional explicit run root under KT_PROD_CLEANROOM/exports/_runs.")
    ap.add_argument("--allow-dirty", action="store_true", help="Allow dirty worktree (default: fail-closed).")

    sub = ap.add_subparsers(dest="cmd", required=True)

    def _add_post_global_options(sp: argparse.ArgumentParser) -> None:
        # Support both: `kt_cli --profile v1 status` and `kt_cli status --profile v1`.
        # Avoid overriding the pre-subcommand values when the post-subcommand flags are omitted.
        sp.add_argument("--profile", default=None, choices=["v1"], dest="profile_post")
        sp.add_argument("--run-root", default=None, dest="run_root_post")
        sp.add_argument("--allow-dirty", action="store_true", default=None, dest="allow_dirty_post")

    ap_status = sub.add_parser("status", help="Verify immutable V1 anchors and emit status report (WORM).")
    _add_post_global_options(ap_status)

    ap_cert = sub.add_parser("certify", help="Run certification harness as a client-of-tools (WORM).")
    _add_post_global_options(ap_cert)
    ap_cert.add_argument("--lane", required=True, choices=["ci_sim", "canonical_hmac"])

    ap_hat = sub.add_parser("hat-demo", help="Run router hat demo (EPIC_19) and emit run report (WORM).")
    _add_post_global_options(ap_hat)

    ap_mve = sub.add_parser("mve-run", help="Run MVE-0 pressure pack and emit multiversal artifacts (WORM).")
    _add_post_global_options(ap_mve)
    ap_mve.add_argument("--pack-manifest", required=True, help="Path to pressure pack manifest JSON.")
    ap_mve.add_argument("--adapter-id", required=True, help="Adapter/artifact id to evaluate.")
    ap_mve.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")

    ap_titan = sub.add_parser(
        "titan-run", help="Run MVE-1 + Titan gates (temporal fitness, drift, capture-resistance, dependency graph)."
    )
    _add_post_global_options(ap_titan)
    ap_titan.add_argument("--pack-manifest", required=True, help="Path to pressure pack manifest JSON.")
    ap_titan.add_argument("--adapter-id", required=True, help="Adapter/artifact id to evaluate.")
    ap_titan.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")
    ap_titan.add_argument("--invariants-file", default="", help="Override invariants file (relative to pack root).")

    ap_rep = sub.add_parser("report", help="Render a human-readable summary from an existing run directory.")
    _add_post_global_options(ap_rep)
    ap_rep.add_argument("--run", required=True, help="Target run directory to summarize.")

    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    profile = V1

    cmd_name = str(args.cmd).replace("_", "-")

    requested_profile = str(getattr(args, "profile_post", None) or getattr(args, "profile", "v1")).strip() or "v1"
    if requested_profile != "v1":
        raise FL3ValidationError("FAIL_CLOSED: unsupported profile")

    requested_run_root = getattr(args, "run_root_post", None)
    if requested_run_root is None:
      requested_run_root = str(args.run_root).strip() or None
    else:
        requested_run_root = str(requested_run_root).strip() or None

    allow_dirty_post = getattr(args, "allow_dirty_post", None)
    allow_dirty = bool(allow_dirty_post) if allow_dirty_post is not None else bool(getattr(args, "allow_dirty", False))

    run_dir = _mk_run_dir(repo_root=repo_root, cmd_name=cmd_name, requested_run_root=requested_run_root)

    # Minimal provenance.
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    write_text_worm(path=run_dir / "git_head.txt", text=_git(repo_root=repo_root, args=["rev-parse", "HEAD"]) + "\n", label="git_head.txt")
    write_text_worm(path=run_dir / "git_status.txt", text=_git(repo_root=repo_root, args=["status", "--porcelain=v1"]) + "\n", label="git_status.txt")
    _write_json_worm(
        path=run_dir / "env_keys.json",
        obj={"hmac_keys": _keys_presence_len(), "allow_dirty": bool(allow_dirty)},
        label="env_keys.json",
    )

    try:
        _maybe_assert_clean_worktree(repo_root=repo_root, allow_dirty=allow_dirty)
        if args.cmd == "status":
            return cmd_status(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
        if args.cmd == "certify":
            if str(args.lane) == "ci_sim":
                return cmd_certify_ci_sim(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
            return cmd_certify_canonical_hmac(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
        if args.cmd == "hat-demo":
            return cmd_hat_demo(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
        if args.cmd == "mve-run":
            return cmd_mve_run(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                pack_manifest=str(args.pack_manifest),
                adapter_id=str(args.adapter_id),
                seed=int(args.seed),
                allow_dirty=allow_dirty,
            )
        if args.cmd == "titan-run":
            return cmd_titan_run(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                pack_manifest=str(args.pack_manifest),
                adapter_id=str(args.adapter_id),
                seed=int(args.seed),
                invariants_file=str(args.invariants_file),
                allow_dirty=allow_dirty,
            )
        if args.cmd == "report":
            return cmd_report(repo_root=repo_root, profile=profile, run_dir=run_dir, target_run=str(args.run), allow_dirty=allow_dirty)
        raise FL3ValidationError("FAIL_CLOSED: unknown command")
    except FL3ValidationError as exc:
        msg = str(exc)
        cmd = str(args.cmd)
        verdict = f"KT_{cmd.upper().replace('-', '_')}_FAIL_CLOSED cmd={cmd} profile={profile.name} allow_dirty={int(bool(allow_dirty))}"
        write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
        write_text_worm(path=run_dir / "error.txt", text=msg + "\n", label="error.txt")
        print(msg)
        print(verdict)
        return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        print(str(exc))
        raise SystemExit(2) from exc
