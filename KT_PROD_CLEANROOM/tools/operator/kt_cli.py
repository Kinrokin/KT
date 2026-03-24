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

def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _bootstrap_syspath(*, repo_root: Path) -> None:
    """
    Operator CLI must be runnable via `python -m tools.operator.kt_cli`
    from the cleanroom root without relying on callers to pre-set PYTHONPATH.
    """
    src_root = (repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()
    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
    for p in (str(src_root), str(cleanroom_root)):
        if p not in sys.path:
            sys.path.insert(0, p)


_bootstrap_syspath(repo_root=_repo_root_from(Path(__file__)))

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from schemas.fl3_suite_registry_schema import validate_fl3_suite_registry
from tools.delivery.delivery_linter import lint_delivery_dir
from tools.delivery.generate_delivery_pack import generate_delivery_pack
from tools.operator.canonical_tree_execute import ARCHIVE_VAULT_RECEIPTS_PREFIX
from tools.operator.titanium_common import operator_fingerprint as titanium_operator_fingerprint
from tools.operator.titanium_common import write_failure_artifacts as titanium_write_failure_artifacts
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
    law_bundle_hash="9c800fe888fa904830ea3149558f54a4a97efa944c07c48bc2869fc394d266e8",
    suite_registry_id="a1d21d415568931778b718827c278918529af8490a1b456ba97f27a9a18be8fc",
    determinism_expected_root_hash="c574cd28deba7020b1ff41f249c02f403cbe8e045cb961222183880977bdb10e",
    authoritative_reseal_receipt=("KT_PROD_CLEANROOM/reports/kt_archive_manifest.json#vault_receipt_epic_hmac_reseal_v1_post_20260301t145027z"),
    router_policy_ref="KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_POLICY_HAT_V1.json",
    router_demo_suite_ref="KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_DEMO_SUITE_V1.json",
)

CI_SIM_PYTEST_TARGETS: Tuple[str, ...] = (
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_law_bundle_integrity.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_fl3_receipts_no_secrets.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
    "KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py",
    "KT_PROD_CLEANROOM/tests/operator/test_titanium_substrate.py::test_hashpin_reports_are_head_stamped_and_candidate_scoped",
    "KT_PROD_CLEANROOM/tests/operator/test_truth_publication.py::test_publish_truth_artifacts_emits_bundle_pointer_and_indexes",
    "KT_PROD_CLEANROOM/tests/operator/test_truth_publication.py::test_publish_truth_artifacts_is_stable_on_repeat_publish",
)


def _utc_now_compact_z() -> str:
    fixed = str(os.environ.get("KT_FIXED_UTC_COMPACT", "")).strip()
    if fixed:
        return fixed
    # Microseconds included to avoid collisions in operator workflows.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

def _utc_now_iso_z() -> str:
    fixed = str(os.environ.get("KT_FIXED_UTC_ISO", "")).strip()
    if fixed:
        return fixed
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


def _governance_manifest_path(repo_root: Path) -> Path:
    return (repo_root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").resolve()


def _governance_manifest(repo_root: Path) -> Dict[str, Any]:
    path = _governance_manifest_path(repo_root)
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return obj if isinstance(obj, dict) else {}


def _constitution_epoch(repo_root: Path) -> int:
    manifest = _governance_manifest(repo_root)
    try:
        return int(manifest.get("constitution_epoch", 1))
    except Exception:  # noqa: BLE001
        return 1


def _payload_sha256(obj: Dict[str, Any], *, exclude_keys: Sequence[str]) -> str:
    payload = {k: v for k, v in obj.items() if k not in set(exclude_keys)}
    return sha256_hex(canonicalize_bytes(payload))


def _ensure_operator_plane_artifacts(
    *,
    repo_root: Path,
    run_dir: Path,
    program_id: str,
    lane_id: str,
    lane_label: str,
    verdict_line: str,
    delivery_manifest_extras: Optional[Dict[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    reports_dir = (run_dir / "reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    fingerprint_path = (reports_dir / "operator_fingerprint.json").resolve()
    if fingerprint_path.exists():
        operator_fp = _load_json(fingerprint_path)
    else:
        operator_fp = titanium_operator_fingerprint()
        if str(os.environ.get("KT_SAFE_RUN_OPERATOR_ID", "")).strip():
            operator_fp["operator_id"] = str(os.environ["KT_SAFE_RUN_OPERATOR_ID"]).strip()
        _write_json_worm(path=fingerprint_path, obj=operator_fp, label="operator_fingerprint.json")

    intent_path = (reports_dir / "operator_intent.json").resolve()
    if intent_path.exists():
        operator_intent = _load_json(intent_path)
    else:
        effective_program_id = str(os.environ.get("KT_SAFE_RUN_PROGRAM_ID") or program_id or lane_id).strip()
        assurance_mode = str(os.environ.get("KT_SAFE_RUN_ASSURANCE_MODE") or "direct").strip()
        intent_surface = {
            "delivery_manifest_extras": delivery_manifest_extras or {},
            "lane_id": lane_id,
            "lane_label": lane_label,
            "program_id": effective_program_id,
            "verdict": verdict_line,
        }
        operator_intent = {
            "operator_id": str(os.environ.get("KT_SAFE_RUN_OPERATOR_ID") or operator_fp.get("operator_id") or os.environ.get("KT_OPERATOR_ID") or "unknown"),
            "operator_intent_class": str(os.environ.get("KT_OPERATOR_INTENT_CLASS", "AUDIT")).upper(),
            "operator_intent_hash": str(os.environ.get("KT_SAFE_RUN_OPERATOR_INTENT_HASH") or sha256_json(intent_surface)),
            "program_id": effective_program_id,
            "config_sha256": sha256_json(intent_surface),
            "inputs_sha256_list": [],
            "assurance_mode": assurance_mode,
            "constitution_epoch": _constitution_epoch(repo_root),
            "created_utc": _utc_now_iso_z(),
        }
        _write_json_worm(path=intent_path, obj=operator_intent, label="operator_intent.json")

    return operator_fp, operator_intent


def _build_evidence_core_merkle(
    *,
    run_dir: Path,
    required_relpaths: Sequence[str],
) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for rel in required_relpaths:
        path = (run_dir / rel).resolve()
        if not path.exists() or not path.is_file():
            raise FL3ValidationError(f"FAIL_CLOSED: missing evidence-core-merkle input: {path.as_posix()}")
        entries.append({"path": rel, "sha256": sha256_file(path)})
    root_hash = sha256_json({"entries": entries})
    return {
        "schema_id": "kt.operator.evidence_core_merkle.v1",
        "created_utc": _utc_now_iso_z(),
        "artifact_count": int(len(entries)),
        "entries": entries,
        "evidence_core_merkle_root_sha256": root_hash,
    }


def _write_runtime_attachment_reports(
    *,
    run_dir: Path,
    program_id: str,
    lane_id: str,
    lane_label: str,
    head: str,
    delivery_manifest_path: Path,
    bindingloop_report: Dict[str, Any],
    delivery_contract_report: Dict[str, Any],
) -> None:
    reports_dir = (run_dir / "reports").resolve()
    safe_run_enforced = str(os.environ.get("KT_SAFE_RUN_ACTIVE", "")).strip() == "1"
    entrypoint = str(os.environ.get("KT_RUNTIME_ENTRYPOINT") or "python -m tools.operator.kt_cli").strip()
    checkpoints = [
        "reports/operator_fingerprint.json",
        "reports/operator_intent.json",
        "evidence/constitutional_snapshot.json",
        "evidence/worm_manifest.json",
        "evidence/evidence_core_merkle.json",
        "delivery/delivery_manifest.json",
        "delivery/delivery_lint_report.json",
        "evidence/replay_receipt.json",
        "evidence/secret_scan_report.json",
        "reports/bindingloop_check.json",
    ]
    row = {
        "program_id": program_id,
        "entrypoint": entrypoint,
        "lane": lane_label,
        "bundle_emitter_used": "_emit_delivery_bundle",
        "titanium_checkpoints_exercised": checkpoints,
        "validator_set_exercised": [
            "program.bindingloop.verify",
            "program.delivery.contract.validate",
        ],
        "ledger_append_observed": bool((run_dir / "governance" / "ledger" / "federal_ledger.jsonl").exists()),
        "production_intended_blocked_if_missing": safe_run_enforced,
        "safe_run_enforced": safe_run_enforced,
        "evidence_plane_complete": True,
    }
    trace = {
        "schema_id": "kt.operator.real_path_trace.v1",
        "created_utc": _utc_now_iso_z(),
        "head": head,
        "program_id": program_id,
        "lane_id": lane_id,
        "lane_label": lane_label,
        "delivery_manifest": delivery_manifest_path.as_posix(),
        "bindingloop_status": str(bindingloop_report.get("status", "")),
        "delivery_contract_status": str(delivery_contract_report.get("status", "")),
        "safe_run_enforced": safe_run_enforced,
        "trace": row,
    }
    assertions = {
        "schema_id": "kt.operator.runtime_attach_assertions.v1",
        "created_utc": _utc_now_iso_z(),
        "program_id": program_id,
        "status": "PASS",
        "checks": [
            {"check": "operator_plane_emitted", "status": "PASS"},
            {"check": "bindingloop_verify", "status": str(bindingloop_report.get("status", ""))},
            {"check": "delivery_contract_validate", "status": str(delivery_contract_report.get("status", ""))},
            {"check": "safe_run_marker_present", "status": "PASS" if safe_run_enforced else "WARN"},
        ],
    }
    receipt = {
        "schema_id": "kt.operator.real_path_attachment_receipt.v1",
        "created_utc": _utc_now_iso_z(),
        "program_id": program_id,
        "lane_id": lane_id,
        "lane_label": lane_label,
        "safe_run_enforced": safe_run_enforced,
        "bindingloop_status": str(bindingloop_report.get("status", "")),
        "delivery_contract_status": str(delivery_contract_report.get("status", "")),
        "evidence_plane_complete": True,
        "status": "PASS",
    }
    matrix = {
        "schema_id": "kt.operator.real_path_attachment_matrix.v1",
        "created_utc": _utc_now_iso_z(),
        "rows": [row],
    }

    _write_json_worm(path=reports_dir / "real_path_trace.json", obj=trace, label="real_path_trace.json")
    trace_md = "\n".join(
        [
            "# KT Real Path Trace",
            "",
            f"- program_id: `{program_id}`",
            f"- lane_id: `{lane_id}`",
            f"- lane_label: `{lane_label}`",
            f"- entrypoint: `{entrypoint}`",
            f"- safe_run_enforced: `{int(bool(safe_run_enforced))}`",
            f"- delivery_manifest: `{delivery_manifest_path.as_posix()}`",
            f"- bindingloop_status: `{bindingloop_report.get('status', '')}`",
            f"- delivery_contract_status: `{delivery_contract_report.get('status', '')}`",
        ]
    )
    write_text_worm(path=reports_dir / "real_path_trace.md", text=trace_md + "\n", label="real_path_trace.md")
    _write_json_worm(path=reports_dir / "runtime_attach_assertions.json", obj=assertions, label="runtime_attach_assertions.json")
    _write_json_worm(path=reports_dir / "real_path_attachment_receipt.json", obj=receipt, label="real_path_attachment_receipt.json")
    _write_json_worm(path=reports_dir / "real_path_attachment_matrix.json", obj=matrix, label="real_path_attachment_matrix.json")


def _append_run_local_federal_ledger(
    *,
    repo_root: Path,
    run_dir: Path,
    program_id: str,
    delivery_zip_sha256: str,
    evidence_core_merkle_root_sha256: str,
    operator_intent_hash: str,
) -> Dict[str, Any]:
    ledger_dir = (run_dir / "governance" / "ledger").resolve()
    ledger_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = (ledger_dir / "federal_ledger.jsonl").resolve()
    previous_entry_hash = ""
    if ledger_path.exists() and ledger_path.stat().st_size:
        lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous_obj = json.loads(lines[-1])
            previous_entry_hash = str(previous_obj.get("entry_hash", "")).strip()
    payload = {
        "created_utc": _utc_now_iso_z(),
        "run_id": run_dir.name,
        "program_id": program_id,
        "jurisdiction_id": "KT_DEFAULT",
        "constitution_epoch": _constitution_epoch(repo_root),
        "evidence_core_merkle_root_sha256": evidence_core_merkle_root_sha256,
        "delivery_zip_sha256": delivery_zip_sha256,
        "operator_intent_hash": operator_intent_hash,
        "previous_entry_hash": previous_entry_hash,
    }
    entry_hash = sha256_hex(canonicalize_bytes(payload))
    payload["entry_hash"] = entry_hash
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    if ledger_path.exists():
        with ledger_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    else:
        write_text_worm(path=ledger_path, text=text, label="federal_ledger.jsonl")
    return payload


def _emit_delivery_bundle(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    head: str,
    lane_id: str,
    lane_label: str,
    verdict_line: str,
    sweep_id: Optional[str] = None,
    sweep_sha256: Optional[str] = None,
    base_model_id: Optional[str] = None,
    active_adapters: Optional[List[Dict[str, str]]] = None,
    datasets: Optional[List[Dict[str, str]]] = None,
    core_copy_dirs: Optional[Sequence[Tuple[str, str]]] = None,
    delivery_manifest_extras: Optional[Dict[str, Any]] = None,
    run_protocol_notes: str = "",
    program_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an evidence pack + client-safe delivery zip inside the certify run root.

    This is intentionally "boring":
      - evidence/ carries run_protocol + secret scan + replay wrappers + a small core set of artifacts.
      - delivery/ uses the existing delivery pack generator (redaction + manifest + zip + sha256).
      - hashes/ records sha256 receipts for critical artifacts.
    """
    run_id = run_dir.name

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
    reports_dir.mkdir(parents=True, exist_ok=True)

    write_text_worm(path=run_dir / "verdict.txt", text=verdict_line + "\n", label="verdict.txt")
    write_text_worm(path=reports_dir / "one_line_verdict.txt", text=verdict_line + "\n", label="one_line_verdict.txt")

    effective_program_id = str(program_id or lane_id).strip() or lane_id
    _operator_fp, operator_intent = _ensure_operator_plane_artifacts(
        repo_root=repo_root,
        run_dir=run_dir,
        program_id=effective_program_id,
        lane_id=lane_id,
        lane_label=lane_label,
        verdict_line=verdict_line,
        delivery_manifest_extras=delivery_manifest_extras,
    )

    # Client replay notes (safe to emit before final verdict is written).
    proves: List[str] = [
        "- Pinned V1 anchors verified (sealed tag/commit, law bundle hash, suite registry id, determinism anchor).",
        f"- Lane `{lane_label}` evidence bundle produced.",
    ]
    if isinstance(sweep_id, str) and sweep_id.strip():
        proves.append(f"- Sweep `{sweep_id}` completed (see evidence/core/sweeps/{sweep_id}/).")
    client_readme = "\n".join(
        [
            "# KT Client Replay Instructions",
            "",
            "This bundle is WORM evidence produced by the KT operator factory lane.",
            "",
            "## What this proves",
            *proves,
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

    if isinstance(core_copy_dirs, Sequence) and core_copy_dirs:
        for src_rel, dst_rel in core_copy_dirs:
            src = (run_dir / str(src_rel)).resolve()
            dst = (core_dir / str(dst_rel)).resolve()
            _copy_tree_worm(src_root=src, dst_root=dst, label=f"evidence:{src_rel}")
    else:
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
    if base_model_id is None:
        base_model_id = str(os.environ.get("KT_BASE_MODEL_ID") or "KT_V1_BASELINE_UNSPECIFIED")
    if active_adapters is None:
        active_adapters = [
            {
                "adapter_id": str(os.environ.get("KT_ADAPTER_ID") or "BASELINE"),
                "adapter_hash": str(os.environ.get("KT_ADAPTER_HASH") or profile.determinism_expected_root_hash),
            }
        ]
    notes = (run_protocol_notes or "").strip()
    if isinstance(sweep_id, str) and sweep_id.strip() and isinstance(sweep_sha256, str) and sweep_sha256.strip():
        sfx = f"sweep_id={sweep_id} sweep_summary_sha256={sweep_sha256}"
        notes = (notes + " | " + sfx).strip(" |") if notes else sfx
    protocol = build_run_protocol(
        {
            "run_id": run_id,
            "lane_id": lane_id,
            "timestamp_utc": _utc_now_iso_z(),
            "determinism_mode": "PRACTICAL",
            "execution_environment_hash": env_hash,
            "governed_phase_start_hash": governed_phase_start_hash,
            "io_guard_status": "BYPASS",
            "base_model_id": str(base_model_id),
            "active_adapters": active_adapters,
            "active_laws": sorted([x for x in law_ids if x]),
            "datasets": datasets or [],
            "replay_command": replay_command,
            "replay_script_hash": str(replay_hashes.get("replay_script_hash", "")),
            "secret_scan_result": secret_status,
            "bundle_root_hash": bundle_root_hash,
            "notes": notes or None,
        }
    )
    write_run_protocol_pair(out_dir=evidence_dir, protocol=protocol)

    # Generate the client delivery pack zip (fail-closed) and lint it.
    delivery_result = generate_delivery_pack(evidence_dir=evidence_dir, out_dir=delivery_out_dir)
    if str(delivery_result.get("status")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: delivery pack generator did not PASS (unexpected)")
    delivery_dir = Path(str(delivery_result["delivery_dir"])).resolve()
    lint_report = lint_delivery_dir(delivery_dir=delivery_dir)
    if isinstance(lint_report, dict) and isinstance(lint_report.get("inputs"), dict):
        lint_report = dict(lint_report)
        lint_inputs = dict(lint_report["inputs"])
        lint_inputs["delivery_dir"] = Path("delivery") / delivery_dir.name
        lint_report["inputs"] = {"delivery_dir": str(lint_inputs["delivery_dir"]).replace("\\", "/")}
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
        "lane": lane_label,
        "lane_id": lane_id,
        "program_id": effective_program_id,
        "run_id": run_id,
        "head": head,
        "pins": {
            "sealed_tag": profile.sealed_tag,
            "sealed_commit": profile.sealed_commit,
            "law_bundle_hash": profile.law_bundle_hash,
            "suite_registry_id": profile.suite_registry_id,
            "determinism_expected_root_hash": profile.determinism_expected_root_hash,
        },
        "sweep": {"sweep_id": str(sweep_id or "").strip(), "sweep_summary_sha256": str(sweep_sha256 or "").strip()}
        if (isinstance(sweep_id, str) and sweep_id.strip() and isinstance(sweep_sha256, str) and sweep_sha256.strip())
        else None,
        "verdict": verdict_line,
        "evidence_dir": "evidence",
        "delivery_dir": f"delivery/{delivery_dir.name}",
        "delivery_zip": {"path": f"delivery/{zip_path.name}", "sha256": zip_sha},
        "replay_command": replay_command,
        "safe_run_enforced": str(os.environ.get("KT_SAFE_RUN_ACTIVE", "")).strip() == "1",
        "operator_intent_hash": str(operator_intent.get("operator_intent_hash", "")),
    }
    if isinstance(delivery_manifest_extras, dict) and delivery_manifest_extras:
        for k, v in delivery_manifest_extras.items():
            if k in delivery_manifest:
                raise FL3ValidationError(f"FAIL_CLOSED: delivery_manifest_extras key collision: {k}")
            delivery_manifest[k] = v

    constitutional_snapshot = {
        "schema_id": "kt.operator.constitutional_snapshot.v1",
        "created_utc": _utc_now_iso_z(),
        "program_id": effective_program_id,
        "lane_id": lane_id,
        "lane_label": lane_label,
        "head": head,
        "constitution_epoch": _constitution_epoch(repo_root),
        "governance_manifest_path": "KT_PROD_CLEANROOM/governance/governance_manifest.json",
        "governance_manifest_sha256": (_sha256_file(_governance_manifest_path(repo_root)) if _governance_manifest_path(repo_root).exists() else ""),
        "delivery_manifest_payload_sha256": "",
    }

    worm_manifest = {
        "schema_id": "kt.operator.worm_manifest.v1",
        "created_utc": _utc_now_iso_z(),
        "run_id": run_id,
        "program_id": effective_program_id,
        "artifacts": [
            {"path": "verdict.txt", "sha256": _sha256_file((run_dir / "verdict.txt").resolve())},
            {"path": "reports/one_line_verdict.txt", "sha256": _sha256_file((reports_dir / "one_line_verdict.txt").resolve())},
            {"path": "reports/operator_fingerprint.json", "sha256": _sha256_file((reports_dir / "operator_fingerprint.json").resolve())},
            {"path": "reports/operator_intent.json", "sha256": _sha256_file((reports_dir / "operator_intent.json").resolve())},
            {"path": "evidence/replay_receipt.json", "sha256": _sha256_file((evidence_dir / "replay_receipt.json").resolve())},
            {"path": "evidence/secret_scan_report.json", "sha256": _sha256_file((evidence_dir / "secret_scan_report.json").resolve())},
            {"path": "delivery/delivery_lint_report.json", "sha256": _sha256_file((delivery_out_dir / "delivery_lint_report.json").resolve())},
        ],
        "constitutional_snapshot_payload_sha256": "",
    }

    constitutional_snapshot["delivery_manifest_payload_sha256"] = _payload_sha256(delivery_manifest, exclude_keys={"worm_manifest_payload_sha256"})
    worm_manifest["constitutional_snapshot_payload_sha256"] = _payload_sha256(
        constitutional_snapshot,
        exclude_keys={"delivery_manifest_payload_sha256"},
    )
    delivery_manifest["worm_manifest_payload_sha256"] = _payload_sha256(
        worm_manifest,
        exclude_keys={"constitutional_snapshot_payload_sha256"},
    )

    _write_json_worm(
        path=evidence_dir / "constitutional_snapshot.json",
        obj=constitutional_snapshot,
        label="constitutional_snapshot.json",
    )
    _write_json_worm(path=evidence_dir / "worm_manifest.json", obj=worm_manifest, label="worm_manifest.json")
    _write_json_worm(path=delivery_out_dir / "delivery_manifest.json", obj=delivery_manifest, label="delivery_manifest.json")

    from tools.operator.bindingloop_verify import verify_binding_loop
    from tools.delivery.delivery_contract_validator import validate_delivery_contract

    bindingloop_report = verify_binding_loop(run_dir)
    if str(bindingloop_report.get("status", "")).strip() != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: binding loop did not PASS after bundle emission")
    _write_json_worm(path=reports_dir / "bindingloop_check.json", obj=bindingloop_report, label="bindingloop_check.json")

    evidence_core_merkle = _build_evidence_core_merkle(
        run_dir=run_dir,
        required_relpaths=[
            "evidence/constitutional_snapshot.json",
            "evidence/worm_manifest.json",
            "evidence/replay_receipt.json",
            "reports/operator_fingerprint.json",
            "reports/operator_intent.json",
            "delivery/delivery_manifest.json",
            "delivery/delivery_lint_report.json",
            "evidence/secret_scan_report.json",
        ],
    )
    _write_json_worm(path=evidence_dir / "evidence_core_merkle.json", obj=evidence_core_merkle, label="evidence_core_merkle.json")

    _append_run_local_federal_ledger(
        repo_root=repo_root,
        run_dir=run_dir,
        program_id=effective_program_id,
        delivery_zip_sha256=zip_sha,
        evidence_core_merkle_root_sha256=str(evidence_core_merkle.get("evidence_core_merkle_root_sha256", "")).strip(),
        operator_intent_hash=str(operator_intent.get("operator_intent_hash", "")).strip(),
    )

    delivery_contract_report = validate_delivery_contract(delivery_out_dir, require_real_path_receipt=False)
    _write_json_worm(
        path=reports_dir / "delivery_contract_validation.json",
        obj=delivery_contract_report,
        label="delivery_contract_validation.json",
    )
    _write_runtime_attachment_reports(
        run_dir=run_dir,
        program_id=effective_program_id,
        lane_id=lane_id,
        lane_label=lane_label,
        head=head,
        delivery_manifest_path=(delivery_out_dir / "delivery_manifest.json").resolve(),
        bindingloop_report=bindingloop_report,
        delivery_contract_report=delivery_contract_report,
    )
    delivery_contract_report = validate_delivery_contract(delivery_out_dir)
    _write_json_worm(
        path=reports_dir / "delivery_contract_validation.json",
        obj=delivery_contract_report,
        label="delivery_contract_validation.json",
    )

    return {"evidence_dir": evidence_dir.as_posix(), "delivery": delivery_result, "delivery_manifest": delivery_manifest}

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
    return _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_CANONICAL_HMAC",
        lane_label="canonical_hmac",
        verdict_line=verdict_line,
        program_id="program.certify.canonical_hmac",
        sweep_id=sweep_id,
        sweep_sha256=sweep_sha256,
        core_copy_dirs=[
            (f"sweeps/{sweep_id}", f"sweeps/{sweep_id}"),
            ("transcripts", "transcripts"),
        ],
        run_protocol_notes="Operator certify canonical_hmac evidence bundle.",
        delivery_manifest_extras=None,
    )


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _normalize_argv_for_safe_run(argv: Optional[Sequence[str]]) -> List[str]:
    items = list(argv) if argv is not None else sys.argv[1:]
    if "--safe-run" not in items:
        return items
    out: List[str] = []
    inserted = False
    for item in items:
        if item == "--safe-run":
            if not inserted:
                out.append("safe-run")
                inserted = True
            continue
        out.append(item)
    return out


def _load_config_arg(repo_root: Path, raw: str) -> Dict[str, Any]:
    value = str(raw).strip()
    if not value:
        return {}
    maybe_path = Path(value).expanduser()
    if maybe_path.exists():
        if not maybe_path.is_absolute():
            maybe_path = (repo_root / maybe_path).resolve()
        return _load_json(maybe_path)
    obj = json.loads(value)
    if not isinstance(obj, dict):
        raise FL3ValidationError("FAIL_CLOSED: --config must be a JSON object or a path to one")
    return obj


def _write_operator_plane_artifacts(*, run_dir: Path, program_id: str, config: Dict[str, Any], assurance_mode: str) -> Dict[str, Any]:
    fingerprint = titanium_operator_fingerprint()
    _write_json_worm(path=run_dir / "reports" / "operator_fingerprint.json", obj=fingerprint, label="operator_fingerprint.json")
    intent_obj = {
        "operator_id": fingerprint["operator_id"],
        "operator_intent_class": str(os.environ.get("KT_OPERATOR_INTENT_CLASS", "AUDIT")).upper(),
        "operator_intent_hash": sha256_json(
            {
                "assurance_mode": assurance_mode,
                "config": config,
                "program_id": program_id,
            }
        ),
        "program_id": program_id,
        "config_sha256": sha256_json(config),
        "inputs_sha256_list": [],
        "assurance_mode": assurance_mode,
        "constitution_epoch": 1,
        "created_utc": _utc_now_iso_z(),
    }
    _write_json_worm(path=run_dir / "reports" / "operator_intent.json", obj=intent_obj, label="operator_intent.json")
    return intent_obj


def cmd_safe_run(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    assurance_mode: str,
    program_id: str,
    config: Dict[str, Any],
    allow_dirty: bool,
) -> int:
    from tools.operator.constitution_self_check import self_check
    from tools.operator.governance_manifest_verify import _verify_manifest
    from tools.operator.hashpin import _manifest_path as _titanium_manifest_path
    from tools.operator.hashpin import _cmd_verify_required_pins
    from tools.operator.program_catalog_verify import _verify_catalog
    from tools.operator.source_integrity import _verify_source_integrity

    mode = str(assurance_mode).strip().lower()
    if mode not in {"practice", "production"}:
        raise FL3ValidationError("FAIL_CLOSED: --assurance-mode must be practice or production")

    program_map: Dict[str, List[str]] = {
        "program.certify.canonical_hmac": ["certify", "--lane", "canonical_hmac"],
        "program.hat_demo": ["hat-demo"],
    }
    validator_map = {
        "program.bindingloop.verify": ("python", "-m", "tools.operator.bindingloop_verify"),
        "program.replay.lint.hermetic": ("python", "-m", "tools.operator.hermetic_replay_linter"),
        "program.delivery.contract.validate": ("python", "-m", "tools.delivery.delivery_contract_validator"),
        "program.hashpin.verify_required_pins": ("python", "-m", "tools.operator.hashpin", "verify-required-pins"),
        "program.source.integrity.verify": ("python", "-m", "tools.operator.source_integrity", "verify"),
        "program.catalog.verify": ("python", "-m", "tools.operator.program_catalog_verify", "--strict"),
        "program.governance.verify_manifest": ("python", "-m", "tools.operator.governance_manifest_verify"),
    }

    if program_id not in program_map and program_id not in validator_map:
        raise FL3ValidationError(f"FAIL_CLOSED: unsupported safe-run program_id={program_id}")

    intent_obj = _write_operator_plane_artifacts(run_dir=run_dir, program_id=program_id, config=config, assurance_mode=mode)
    preflight: Dict[str, Any] = {
        "assurance_mode": mode,
        "profile": profile.name,
        "program_id": program_id,
        "status": "PASS",
        "checks": [],
    }

    def _record(name: str, ok: bool, detail: str = "") -> None:
        preflight["checks"].append({"check": name, "detail": detail or None, "status": "PASS" if ok else "FAIL"})
        if not ok:
            preflight["status"] = "FAIL"

    try:
        if mode == "production":
            _maybe_assert_clean_worktree(repo_root=repo_root, allow_dirty=False)
            _record("clean_worktree_required_in_production", True)
        else:
            _record("clean_worktree_required_in_production", True, "practice mode")
    except Exception as exc:  # noqa: BLE001
        _record("clean_worktree_required_in_production", False, str(exc))

    try:
        source_report = _verify_source_integrity()
        _record("source_integrity_verified", source_report.get("status") == "PASS")
    except Exception as exc:  # noqa: BLE001
        _record("source_integrity_verified", False, str(exc))

    try:
        catalog_report = _verify_catalog(strict=True)
        _record("program_catalog_verified", catalog_report.get("status") == "PASS")
    except Exception as exc:  # noqa: BLE001
        _record("program_catalog_verified", False, str(exc))

    try:
        constitution_report = self_check()
        _record("constitution_epoch_matches", constitution_report.get("status") == "PASS")
    except Exception as exc:  # noqa: BLE001
        _record("constitution_epoch_matches", False, str(exc))

    if mode == "production":
        try:
            gov_report = _verify_manifest(_titanium_manifest_path(repo_root))
            _record("governance_manifest_verified_and_signed", gov_report.get("status") == "PASS")
        except Exception as exc:  # noqa: BLE001
            _record("governance_manifest_verified_and_signed", False, str(exc))
        try:
            rc = _cmd_verify_required_pins(run_dir=run_dir / "preflight_hashpin")
            _record("pin_registry_all_required_pinned", rc == 0)
        except Exception as exc:  # noqa: BLE001
            _record("pin_registry_all_required_pinned", False, str(exc))
    else:
        _record("governance_manifest_verified_and_signed", True, "practice mode")
        _record("pin_registry_all_required_pinned", True, "practice mode")

    _write_json_worm(path=run_dir / "reports" / "operator_preflight.json", obj=preflight, label="operator_preflight.json")
    if preflight["status"] != "PASS":
        return titanium_write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.safe_run",
            failure_name="STOP_GATE_BLOCKED" if mode == "production" else "CATALOG_INCOMPLETE",
            message="preflight_failed",
            next_actions=["Inspect reports/operator_preflight.json and repair the failing Titanium gate."],
            operator_intent_hash=str(intent_obj.get("operator_intent_hash", "")),
        )

    env = _base_env(repo_root=repo_root)
    env["KT_SAFE_RUN_ACTIVE"] = "1"
    env["KT_SAFE_RUN_ASSURANCE_MODE"] = mode
    env["KT_SAFE_RUN_PROGRAM_ID"] = program_id
    env["KT_SAFE_RUN_OPERATOR_INTENT_HASH"] = str(intent_obj.get("operator_intent_hash", ""))
    env["KT_SAFE_RUN_OPERATOR_ID"] = str(intent_obj.get("operator_id", ""))
    env["KT_RUNTIME_ENTRYPOINT"] = f"safe-run:{program_id}"
    inner_run = (run_dir / "program_run").resolve()
    inner_run.mkdir(parents=True, exist_ok=True)
    if program_id in program_map:
        cmd = [sys.executable, "-m", "tools.operator.kt_cli", "--profile", profile.name, "--run-root", str(inner_run)]
        if allow_dirty or mode == "practice":
            cmd.append("--allow-dirty")
        cmd.extend(program_map[program_id])
    else:
        cmd = list(validator_map[program_id])
        if program_id == "program.bindingloop.verify":
            cmd.extend(["--run-dir", str(config.get("run_dir", "")), "--run-root", str(inner_run)])
        elif program_id == "program.replay.lint.hermetic":
            cmd.extend(["--delivery-dir", str(config.get("delivery_dir", "")), "--mve", str(config.get("mve", "")), "--run-root", str(inner_run)])
        elif program_id == "program.delivery.contract.validate":
            cmd.extend(["--delivery-dir", str(config.get("delivery_dir", "")), "--run-root", str(inner_run)])
        elif program_id == "program.governance.verify_manifest":
            cmd.extend(["--manifest", str(config.get("manifest", "KT_PROD_CLEANROOM/governance/governance_manifest.json")), "--run-root", str(inner_run)])
        else:
            cmd.extend(["--run-root", str(inner_run)])

    rc, _out, _log = _run_cmd(repo_root=repo_root, run_dir=run_dir, name="safe_run_dispatch", cmd=cmd, env=env, allow_nonzero=True)
    if rc != 0:
        return titanium_write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.safe_run",
            failure_name="STOP_GATE_BLOCKED" if mode == "production" else "CATALOG_INCOMPLETE",
            message=f"safe_run_dispatch_rc={rc}",
            next_actions=["Inspect transcripts/safe_run_dispatch.log and the nested program_run artifacts."],
            operator_intent_hash=str(intent_obj.get("operator_intent_hash", "")),
        )
    verdict = (
        f"KT_SAFE_RUN_PASS cmd=safe-run profile={profile.name} assurance_mode={mode} "
        f"program_id={program_id} nested_run={inner_run.as_posix()}"
    )
    write_text_worm(path=run_dir / "verdict.txt", text=verdict + "\n", label="verdict.txt")
    write_text_worm(path=run_dir / "reports" / "one_line_verdict.txt", text=verdict + "\n", label="one_line_verdict.txt")
    print(verdict)
    return 0


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
    step("pytest_cleanroom", ["python", "-m", "pytest", "-q", *CI_SIM_PYTEST_TARGETS], step_env=pytest_env)
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
        [
            "python",
            "-m",
            "tools.verification.validate_receipts",
            "--receipts-dir",
            ARCHIVE_VAULT_RECEIPTS_PREFIX,
            "--out-dir",
            str(run_dir),
        ],
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

    print(verdict)
    return 0


def cmd_red_assault(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    pack_id: str,
    pressure_level: str,
    attack_mix: Sequence[str],
    sample_count: int,
    seed: int,
    overlay_ids: Sequence[str],
    probe_pack_ref: str = "",
    probe_payloads: str = "",
    probe_engine: str = "stub",
    base_model_dir: str = "",
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    env = _base_env(repo_root=repo_root)
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

    pack = str(pack_id).strip()
    if not pack:
        raise FL3ValidationError("FAIL_CLOSED: --pack-id missing/empty")
    if pack not in {"fl3_factory_v1", "serious_v1"}:
        raise FL3ValidationError(f"FAIL_CLOSED: unsupported --pack-id {pack!r} (supported: fl3_factory_v1, serious_v1)")

    probe_pack_ref_norm = str(probe_pack_ref).strip()
    probe_payloads_norm = str(probe_payloads).strip()
    probe_engine_norm = (str(probe_engine).strip() or "stub").strip()
    base_model_dir_norm = str(base_model_dir).strip()
    if pack != "serious_v1":
        if probe_pack_ref_norm or probe_payloads_norm or base_model_dir_norm or probe_engine_norm != "stub":
            raise FL3ValidationError("FAIL_CLOSED: probe flags are supported only for --pack-id serious_v1")

    level = str(pressure_level).strip().lower()
    if level not in {"low", "med", "high", "l0", "l1", "l2", "l3", "l4"}:
        raise FL3ValidationError("FAIL_CLOSED: --pressure-level must be one of: low, med, high, l0, l1, l2, l3, l4")
    if int(sample_count) <= 0:
        raise FL3ValidationError("FAIL_CLOSED: --sample-count must be > 0")

    reports_dir = (run_dir / "reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    all_passed = False
    failures: List[Dict[str, Any]] = []
    failure_count = 0
    observed_tool_rc = 0
    attack_mix_norm = sorted([str(x).strip() for x in attack_mix if str(x).strip()])
    overlay_ids_norm = sorted([str(x).strip() for x in overlay_ids if str(x).strip()])
    probe_pack_id = ""
    probe_payload_bundle_sha256 = ""
    probe_engine_used = ""
    executed_probe_count = 0
    probe_failure_count = 0

    if pack == "fl3_factory_v1":
        out_summary = (reports_dir / "red_assault_summary.json").resolve()
        ra_rc, _ra_out, _ra_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="red_assault",
            cmd=[sys.executable, "-m", "tools.verification.fl3_red_assault", "--out", str(out_summary)],
            env=env,
            allow_nonzero=True,
        )
        observed_tool_rc = int(ra_rc)
        if not out_summary.exists():
            raise FL3ValidationError("FAIL_CLOSED: missing reports/red_assault_summary.json (unexpected)")

        summary = _load_json(out_summary)
        all_passed = bool(summary.get("all_passed", False))
        results = summary.get("results", [])
        if not isinstance(results, list):
            raise FL3ValidationError("FAIL_CLOSED: red_assault_summary.results must be a list")

        failures = [r for r in results if isinstance(r, dict) and bool(r.get("passed")) is False]
        failure_count = int(len(failures))
        taxonomy = {
            "schema_id": "kt.operator.red_assault.failure_taxonomy.unbound.v1",
            "pack_id": pack,
            "pressure_level": level,
            "attack_mix": attack_mix_norm,
            "sample_count": int(sample_count),
            "seed": int(seed),
            "all_passed": bool(all_passed),
            "failure_count": int(failure_count),
            "failures": [
                {
                    "attack_id": str(r.get("attack_id", "")).strip(),
                    "observed_exit_code": int(r.get("observed_exit_code", -1)),
                    "expected_exit_codes": list(r.get("expected_exit_codes", [])),
                }
                for r in sorted(failures, key=lambda rr: str(rr.get("attack_id", "")).strip())
            ],
            "notes": "Factory red assault pack: verifies export traversal + schema hash tamper + entrypoint hash tamper are blocked.",
            "observed_tool_rc": int(ra_rc),
        }
        _write_json_worm(path=reports_dir / "failure_taxonomy.json", obj=taxonomy, label="failure_taxonomy.json")

        top_failures_path = (reports_dir / "top_failures.jsonl").resolve()
        lines: List[str] = []
        for r in sorted(failures, key=lambda rr: str(rr.get("attack_id", "")).strip()):
            lines.append(json.dumps(r, sort_keys=True, ensure_ascii=True))
        write_text_worm(path=top_failures_path, text="\n".join(lines) + ("\n" if lines else ""), label="top_failures.jsonl")
    else:
        pins_json = json.dumps(
            {
                "sealed_tag": profile.sealed_tag,
                "sealed_commit": profile.sealed_commit,
                "law_bundle_hash": profile.law_bundle_hash,
                "suite_registry_id": profile.suite_registry_id,
                "determinism_expected_root_hash": profile.determinism_expected_root_hash,
                "head_git_sha": head,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        cmd = [
            sys.executable,
            "-m",
            "tools.operator.serious_layer.red_assault_serious_v1",
            "--out-dir",
            str(reports_dir),
            "--pins-json",
            pins_json,
            "--pressure",
            str(level),
            "--seed",
            str(int(seed)),
            "--case-budget",
            str(int(sample_count)),
        ]
        if attack_mix_norm:
            cmd += ["--attack-mix", *attack_mix_norm]
        for ov in overlay_ids_norm:
            cmd += ["--overlay-id", ov]
        if probe_payloads_norm:
            cmd += ["--probe-payloads", probe_payloads_norm, "--probe-engine", probe_engine_norm]
            if probe_pack_ref_norm:
                cmd += ["--probe-pack-ref", probe_pack_ref_norm]
            if base_model_dir_norm:
                cmd += ["--base-model-dir", base_model_dir_norm]

        ra_rc, ra_out, _ra_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="red_assault_serious_v1",
            cmd=cmd,
            env=env,
            allow_nonzero=True,
        )
        observed_tool_rc = int(ra_rc)
        # Script writes failure_taxonomy.json/top_failures.jsonl and prints a JSON summary.
        try:
            last = (ra_out.strip().splitlines()[-1] if ra_out.strip() else "{}")
            summary = json.loads(last)
        except Exception:  # noqa: BLE001
            summary = {}
        all_passed = bool(summary.get("status") == "PASS")
        try:
            failure_count = int(summary.get("failure_count", 0))
        except Exception:  # noqa: BLE001
            failure_count = 0

        probe_pack_id = str(summary.get("probe_pack_id", "")).strip()
        probe_payload_bundle_sha256 = str(summary.get("probe_payload_bundle_sha256", "")).strip()
        probe_engine_used = str(summary.get("probe_engine", "")).strip()
        try:
            executed_probe_count = int(summary.get("executed_probe_count", 0))
        except Exception:  # noqa: BLE001
            executed_probe_count = 0
        try:
            probe_failure_count = int(summary.get("probe_failure_count", 0))
        except Exception:  # noqa: BLE001
            probe_failure_count = 0

        # Emit a lane-level summary under the contract name.
        out_summary = (reports_dir / "red_assault_summary.json").resolve()
        _write_json_worm(
            path=out_summary,
            obj={
                "schema_id": "kt.operator.serious_layer.red_assault_summary.unbound.v1",
                "pack_id": pack,
                "pressure_level": level,
                "attack_mix": attack_mix_norm,
                "overlay_ids": overlay_ids_norm,
                "case_budget": int(sample_count),
                "seed": int(seed),
                "probe_pack_id": probe_pack_id,
                "probe_payload_bundle_sha256": probe_payload_bundle_sha256,
                "probe_engine": (probe_engine_used or probe_engine_norm),
                "executed_probe_count": int(executed_probe_count),
                "probe_failure_count": int(probe_failure_count),
                "status": "PASS" if all_passed else "HOLD",
                "observed_tool_rc": int(observed_tool_rc),
                "summary": summary,
                "notes": "Serious Layer v1: generator-first red assault (governance-plane executed; optional probe packs executed with out-of-repo payloads; hash-ref-only artifacts).",
            },
            label="red_assault_summary.json",
        )

    verdict_kind = "PASS" if all_passed else "HOLD"
    verdict = (
        f"KT_RED_ASSAULT_{verdict_kind} cmd=red-assault profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} pack_id={pack} pressure_level={level} sample_count={int(sample_count)} seed={int(seed)} "
        f"all_passed={int(bool(all_passed))} failures={int(failure_count)} tool_rc={int(observed_tool_rc)}"
    )

    lane_id = "KT_OPERATOR_RED_ASSAULT_SERIOUS_V1" if pack == "serious_v1" else "KT_OPERATOR_RED_ASSAULT_V1"
    lane_label = "red_assault.serious_v1" if pack == "serious_v1" else "red_assault.v1"

    _ = _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id=lane_id,
        lane_label=lane_label,
        verdict_line=verdict,
        program_id=("program.red_assault.serious_v1" if pack == "serious_v1" else "program.red_assault.v1"),
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts")],
        run_protocol_notes=f"Operator red-assault lane; pack_id={pack} pressure_level={level} sample_count={int(sample_count)} seed={int(seed)}",
        delivery_manifest_extras={
            "red_assault": {
                "program": "serious_v1" if pack == "serious_v1" else "v1",
                "pack_id": pack,
                "pressure_level": level,
                "attack_mix": attack_mix_norm,
                "overlay_ids": overlay_ids_norm,
                "sample_count": int(sample_count),
                "seed": int(seed),
                "all_passed": bool(all_passed),
                "failure_count": int(failure_count),
                "probe_pack_id": probe_pack_id,
                "probe_payload_bundle_sha256": probe_payload_bundle_sha256,
                "probe_engine": (probe_engine_used or probe_engine_norm),
                "executed_probe_count": int(executed_probe_count),
                "probe_failure_count": int(probe_failure_count),
            }
        },
    )

    print(verdict)
    return 0


def _resolve_existing_run_dir(*, repo_root: Path, value: str) -> Path:
    target = Path(str(value)).expanduser()
    if not target.is_absolute():
        target = (repo_root / target).resolve()
    _assert_under_runs_root(repo_root=repo_root, path=target)
    if not target.exists() or not target.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: run dir does not exist: {target.as_posix()}")
    return target


def _load_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return obj if isinstance(obj, dict) else None


def _classify_run_status(*, run_dir: Path) -> str:
    err = (run_dir / "error.txt").resolve()
    if err.exists():
        return "FAIL_CLOSED"
    v = (run_dir / "verdict.txt").resolve()
    if not v.exists():
        return "UNKNOWN"
    t = v.read_text(encoding="utf-8", errors="replace").strip().upper()
    if "_PASS" in t and "FAIL_CLOSED" not in t:
        return "PASS"
    if "_HOLD" in t:
        return "HOLD"
    if "_BLOCKED" in t:
        return "BLOCKED"
    return "UNKNOWN"


def cmd_continuous_gov(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    program: str,
    baseline_run: str,
    window: str,
    thresholds_json: str,
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    program = str(program).strip().lower()
    if program not in {"v1", "serious_v1"}:
        raise FL3ValidationError("FAIL_CLOSED: --program must be one of: v1, serious_v1")
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

    if program == "serious_v1":
        env = _base_env(repo_root=repo_root)
        reports_dir = (run_dir / "reports").resolve()
        reports_dir.mkdir(parents=True, exist_ok=True)
        pins_json = json.dumps(
            {
                "sealed_tag": profile.sealed_tag,
                "sealed_commit": profile.sealed_commit,
                "law_bundle_hash": profile.law_bundle_hash,
                "suite_registry_id": profile.suite_registry_id,
                "determinism_expected_root_hash": profile.determinism_expected_root_hash,
                "head_git_sha": head,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        cg_rc, cg_out, _cg_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="continuous_gov_serious_v1",
            cmd=[
                sys.executable,
                "-m",
                "tools.operator.serious_layer.continuous_gov_serious_v1",
                "--out-dir",
                str(reports_dir),
                "--pins-json",
                pins_json,
                "--baseline-run",
                str(baseline_run),
                "--window",
                str(window),
                "--thresholds",
                str(thresholds_json),
            ],
            env=env,
            allow_nonzero=True,
        )
        try:
            last = (cg_out.strip().splitlines()[-1] if cg_out.strip() else "{}")
            res = json.loads(last)
        except Exception:  # noqa: BLE001
            res = {}
        ok = bool(res.get("status") == "PASS") and int(cg_rc) == 0

        verdict_kind = "PASS" if ok else "HOLD"
        verdict = (
            f"KT_CONTINUOUS_GOV_{verdict_kind} cmd=continuous-gov profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
            f"head={head} program={program} baseline_run={baseline_run} window={str(window).strip() or '<baseline_only>'}"
        )

        baseline_dir = _resolve_existing_run_dir(repo_root=repo_root, value=baseline_run)
        _ = _emit_delivery_bundle(
            repo_root=repo_root,
            profile=profile,
            run_dir=run_dir,
            head=head,
            lane_id="KT_OPERATOR_CONTINUOUS_GOV_SERIOUS_V1",
            lane_label="continuous_gov.serious_v1",
            verdict_line=verdict,
            core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts")],
            datasets=[
                {"relpath": "baseline_run/delivery_manifest.json", "sha256": sha256_file((baseline_dir / "delivery" / "delivery_manifest.json").resolve())},
                {"relpath": "baseline_run/run_protocol.json", "sha256": sha256_file((baseline_dir / "evidence" / "run_protocol.json").resolve())},
            ],
            run_protocol_notes=f"Continuous governance (Serious Layer v1) diff against baseline_run={baseline_run} window={window}",
            program_id="program.continuous_gov.serious_v1",
            delivery_manifest_extras={
                "continuous_gov": {
                    "program": program,
                    "baseline_run": str(baseline_run),
                    "window": str(window),
                    "thresholds": (json.loads(thresholds_json) if str(thresholds_json).strip() else {}),
                    "result": res,
                }
            },
        )

        print(verdict)
        return 0 if ok else 2

    baseline = _resolve_existing_run_dir(repo_root=repo_root, value=baseline_run)
    base_manifest = _load_optional_json((baseline / "delivery" / "delivery_manifest.json").resolve())
    base_protocol = _load_optional_json((baseline / "evidence" / "run_protocol.json").resolve())
    if base_manifest is None or base_protocol is None:
        raise FL3ValidationError(
            "FAIL_CLOSED: baseline run is missing required artifacts for diffing. "
            "NEXT_ACTION: provide a baseline run produced by kt_cli certify canonical_hmac (delivery bundle required)."
        )

    thresholds: Dict[str, Any] = {}
    if str(thresholds_json).strip():
        try:
            thresholds_obj = json.loads(str(thresholds_json))
        except Exception as exc:  # noqa: BLE001
            raise FL3ValidationError("FAIL_CLOSED: --thresholds must be valid JSON") from exc
        if not isinstance(thresholds_obj, dict):
            raise FL3ValidationError("FAIL_CLOSED: --thresholds must be a JSON object")
        thresholds = thresholds_obj

    runs_root = (_runs_root(repo_root) / "KT_OPERATOR").resolve()
    candidates: List[Path] = []
    if runs_root.exists():
        for p in sorted(runs_root.iterdir(), reverse=True):
            if p.is_dir():
                candidates.append(p.resolve())

    window_runs: List[Path] = []
    w = str(window).strip()
    if not w:
        window_runs = [baseline]
    elif w.isdigit():
        n = int(w)
        if n <= 0:
            raise FL3ValidationError("FAIL_CLOSED: --window N must be > 0")
        window_runs = candidates[:n]
        if baseline not in window_runs:
            window_runs.append(baseline)
    else:
        items = [x.strip() for x in w.replace(";", ",").split(",") if x.strip()]
        if not items:
            raise FL3ValidationError("FAIL_CLOSED: --window list is empty")
        window_runs = [_resolve_existing_run_dir(repo_root=repo_root, value=x) for x in items]
        if baseline not in window_runs:
            window_runs.append(baseline)

    # Deduplicate and exclude the current run_dir (analysis should only read prior roots).
    unique: List[Path] = []
    seen: set[str] = set()
    for p in window_runs:
        key = p.as_posix()
        if key == run_dir.resolve().as_posix():
            continue
        if key not in seen:
            seen.add(key)
            unique.append(p)
    window_runs = unique

    def facts(p: Path) -> Dict[str, Any]:
        dm = _load_optional_json((p / "delivery" / "delivery_manifest.json").resolve()) or {}
        rp = _load_optional_json((p / "evidence" / "run_protocol.json").resolve()) or {}
        status = _classify_run_status(run_dir=p)
        return {
            "run_dir": p.as_posix(),
            "status": status,
            "verdict": (p / "verdict.txt").read_text(encoding="utf-8", errors="replace").strip()
            if (p / "verdict.txt").exists()
            else "",
            "pins": dm.get("pins", {}),
            "lane": dm.get("lane", ""),
            "lane_id": rp.get("lane_id", ""),
            "bundle_root_hash": rp.get("bundle_root_hash", ""),
        }

    base_facts = facts(baseline)
    compared = [facts(p) for p in window_runs if p != baseline]

    pin_fields = ("sealed_commit", "law_bundle_hash", "suite_registry_id", "determinism_expected_root_hash")
    regressions: List[Dict[str, Any]] = []
    drift_rows: List[Dict[str, Any]] = []
    for row in compared:
        drift: Dict[str, Any] = {"run_dir": row["run_dir"], "status": row["status"], "pin_deltas": {}, "bundle_root_hash_changed": False}
        for k in pin_fields:
            b = str((base_facts.get("pins") or {}).get(k, "")).strip()
            c = str((row.get("pins") or {}).get(k, "")).strip()
            if b and c and b != c:
                drift["pin_deltas"][k] = {"baseline": b, "current": c}
        drift["bundle_root_hash_changed"] = bool(base_facts.get("bundle_root_hash") and row.get("bundle_root_hash") and base_facts["bundle_root_hash"] != row["bundle_root_hash"])
        drift_rows.append(drift)
        if drift["pin_deltas"]:
            regressions.append({"kind": "PIN_DRIFT", "run_dir": row["run_dir"], "details": drift["pin_deltas"]})
        if row["status"] not in {"PASS"}:
            regressions.append({"kind": "NON_PASS_RUN", "run_dir": row["run_dir"], "status": row["status"]})

    drift_report = {
        "schema_id": "kt.operator.continuous_gov.drift_report.unbound.v1",
        "baseline_run_dir": baseline.as_posix(),
        "window": w or "<baseline_only>",
        "thresholds": thresholds,
        "baseline": base_facts,
        "drift": drift_rows,
        "created_utc": _utc_now_iso_z(),
    }
    regression_report = {
        "schema_id": "kt.operator.continuous_gov.regression_report.unbound.v1",
        "baseline_run_dir": baseline.as_posix(),
        "regressions": regressions,
        "regression_count": int(len(regressions)),
        "created_utc": _utc_now_iso_z(),
    }
    trend = {
        "schema_id": "kt.operator.continuous_gov.trend_snapshot.unbound.v1",
        "baseline_run_dir": baseline.as_posix(),
        "runs": [base_facts] + compared,
        "counts": {
            "PASS": int(sum(1 for r in [base_facts] + compared if r.get("status") == "PASS")),
            "HOLD": int(sum(1 for r in [base_facts] + compared if r.get("status") == "HOLD")),
            "BLOCKED": int(sum(1 for r in [base_facts] + compared if r.get("status") == "BLOCKED")),
            "FAIL_CLOSED": int(sum(1 for r in [base_facts] + compared if r.get("status") == "FAIL_CLOSED")),
            "UNKNOWN": int(sum(1 for r in [base_facts] + compared if r.get("status") == "UNKNOWN")),
        },
        "created_utc": _utc_now_iso_z(),
    }

    reports_dir = (run_dir / "reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    _write_json_worm(path=reports_dir / "drift_report.json", obj=drift_report, label="drift_report.json")
    _write_json_worm(path=reports_dir / "regression_report.json", obj=regression_report, label="regression_report.json")
    _write_json_worm(path=reports_dir / "trend_snapshot.json", obj=trend, label="trend_snapshot.json")

    # Human diff summary (deterministic).
    md_lines: List[str] = []
    md_lines.append("# KT Continuous Governance Diff Summary")
    md_lines.append("")
    md_lines.append(f"- baseline_run: `{baseline.as_posix()}`")
    md_lines.append(f"- window: `{w or '<baseline_only>'}`")
    md_lines.append(f"- regression_count: `{len(regressions)}`")
    if regressions:
        md_lines.append("")
        md_lines.append("## Regressions")
        for r in regressions:
            md_lines.append(f"- {r.get('kind')} run={r.get('run_dir')} status={r.get('status','')}")
    write_text_worm(path=reports_dir / "diff_summary.md", text="\n".join(md_lines) + "\n", label="diff_summary.md")

    verdict_kind = "PASS" if not regressions else "HOLD"
    verdict = (
        f"KT_CONTINUOUS_GOV_{verdict_kind} cmd=continuous-gov profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} program={program} baseline_run={baseline.as_posix()} window={w or '<baseline_only>'} regressions={len(regressions)}"
    )

    _ = _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_CONTINUOUS_GOV_V1",
        lane_label="continuous_gov.v1",
        verdict_line=verdict,
        program_id="program.continuous_gov.v1",
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts")],
        datasets=[
            {"relpath": "baseline_run/delivery_manifest.json", "sha256": sha256_file((baseline / "delivery" / "delivery_manifest.json").resolve())},
            {"relpath": "baseline_run/run_protocol.json", "sha256": sha256_file((baseline / "evidence" / "run_protocol.json").resolve())},
        ],
        run_protocol_notes=f"Continuous governance diff against baseline_run={baseline.as_posix()} window={w or '<baseline_only>'}",
        delivery_manifest_extras={
            "continuous_gov": {
                "baseline_run": baseline.as_posix(),
                "window": w,
                "thresholds": thresholds,
                "regression_count": int(len(regressions)),
            }
        },
    )

    print(verdict)
    return 0


def _load_overlay_registry(*, repo_root: Path) -> Dict[str, Any]:
    reg_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "OVERLAYS" / "OVERLAY_REGISTRY.json").resolve()
    if not reg_path.exists():
        raise FL3ValidationError(
            "FAIL_CLOSED: missing overlay registry. "
            "NEXT_ACTION: create KT_PROD_CLEANROOM/AUDITS/OVERLAYS/OVERLAY_REGISTRY.json and overlay packs under packs/."
        )
    reg = _load_json(reg_path)
    if str(reg.get("schema_id", "")).strip() != "kt.operator.overlay_registry.unbound.v1":
        raise FL3ValidationError("FAIL_CLOSED: overlay registry schema_id mismatch")
    overlays = reg.get("overlays")
    if not isinstance(overlays, list) or not overlays:
        raise FL3ValidationError("FAIL_CLOSED: overlay registry overlays missing/empty")
    return reg


def _overlay_entry_by_id(*, registry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    overlays = registry.get("overlays", [])
    if not isinstance(overlays, list):
        return out
    for row in overlays:
        if not isinstance(row, dict):
            continue
        oid = str(row.get("overlay_id", "")).strip()
        if oid:
            out[oid] = row
    return out


def _load_and_verify_overlay_pack(*, repo_root: Path, entry: Dict[str, Any]) -> Dict[str, Any]:
    rel = str(entry.get("pack_relpath", "")).strip()
    expected = str(entry.get("pack_sha256", "")).strip()
    if not rel or len(expected) != 64:
        raise FL3ValidationError("FAIL_CLOSED: overlay registry entry missing pack_relpath or pack_sha256")
    pack_path = Path(rel)
    if not pack_path.is_absolute():
        pack_path = (repo_root / pack_path).resolve()
    if not pack_path.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: overlay pack missing: {pack_path.as_posix()}")
    got = sha256_file(pack_path)
    if got != expected:
        raise FL3ValidationError(f"FAIL_CLOSED: overlay pack hash mismatch for {pack_path.as_posix()} expected={expected} got={got}")
    pack = _load_json(pack_path)
    if str(pack.get("schema_id", "")).strip() != "kt.operator.overlay_pack.unbound.v1":
        raise FL3ValidationError("FAIL_CLOSED: overlay pack schema_id mismatch")
    return pack


def cmd_overlay_apply(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    overlay_ids: Sequence[str],
    target_lane: str,
    strict: bool,
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

    requested = [str(x).strip() for x in overlay_ids if str(x).strip()]
    if not requested:
        raise FL3ValidationError("FAIL_CLOSED: at least one --overlay-id is required")

    lane = str(target_lane).strip()
    if lane not in {"certify", "red_assault", "continuous_gov", "forge"}:
        raise FL3ValidationError("FAIL_CLOSED: --target-lane must be one of: certify, red_assault, continuous_gov, forge")

    reg = _load_overlay_registry(repo_root=repo_root)
    by_id = _overlay_entry_by_id(registry=reg)

    resolved: List[Dict[str, Any]] = []
    suite_add: List[str] = []
    policy_add: List[str] = []
    scorer_overrides: List[Dict[str, Any]] = []
    reporting_fields: List[str] = []

    for oid in requested:
        entry = by_id.get(oid)
        if entry is None:
            if strict:
                raise FL3ValidationError(f"FAIL_CLOSED: overlay id not in registry: {oid}")
            continue
        pack = _load_and_verify_overlay_pack(repo_root=repo_root, entry=entry)
        applies = pack.get("applies_to", [])
        if not isinstance(applies, list) or lane not in [str(x).strip() for x in applies]:
            raise FL3ValidationError(f"FAIL_CLOSED: overlay {oid} does not apply_to target lane {lane!r}")

        suite_add += [str(x).strip() for x in (pack.get("suite_scope_additions", []) or []) if str(x).strip()]
        policy_add += [str(x).strip() for x in (pack.get("policy_additions", []) or []) if str(x).strip()]
        scorer_overrides += [x for x in (pack.get("scorer_overrides", []) or []) if isinstance(x, dict)]
        reporting_fields += [str(x).strip() for x in (pack.get("reporting_fields", []) or []) if str(x).strip()]

        resolved.append(
            {
                "overlay_id": str(pack.get("overlay_id", "")).strip() or oid,
                "version": str(pack.get("version", "")).strip(),
                "pack_relpath": str(entry.get("pack_relpath", "")).strip(),
                "pack_sha256": str(entry.get("pack_sha256", "")).strip(),
                "suite_scope_additions": sorted(set([str(x).strip() for x in pack.get("suite_scope_additions", []) if str(x).strip()])),
                "policy_additions": sorted(set([str(x).strip() for x in pack.get("policy_additions", []) if str(x).strip()])),
                "reporting_fields": sorted(set([str(x).strip() for x in pack.get("reporting_fields", []) if str(x).strip()])),
            }
        )

    suite_add = sorted(set(suite_add))
    policy_add = sorted(set(policy_add))
    reporting_fields = sorted(set(reporting_fields))

    base_cfg = {
        "schema_id": "kt.operator.overlay_base_config.unbound.v1",
        "target_lane": lane,
        "overlay_ids": [],
        "suite_scope_additions": [],
        "policy_additions": [],
        "scorer_overrides": [],
        "reporting_fields": [],
    }
    applied_cfg = {
        **base_cfg,
        "overlay_ids": sorted([r["overlay_id"] for r in resolved]),
        "suite_scope_additions": suite_add,
        "policy_additions": policy_add,
        "scorer_overrides": scorer_overrides,
        "reporting_fields": reporting_fields,
    }

    reports_dir = (run_dir / "reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    resolution = {
        "schema_id": "kt.operator.overlay_resolution.unbound.v1",
        "registry_id": str(reg.get("registry_id", "")).strip(),
        "target_lane": lane,
        "requested_overlay_ids": requested,
        "resolved_overlays": resolved,
        "applied_config_hash": sha256_json(applied_cfg),
        "created_utc": _utc_now_iso_z(),
        "strict": bool(strict),
    }
    _write_json_worm(path=reports_dir / "overlay_resolution.json", obj=resolution, label="overlay_resolution.json")

    diff = {
        "schema_id": "kt.operator.overlay_diff.unbound.v1",
        "base_config_hash": sha256_json(base_cfg),
        "applied_config_hash": resolution["applied_config_hash"],
        "added": {
            "overlay_ids": applied_cfg["overlay_ids"],
            "suite_scope_additions": suite_add,
            "policy_additions": policy_add,
            "reporting_fields": reporting_fields,
        },
        "created_utc": _utc_now_iso_z(),
    }
    _write_json_worm(path=reports_dir / "overlay_diff.json", obj=diff, label="overlay_diff.json")

    effect = {
        "schema_id": "kt.operator.overlay_effect_summary.unbound.v1",
        "target_lane": lane,
        "overlay_count": int(len(resolved)),
        "suite_scope_additions_count": int(len(suite_add)),
        "policy_additions_count": int(len(policy_add)),
        "reporting_fields_count": int(len(reporting_fields)),
        "created_utc": _utc_now_iso_z(),
    }
    _write_json_worm(path=reports_dir / "overlay_effect_summary.json", obj=effect, label="overlay_effect_summary.json")

    verdict = (
        f"KT_OVERLAY_APPLY_PASS cmd=overlay-apply profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} target_lane={lane} overlays={int(len(resolved))}"
    )

    _ = _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_OVERLAY_APPLY_V1",
        lane_label="overlay_apply.v1",
        verdict_line=verdict,
        program_id="program.overlay.apply",
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts")],
        run_protocol_notes=f"Overlay apply lane; target_lane={lane} overlays={','.join([r['overlay_id'] for r in resolved])}",
        delivery_manifest_extras={"overlay_apply": {"target_lane": lane, "resolved_overlays": resolved}},
    )

    print(verdict)
    return 0


def _parse_train_config_value(*, repo_root: Path, value: str) -> Dict[str, Any]:
    raw = str(value).strip()
    if not raw:
        raise FL3ValidationError("FAIL_CLOSED: --train-config missing/empty")
    p = Path(raw).expanduser()
    if p.exists():
        if not p.is_absolute():
            p = (repo_root / p).resolve()
        obj = json.loads(p.read_text(encoding="utf-8"))
    else:
        obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise FL3ValidationError("FAIL_CLOSED: train-config must be a JSON object")
    return obj


def _hash_tree_manifest(*, root: Path) -> Dict[str, Any]:
    root = root.resolve()
    if not root.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: missing input path for hashing: {root.as_posix()}")
    entries: List[Dict[str, str]] = []
    if root.is_file():
        entries.append({"path": root.name, "sha256": sha256_file(root)})
    else:
        files = [x for x in root.rglob("*") if x.is_file()]
        files.sort(key=lambda x: x.relative_to(root).as_posix())
        for p in files:
            entries.append({"path": p.relative_to(root).as_posix(), "sha256": sha256_file(p)})
    root_hash = sha256_json({"entries": entries})
    return {
        "schema_id": "kt.operator.hash_tree_manifest.unbound.v1",
        "root": root.as_posix(),
        "file_count": int(len(entries)),
        "entries": entries,
        "root_hash": root_hash,
    }

def cmd_forge(
    *,
    repo_root: Path,
    profile: V1Profile,
    run_dir: Path,
    failure_source: str,
    holdout_pack: str,
    train_config: str,
    adapter_id: str,
    seed: int,
    engine: str,
    base_model_dir: str,
    enable_real_engine: bool,
    allow_dirty: bool,
) -> int:
    _ = allow_dirty
    env = _base_env(repo_root=repo_root)
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

    src = Path(str(failure_source)).expanduser()
    if not src.is_absolute():
        src = (repo_root / src).resolve()
    if not src.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: --failure-source missing: {src.as_posix()}")

    pack = Path(str(holdout_pack)).expanduser()
    if not pack.is_absolute():
        pack = (repo_root / pack).resolve()
    if not pack.exists() or not pack.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: --holdout-pack missing: {pack.as_posix()}")

    aid = str(adapter_id).strip()
    if not aid:
        raise FL3ValidationError("FAIL_CLOSED: --adapter-id missing/empty")

    cfg = _parse_train_config_value(repo_root=repo_root, value=train_config)
    cfg["seed"] = int(seed)
    cfg["adapter_id"] = aid
    cfg.setdefault("adapter_version", "v0")
    cfg.setdefault("training_mode", "lora")

    forge_dir = (run_dir / "forge").resolve()
    forge_dir.mkdir(parents=True, exist_ok=True)

    train_cfg_path = (forge_dir / "train_config.json").resolve()
    _write_json_worm(path=train_cfg_path, obj=cfg, label="forge/train_config.json")

    data_manifest = _hash_tree_manifest(root=src)
    data_manifest_path = (forge_dir / "train_data_manifest.json").resolve()
    _write_json_worm(path=data_manifest_path, obj=data_manifest, label="forge/train_data_manifest.json")

    train_out_dir = (forge_dir / "training_run").resolve()
    cmd: List[str] = [
        sys.executable,
        "-m",
        "tools.training.rapid_lora_loop",
        "--dataset",
        str(src),
        "--config",
        str(train_cfg_path),
        "--engine",
        str(engine),
        "--out-dir",
        str(train_out_dir),
    ]
    if str(base_model_dir).strip():
        cmd += ["--base-model-dir", str(base_model_dir).strip()]
    if bool(enable_real_engine):
        cmd += ["--enable-real-engine"]

    train_rc, _train_out, _train_log = _run_cmd(
        repo_root=repo_root,
        run_dir=run_dir,
        name="forge_training",
        cmd=cmd,
        env=env,
        allow_nonzero=True,
    )

    # Training artifacts are WORM-owned by rapid_lora_loop; accept either PASS or FAIL_CLOSED manifest.
    train_manifest_path = (train_out_dir / "training_run_manifest.PASS.json").resolve()
    if not train_manifest_path.exists():
        train_manifest_path = (train_out_dir / "training_run_manifest.FAIL_CLOSED.json").resolve()
    if not train_manifest_path.exists():
        raise FL3ValidationError("FAIL_CLOSED: missing training_run_manifest.*.json (unexpected)")
    train_manifest = _load_json(train_manifest_path)
    training_status = str(train_manifest.get("status", "")).strip() or "UNKNOWN"
    produced = train_manifest.get("produced") if isinstance(train_manifest.get("produced"), dict) else {}
    adapter_hash = str(produced.get("output_adapter_hash", "") or "").strip()
    adapter_path = str(produced.get("output_adapter_path", "") or "").strip()

    adapter_meta = {
        "schema_id": "kt.operator.forge.adapter_metadata.unbound.v1",
        "adapter_id": aid,
        "adapter_version": str(cfg.get("adapter_version", "")).strip(),
        "training_engine": str(engine),
        "training_status": training_status,
        "training_rc": int(train_rc),
        "training_manifest_path": train_manifest_path.as_posix(),
        "output_adapter_hash": adapter_hash,
        "output_adapter_path": adapter_path,
        "created_utc": _utc_now_iso_z(),
    }
    _write_json_worm(path=forge_dir / "adapter_metadata.json", obj=adapter_meta, label="forge/adapter_metadata.json")

    validation_root = (forge_dir / "validation").resolve()
    validation_root.mkdir(parents=True, exist_ok=True)

    # Only run validation gates if training PASS; otherwise produce a blocked gate record and skip.
    promotion_gate_status = {"status": "SKIPPED", "promotion_blocked": True, "block_reason_codes": ["RC_TRAINING_NOT_PASS"]}
    before_after: Dict[str, Any] = {"schema_id": "kt.operator.forge.before_after_metrics.unbound.v1", "before": None, "after": None, "delta": None}

    if training_status == "PASS":
        def _mve_metrics(mve_dir: Path) -> Dict[str, Any]:
            summary = _load_json(mve_dir / "mve_summary.json")
            fitness = _load_json(mve_dir / "multiversal_fitness.json")
            wf = fitness.get("world_fitness") if isinstance(fitness.get("world_fitness"), list) else []
            regions = [str(r.get("region", "")).strip().upper() for r in wf if isinstance(r, dict)]
            drift = _load_optional_json(mve_dir / "mve_drift_report.json") or {}
            capture = _load_optional_json(mve_dir / "mve_capture_resistance_report.json") or {}
            return {
                "adapter_id": str(summary.get("adapter_id", "")).strip(),
                "mode": str(summary.get("mode", "")).strip(),
                "seed": int(summary.get("seed", 0)),
                "conflicts_count": int(summary.get("conflicts_count", 0)),
                "promotion_blocked": bool(summary.get("promotion_blocked", False)),
                "regions": regions,
                "region_counts": {k: int(sum(1 for r in regions if r == k)) for k in ("A", "B", "C")},
                "drift_terminal": bool(drift.get("terminal", False)),
                "capture_status": str(capture.get("status", "")).strip(),
            }

        # Baseline (before) and trained (after) MVE-1 runs.
        before_out = (validation_root / "mve1_before").resolve()
        after_out = (validation_root / "mve1_after").resolve()
        for out_dir, a in [(before_out, "BASELINE"), (after_out, aid)]:
            args = [
                sys.executable,
                "-m",
                "tools.eval.mve_runner",
                "--mode",
                "mve1",
                "--pack-manifest",
                str(pack),
                "--adapter-id",
                a,
                "--seed",
                str(int(seed)),
                "--law-bundle-hash-in-force",
                profile.law_bundle_hash,
                "--out-dir",
                str(out_dir),
            ]
            _rc, _out, _log = _run_cmd(
                repo_root=repo_root,
                run_dir=run_dir,
                name=("forge_mve_before" if a == "BASELINE" else "forge_mve_after"),
                cmd=args,
                env=env,
            )
            if int(_rc) != 0:
                raise FL3ValidationError("FAIL_CLOSED: mve_runner failed (unexpected)")
            mve_dir = (out_dir / "mve").resolve()
            if not (mve_dir / "mve_summary.json").exists():
                raise FL3ValidationError("FAIL_CLOSED: missing mve_summary.json after mve_runner (unexpected)")

        before_mve_dir = (before_out / "mve").resolve()
        after_mve_dir = (after_out / "mve").resolve()
        before_metrics = _mve_metrics(before_mve_dir)
        after_metrics = _mve_metrics(after_mve_dir)
        before_after = {
            "schema_id": "kt.operator.forge.before_after_metrics.unbound.v1",
            "before": before_metrics,
            "after": after_metrics,
            "delta": {
                "conflicts_count": int(after_metrics["conflicts_count"] - before_metrics["conflicts_count"]),
                "region_c_count": int(after_metrics["region_counts"]["C"] - before_metrics["region_counts"]["C"]),
                "promotion_blocked_changed": bool(after_metrics["promotion_blocked"]) != bool(before_metrics["promotion_blocked"]),
            },
        }

        # Temporal fitness memory gate (may return rc=2 on regression but still writes gate JSON).
        temporal_out_dir = (validation_root / "temporal").resolve()
        temporal_rc, _temporal_out, _temporal_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="forge_temporal_fitness_ledger",
            cmd=[
                sys.executable,
                "-m",
                "tools.eval.temporal_fitness_ledger",
                "--fitness-record",
                str(after_mve_dir / "multiversal_fitness.json"),
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

        gate_out_dir = (validation_root / "promotion_gate").resolve()
        gate_rc, _gate_out, _gate_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="forge_titan_promotion_gate",
            cmd=[
                sys.executable,
                "-m",
                "tools.eval.titan_promotion_gate",
                "--mve-dir",
                str(after_mve_dir),
                "--temporal-gate",
                str(temporal_gate_path),
                "--run-id",
                str(run_dir.name),
                "--out-dir",
                str(gate_out_dir),
                "--mode",
                "mve1",
            ],
            env=env,
        )
        if int(gate_rc) != 0:
            raise FL3ValidationError("FAIL_CLOSED: titan_promotion_gate failed (unexpected)")
        titan_gate_path = (gate_out_dir / "titan_promotion_gate.json").resolve()
        if not titan_gate_path.exists():
            raise FL3ValidationError("FAIL_CLOSED: missing titan_promotion_gate.json (unexpected)")

        admission_out_dir = (validation_root / "admission").resolve()
        admission_rc, _admission_out, _admission_log = _run_cmd(
            repo_root=repo_root,
            run_dir=run_dir,
            name="forge_mve_admission_gate",
            cmd=[
                sys.executable,
                "-m",
                "tools.eval.mve_admission_gate",
                "--mode",
                "mve1",
                "--mve-dir",
                str(after_mve_dir),
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

        admission_rec = _load_json(admission_record_path)
        admission_status = str(admission_rec.get("status", "")).strip() or "UNKNOWN"
        titan_gate = _load_json(titan_gate_path)
        promotion_blocked = bool(titan_gate.get("promotion_blocked", True))
        promotion_gate_status = {
            "status": "OK",
            "mode": "mve1",
            "mve_after_dir": after_mve_dir.as_posix(),
            "temporal_rc": int(temporal_rc),
            "gate_rc": int(gate_rc),
            "admission_rc": int(admission_rc),
            "admission_status": admission_status,
            "promotion_blocked": bool(promotion_blocked),
            "block_reason_codes": list(titan_gate.get("block_reason_codes", []) or []),
            "paths": {
                "temporal_gate_path": temporal_gate_path.as_posix(),
                "titan_gate_path": titan_gate_path.as_posix(),
                "admission_record_path": admission_record_path.as_posix(),
            },
        }

    _write_json_worm(path=forge_dir / "before_after_metrics.json", obj=before_after, label="forge/before_after_metrics.json")
    _write_json_worm(path=forge_dir / "promotion_gate.json", obj=promotion_gate_status, label="forge/promotion_gate.json")

    reports_dir = (run_dir / "reports").resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    forge_summary = {
        "schema_id": "kt.operator.forge_summary.unbound.v1",
        "adapter_id": aid,
        "seed": int(seed),
        "failure_source": src.as_posix(),
        "holdout_pack": pack.as_posix(),
        "training_status": training_status,
        "training_rc": int(train_rc),
        "promotion_gate": promotion_gate_status,
        "created_utc": _utc_now_iso_z(),
    }
    _write_json_worm(path=reports_dir / "forge_summary.json", obj=forge_summary, label="forge_summary.json")

    admission_ok = bool(promotion_gate_status.get("status") == "OK" and promotion_gate_status.get("admission_status") == "PASS")
    promotion_blocked = bool(promotion_gate_status.get("promotion_blocked", True))
    verdict_kind = "PASS" if (training_status == "PASS" and admission_ok and (not promotion_blocked)) else "BLOCKED"
    verdict = (
        f"KT_FORGE_{verdict_kind} cmd=forge profile={profile.name} allow_dirty={int(bool(allow_dirty))} "
        f"head={head} adapter_id={aid} seed={int(seed)} training_status={training_status} "
        f"admission_status={str(promotion_gate_status.get('admission_status','')).strip()} promotion_blocked={int(promotion_blocked)}"
    )

    # Bind forged dataset/config into run protocol datasets list.
    ds_entries = [
        {"relpath": "forge/train_config.json", "sha256": sha256_file(train_cfg_path)},
        {"relpath": "forge/train_data_manifest.json", "sha256": sha256_file(data_manifest_path)},
    ]
    _ = _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_FORGE_V1",
        lane_label="forge.v1",
        verdict_line=verdict,
        program_id="program.forge.hf_lora_or_stub",
        active_adapters=[
            {"adapter_id": aid, "adapter_hash": adapter_hash or profile.determinism_expected_root_hash},
        ],
        datasets=ds_entries,
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts"), ("forge", "forge")],
        run_protocol_notes=f"Forge lane (engine={engine}) failure_source={src.as_posix()} holdout_pack={pack.as_posix()}",
        delivery_manifest_extras={"forge": {"adapter_id": aid, "seed": int(seed), "training_status": training_status, "promotion_gate": promotion_gate_status}},
    )

    print(verdict)
    return 0


def cmd_hat_demo(*, repo_root: Path, profile: V1Profile, run_dir: Path, allow_dirty: bool) -> int:
    env = _base_env(repo_root=repo_root)
    head = _git(repo_root=repo_root, args=["rev-parse", "HEAD"])

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
    _ = _emit_delivery_bundle(
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_HAT_DEMO_V1",
        lane_label="hat_demo.v1",
        verdict_line=verdict,
        program_id="program.hat_demo",
        core_copy_dirs=[("hat_demo", "hat_demo"), ("transcripts", "transcripts")],
        run_protocol_notes=f"Hat demo lane run_id={run_id}",
        delivery_manifest_extras={
            "hat_demo": {
                "router_run_report_id": str(report.get("router_run_report_id", "")).strip(),
                "router_policy_id": str(report.get("router_policy_id", "")).strip(),
                "router_demo_suite_id": str(report.get("router_demo_suite_id", "")).strip(),
                "run_id": run_id,
            }
        },
    )
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
    argv = _normalize_argv_for_safe_run(argv)
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

    ap_ra = sub.add_parser("red-assault", help="Run red assault lane and emit failure taxonomy + delivery bundle (WORM).")
    _add_post_global_options(ap_ra)
    ap_ra.add_argument("--pack-id", required=True, choices=["fl3_factory_v1", "serious_v1"], help="Adversarial pack id.")
    ap_ra.add_argument(
        "--pressure-level", required=True, choices=["low", "med", "high", "l0", "l1", "l2", "l3", "l4"], help="Pressure intensity."
    )
    ap_ra.add_argument("--sample-count", required=True, type=int, help="Sample count (int).")
    ap_ra.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")
    ap_ra.add_argument(
        "--attack-mix",
        action="append",
        default=[],
        choices=["prompt_injection", "policy_jailbreak", "format_break", "hallucination_traps", "context_overload"],
        help="Attack mix tags (recorded in reports; repeatable).",
    )
    ap_ra.add_argument("--overlay-id", action="append", default=[], help="Optional overlay id(s) (recorded; serious_v1 uses them for scope labeling).")
    ap_ra.add_argument("--probe-pack-ref", default="", help="(serious_v1) Probe pack descriptor path (hash-ref-only).")
    ap_ra.add_argument("--probe-payloads", default="", help="(serious_v1) Out-of-repo JSONL payloads file to execute probes (hash-ref-only).")
    ap_ra.add_argument("--probe-engine", default="stub", choices=["stub", "stub_unsafe", "hf_local"], help="(serious_v1) Probe engine.")
    ap_ra.add_argument("--base-model-dir", default="", help="(serious_v1) Offline base model dir (required for hf_local).")

    ap_cg = sub.add_parser(
        "continuous-gov", help="Run continuous governance diff against a baseline and emit drift/regression artifacts (WORM)."
    )
    _add_post_global_options(ap_cg)
    ap_cg.add_argument("--program", default="v1", choices=["v1", "serious_v1"], help="Continuous governance program (default: v1).")
    ap_cg.add_argument("--baseline-run", required=True, help="Baseline run directory under exports/_runs.")
    ap_cg.add_argument("--window", default="", help="N recent runs or comma-separated run dirs (optional).")
    ap_cg.add_argument("--thresholds", default="", help="Optional JSON thresholds object (string).")

    ap_ov = sub.add_parser("overlay-apply", help="Resolve overlay packs in strict mode and emit overlay effect reports (WORM).")
    _add_post_global_options(ap_ov)
    ap_ov.add_argument("--overlay-id", action="append", required=True, help="Overlay id (repeatable).")
    ap_ov.add_argument("--target-lane", required=True, choices=["certify", "red_assault", "continuous_gov", "forge"])
    ap_ov.add_argument("--strict", action="store_true", help="Explicit strict mode (default).")
    ap_ov.add_argument("--no-strict", action="store_true", help="Disable strict mode (default: strict).")

    ap_forge = sub.add_parser("forge", help="Adapter forge lane (train -> validate -> promote/block -> deliver).")
    _add_post_global_options(ap_forge)
    ap_forge.add_argument("--failure-source", required=True, help="Failure source path (file/dir).")
    ap_forge.add_argument("--holdout-pack", required=True, help="Holdout pack manifest path (MVE pack_manifest.json).")
    ap_forge.add_argument("--train-config", required=True, help="Training config JSON string or path to JSON file.")
    ap_forge.add_argument("--adapter-id", required=True, help="Adapter id (string).")
    ap_forge.add_argument("--seed", type=int, default=0, help="Deterministic seed (default: 0).")
    ap_forge.add_argument("--engine", default="stub", choices=["stub", "hf_lora"], help="Training engine (default: stub).")
    ap_forge.add_argument("--base-model-dir", default="", help="Local base model dir (required for hf_lora engine).")
    ap_forge.add_argument("--enable-real-engine", action="store_true", help="Allow non-stub engines (default: disabled).")

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

    ap_safe = sub.add_parser("safe-run", help="Titanium safe-run production entrypoint.")
    _add_post_global_options(ap_safe)
    ap_safe.add_argument("--assurance-mode", required=True, choices=["practice", "production"])
    ap_safe.add_argument("--program", required=True)
    ap_safe.add_argument("--config", default="{}")

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
        if args.cmd != "safe-run":
            _maybe_assert_clean_worktree(repo_root=repo_root, allow_dirty=allow_dirty)
        if args.cmd == "status":
            return cmd_status(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
        if args.cmd == "certify":
            if str(args.lane) == "ci_sim":
                return cmd_certify_ci_sim(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
            return cmd_certify_canonical_hmac(repo_root=repo_root, profile=profile, run_dir=run_dir, allow_dirty=allow_dirty)
        if args.cmd == "red-assault":
            return cmd_red_assault(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                pack_id=str(args.pack_id),
                pressure_level=str(args.pressure_level),
                attack_mix=list(getattr(args, "attack_mix", []) or []),
                sample_count=int(args.sample_count),
                seed=int(args.seed),
                overlay_ids=list(getattr(args, "overlay_id", []) or []),
                probe_pack_ref=str(getattr(args, "probe_pack_ref", "") or ""),
                probe_payloads=str(getattr(args, "probe_payloads", "") or ""),
                probe_engine=str(getattr(args, "probe_engine", "stub") or "stub"),
                base_model_dir=str(getattr(args, "base_model_dir", "") or ""),
                allow_dirty=allow_dirty,
            )
        if args.cmd == "continuous-gov":
            return cmd_continuous_gov(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                program=str(getattr(args, "program", "v1")),
                baseline_run=str(args.baseline_run),
                window=str(args.window),
                thresholds_json=str(args.thresholds),
                allow_dirty=allow_dirty,
            )
        if args.cmd == "overlay-apply":
            if bool(getattr(args, "strict", False)) and bool(getattr(args, "no_strict", False)):
                raise FL3ValidationError("FAIL_CLOSED: --strict and --no-strict are mutually exclusive")
            return cmd_overlay_apply(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                overlay_ids=list(getattr(args, "overlay_id", []) or []),
                target_lane=str(args.target_lane),
                strict=not bool(getattr(args, "no_strict", False)),
                allow_dirty=allow_dirty,
            )
        if args.cmd == "forge":
            return cmd_forge(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                failure_source=str(args.failure_source),
                holdout_pack=str(args.holdout_pack),
                train_config=str(args.train_config),
                adapter_id=str(args.adapter_id),
                seed=int(args.seed),
                engine=str(args.engine),
                base_model_dir=str(args.base_model_dir),
                enable_real_engine=bool(args.enable_real_engine),
                allow_dirty=allow_dirty,
            )
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
        if args.cmd == "safe-run":
            return cmd_safe_run(
                repo_root=repo_root,
                profile=profile,
                run_dir=run_dir,
                assurance_mode=str(args.assurance_mode),
                program_id=str(args.program),
                config=_load_config_arg(repo_root, str(args.config)),
                allow_dirty=allow_dirty,
            )
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
