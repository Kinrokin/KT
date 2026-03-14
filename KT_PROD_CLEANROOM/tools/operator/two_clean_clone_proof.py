from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import (
    load_json,
    make_run_dir,
    repo_root,
    utc_now_iso_z,
    write_failure_artifacts,
    write_json_stable,
    write_json_worm,
)


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WS8_REPRESENTATIVE_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
DEFAULT_WS8_LANE_SPECS: List[Dict[str, Any]] = [
    {
        "proof_id": "certify",
        "program_id": "program.certify.canonical_hmac",
        "run_label": "WS8_certify_canonical_hmac",
        "compare_relpath": "",
        "kt_cli_args": ["--profile", "v1", "certify", "--lane", "canonical_hmac"],
    },
    {
        "proof_id": "hat_demo",
        "program_id": "program.hat_demo",
        "run_label": "WS8_safe_run_hat_demo",
        "compare_relpath": "program_run",
        "kt_cli_args": ["--safe-run", "--profile", "v1", "--assurance-mode", "practice", "--program", "program.hat_demo", "--config", "{}"],
    },
    {
        "proof_id": "red_assault_serious_v1",
        "program_id": "program.red_assault.serious_v1",
        "run_label": "WS8_red_assault_serious_v1",
        "compare_relpath": "",
        "kt_cli_args": [
            "--profile",
            "v1",
            "red-assault",
            "--pack-id",
            "serious_v1",
            "--pressure-level",
            "low",
            "--sample-count",
            "12",
            "--seed",
            "1337",
        ],
    },
]


def _sha_obj(obj: Dict[str, Any]) -> str:
    return sha256_hex(canonicalize_bytes(obj))


def _normalized_pack_manifest(pack_manifest: Dict[str, Any]) -> Dict[str, Any]:
    files = []
    for row in pack_manifest.get("files", []):
        if not isinstance(row, dict):
            continue
        files.append(
            {
                "path": str(row.get("path", "")).replace("\\", "/"),
                "redacted": bool(row.get("redacted")),
            }
        )
    files.sort(key=lambda row: row["path"])
    return {
        "files": files,
        "redaction_rules_version": str(pack_manifest.get("redaction_rules_version", "")).strip(),
        "schema_id": str(pack_manifest.get("schema_id", "")).strip(),
        "schema_version_hash": str(pack_manifest.get("schema_version_hash", "")).strip(),
    }


def _normalized_delivery_manifest(delivery_manifest: Dict[str, Any]) -> Dict[str, Any]:
    keep: Dict[str, Any] = {
        "schema_id": str(delivery_manifest.get("schema_id", "")).strip(),
        "profile": str(delivery_manifest.get("profile", "")).strip(),
        "lane": str(delivery_manifest.get("lane", "")).strip(),
        "lane_id": str(delivery_manifest.get("lane_id", "")).strip(),
        "program_id": str(delivery_manifest.get("program_id", "")).strip(),
        "head": str(delivery_manifest.get("head", "")).strip(),
        "pins": delivery_manifest.get("pins", {}),
        "safe_run_enforced": bool(delivery_manifest.get("safe_run_enforced")),
        "replay_command": str(delivery_manifest.get("replay_command", "")).strip(),
    }
    sweep = delivery_manifest.get("sweep")
    if isinstance(sweep, dict):
        keep["sweep"] = {"sweep_id": str(sweep.get("sweep_id", "")).strip()}
    for extra_key in ("hat_demo", "red_assault", "continuous_gov", "forge", "overlay_apply"):
        extra_value = delivery_manifest.get(extra_key)
        if not isinstance(extra_value, dict):
            continue
        if extra_key == "hat_demo":
            keep[extra_key] = {
                "router_demo_suite_id": str(extra_value.get("router_demo_suite_id", "")).strip(),
                "router_policy_id": str(extra_value.get("router_policy_id", "")).strip(),
            }
            continue
        keep[extra_key] = extra_value
    return keep


def _normalized_constitutional_snapshot(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": str(obj.get("schema_id", "")).strip(),
        "program_id": str(obj.get("program_id", "")).strip(),
        "lane_id": str(obj.get("lane_id", "")).strip(),
        "lane_label": str(obj.get("lane_label", "")).strip(),
        "head": str(obj.get("head", "")).strip(),
        "constitution_epoch": int(obj.get("constitution_epoch", 0)),
        "governance_manifest_sha256": str(obj.get("governance_manifest_sha256", "")).strip(),
    }


def _normalized_worm_manifest(obj: Dict[str, Any]) -> Dict[str, Any]:
    artifacts = []
    for row in obj.get("artifacts", []):
        if not isinstance(row, dict):
            continue
        artifacts.append({"path": str(row.get("path", "")).replace("\\", "/")})
    artifacts.sort(key=lambda row: row["path"])
    return {
        "schema_id": str(obj.get("schema_id", "")).strip(),
        "program_id": str(obj.get("program_id", "")).strip(),
        "artifacts": artifacts,
    }


def _normalized_operator_fingerprint(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "machine_fingerprint": str(obj.get("machine_fingerprint", "")).strip(),
        "mve_environment_fingerprint": str(obj.get("mve_environment_fingerprint", "")).strip(),
        "operator_id": str(obj.get("operator_id", "")).strip(),
    }


def _normalized_operator_intent(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "operator_id": str(obj.get("operator_id", "")).strip(),
        "operator_intent_class": str(obj.get("operator_intent_class", "")).strip(),
        "program_id": str(obj.get("program_id", "")).strip(),
        "assurance_mode": str(obj.get("assurance_mode", "")).strip(),
        "constitution_epoch": int(obj.get("constitution_epoch", 0)),
    }


def _normalized_replay_receipt(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": str(obj.get("schema_id", "")).strip(),
        "schema_version_hash": str(obj.get("schema_version_hash", "")).strip(),
        "lane_id": str(obj.get("lane_id", "")).strip(),
        "replay_command": str(obj.get("replay_command", "")).strip(),
        "replay_sh_sha256": str(obj.get("replay_sh_sha256", "")).strip(),
        "replay_ps1_sha256": str(obj.get("replay_ps1_sha256", "")).strip(),
        "replay_script_hash": str(obj.get("replay_script_hash", "")).strip(),
    }


def _normalized_secret_scan(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": str(obj.get("schema_id", "")).strip(),
        "status": str(obj.get("status", "")).strip(),
    }


def _normalized_lint(obj: Dict[str, Any]) -> Dict[str, Any]:
    checks = obj.get("checks", {})
    return {
        "status": str(obj.get("status", "")).strip(),
        "checks": checks if isinstance(checks, dict) else {},
    }


def _load_run_surface(run_dir: Path) -> Dict[str, Any]:
    run_dir = run_dir.resolve()
    delivery_manifest = load_json(run_dir / "delivery" / "delivery_manifest.json")
    constitutional = load_json(run_dir / "evidence" / "constitutional_snapshot.json")
    worm_manifest = load_json(run_dir / "evidence" / "worm_manifest.json")
    bindingloop = load_json(run_dir / "reports" / "bindingloop_check.json")
    replay_receipt = load_json(run_dir / "evidence" / "replay_receipt.json")
    operator_fp = load_json(run_dir / "reports" / "operator_fingerprint.json")
    operator_intent = load_json(run_dir / "reports" / "operator_intent.json")
    secret_scan = load_json(run_dir / "evidence" / "secret_scan_report.json")
    lint_report = load_json(run_dir / "delivery" / "delivery_lint_report.json")

    pack_dir_rel = str(delivery_manifest.get("delivery_dir", "")).strip()
    if not pack_dir_rel:
        raise RuntimeError(f"FAIL_CLOSED: delivery_dir missing in {run_dir.as_posix()}")
    pack_dir = (run_dir / pack_dir_rel).resolve()
    pack_manifest = load_json(pack_dir / "delivery_pack_manifest.json")

    normalized_delivery = _normalized_delivery_manifest(delivery_manifest)
    normalized_constitutional = _normalized_constitutional_snapshot(constitutional)
    normalized_worm = _normalized_worm_manifest(worm_manifest)
    normalized_operator_fp = _normalized_operator_fingerprint(operator_fp)
    normalized_operator_intent = _normalized_operator_intent(operator_intent)
    normalized_replay = _normalized_replay_receipt(replay_receipt)
    normalized_secret_scan = _normalized_secret_scan(secret_scan)
    normalized_lint = _normalized_lint(lint_report)
    normalized_pack_manifest = _normalized_pack_manifest(pack_manifest)

    delivery_root_hash = _sha_obj(
        {
            "delivery_manifest": normalized_delivery,
            "delivery_pack_manifest": normalized_pack_manifest,
        }
    )
    bindingloop_hash = _sha_obj(
        {
            "delivery_manifest": normalized_delivery,
            "constitutional_snapshot": normalized_constitutional,
            "worm_manifest": normalized_worm,
            "bindingloop_status": str(bindingloop.get("status", "")).strip(),
        }
    )
    replay_receipt_hash = str(normalized_replay.get("replay_receipt_id", "")).strip() or _sha_obj(normalized_replay)
    evidence_core_root = _sha_obj(
        {
            "operator_fingerprint": normalized_operator_fp,
            "operator_intent": normalized_operator_intent,
            "constitutional_snapshot": normalized_constitutional,
            "delivery_root_hash": delivery_root_hash,
            "bindingloop_check_hash": bindingloop_hash,
            "replay_receipt_hash": replay_receipt_hash,
            "delivery_lint": normalized_lint,
            "secret_scan": normalized_secret_scan,
        }
    )
    return {
        "delivery_root_hash": delivery_root_hash,
        "bindingloop_check_hash": bindingloop_hash,
        "evidence_core_merkle_root_sha256": evidence_core_root,
        "replay_receipt_hash": replay_receipt_hash,
        "governance_manifest_sha256": str(normalized_constitutional.get("governance_manifest_sha256", "")).strip(),
        "constitution_epoch": int(normalized_constitutional.get("constitution_epoch", 0)),
        "mve_environment_fingerprint": str(normalized_operator_fp.get("mve_environment_fingerprint", "")).strip(),
        "normalized_inputs": {
            "delivery_manifest": normalized_delivery,
            "delivery_pack_manifest": normalized_pack_manifest,
            "constitutional_snapshot": normalized_constitutional,
            "worm_manifest": normalized_worm,
            "operator_fingerprint": normalized_operator_fp,
            "operator_intent": normalized_operator_intent,
            "replay_receipt": normalized_replay,
            "secret_scan": normalized_secret_scan,
            "delivery_lint": normalized_lint,
        },
    }


def compare_runs(run_a: Path, run_b: Path) -> Dict[str, object]:
    facts_a = _load_run_surface(run_a)
    facts_b = _load_run_surface(run_b)
    compare_keys = [
        "delivery_root_hash",
        "bindingloop_check_hash",
        "evidence_core_merkle_root_sha256",
        "replay_receipt_hash",
        "governance_manifest_sha256",
        "constitution_epoch",
        "mve_environment_fingerprint",
    ]
    comparisons = []
    violations = []
    for key in compare_keys:
        a_value = facts_a.get(key)
        b_value = facts_b.get(key)
        status = "PASS" if a_value == b_value else "FAIL"
        if status != "PASS":
            violations.append(key)
        comparisons.append({"a_value": a_value, "b_value": b_value, "key": key, "status": status})
    return {
        "compare_keys": compare_keys,
        "comparisons": comparisons,
        "run_a": str(run_a),
        "run_b": str(run_b),
        "schema_id": "kt.operator.twocleanclone_proof.v1",
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
    }


def _relpath(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:  # noqa: BLE001
        return path.resolve().as_posix()


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _py_env_for_clone(clone_root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(clone_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"),
            str(clone_root / "KT_PROD_CLEANROOM"),
        ]
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    env.setdefault("KT_SEAL_MODE", "1")
    return env


def _clone_repo_at_head(*, source_root: Path, head_sha: str, clone_label: str) -> Dict[str, Any]:
    clone_root = Path(tempfile.mkdtemp(prefix=f"KT_WS8_{clone_label}_{head_sha[:7]}_")).resolve()
    subprocess.run(["git", "clone", str(source_root), str(clone_root)], check=True, text=True)
    subprocess.run(["git", "-C", str(clone_root), "checkout", head_sha], check=True, text=True)
    observed_head = _git(clone_root, "rev-parse", "HEAD")
    clean = not bool(_git(clone_root, "status", "--porcelain=v1").strip())
    return {
        "clone_root": clone_root,
        "clone_path": clone_root.as_posix(),
        "head": observed_head,
        "clean": clean,
        "clone_label": clone_label,
    }


def _run_lane_in_clone(*, clone_root: Path, clone_label: str, head_sha: str, lane_spec: Dict[str, Any]) -> Dict[str, str]:
    run_root = (
        clone_root
        / "KT_PROD_CLEANROOM"
        / "exports"
        / "_runs"
        / "KT_OPERATOR"
        / f"{lane_spec['run_label']}_{head_sha[:7]}_{clone_label}"
    ).resolve()
    cmd = [sys.executable, "-m", "tools.operator.kt_cli", "--run-root", str(run_root), *[str(item) for item in lane_spec["kt_cli_args"]]]
    subprocess.run(cmd, cwd=str(clone_root), env=_py_env_for_clone(clone_root), check=True, text=True)
    compare_root = run_root / str(lane_spec.get("compare_relpath", "")).strip() if str(lane_spec.get("compare_relpath", "")).strip() else run_root
    return {
        "run_root": run_root.as_posix(),
        "compare_root": compare_root.resolve().as_posix(),
        "proof_id": str(lane_spec["proof_id"]).strip(),
        "program_id": str(lane_spec["program_id"]).strip(),
    }


def _write_individual_proof_run(
    *,
    repo_root_path: Path,
    head_sha: str,
    proof_id: str,
    program_id: str,
    run_a: Path,
    run_b: Path,
    report: Dict[str, Any],
) -> str:
    proof_run_dir = make_run_dir(
        cmd_name="twocleanclone-proof",
        requested_run_root=f"KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS8_twocleanclone_{proof_id}_{head_sha[:7]}",
    )
    write_json_worm(proof_run_dir / "reports" / "twocleanclone_proof.json", report, label="twocleanclone_proof.json")
    write_json_worm(
        proof_run_dir / "reports" / "proofrunbundle_index.json",
        {"programs": program_id, "run_a": run_a.as_posix(), "run_b": run_b.as_posix()},
        label="proofrunbundle_index.json",
    )
    summary = "\n".join(str(x) for x in report.get("violations", [])) + ("\n" if report.get("violations") else "PASS\n")
    (proof_run_dir / "reports" / "twocleanclone_diff_summary.txt").write_text(summary, encoding="utf-8")
    return _relpath(repo_root_path, proof_run_dir)


def build_twocleanclone_bundle_payload(
    *,
    head_sha: str,
    generated_utc: str,
    proofs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    representative = next((row for row in proofs if str(row.get("proof_id", "")).strip() == "red_assault_serious_v1"), None)
    representative_pass = bool(representative) and str((representative.get("report") or {}).get("status", "")).strip() == "PASS"
    overall_status = "PASS" if proofs and all(str((row.get("report") or {}).get("status", "")).strip() == "PASS" for row in proofs) else "FAIL"
    return {
        "schema_id": "kt.sovereign.twocleanclone_bundle.v1",
        "generated_utc": generated_utc,
        "status": overall_status,
        "validated_head_sha": head_sha,
        "candidate_worktree_execution_sealing_claimed": False,
        "published_head_authority_claimed": False,
        "minimum_scope_only": False,
        "proof_scope": "clean_clone_reproducibility_representative_authority_lane_same_mve_only",
        "representative_authority_lane_program_id": "program.red_assault.serious_v1",
        "representative_authority_lane_proof_id": "red_assault_serious_v1",
        "representative_authority_lane_proven": representative_pass,
        "cross_environment_controlled_variation_complete": False,
        "cross_environment_controlled_variation_status": "NOT_RUN",
        "proofs": list(proofs),
    }


def build_proofrunbundle_index_payload(
    *,
    head_sha: str,
    generated_utc: str,
    proofs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    bundles = []
    for row in proofs:
        report = row.get("report") if isinstance(row.get("report"), dict) else {}
        bundles.append(
            {
                "proof_id": str(row.get("proof_id", "")).strip(),
                "program_id": str(row.get("program_id", "")).strip(),
                "run_dir": str(row.get("run_dir", "")).strip(),
                "source_runs": [str(report.get("run_a", "")).strip(), str(report.get("run_b", "")).strip()],
                "validated_head_sha": str(row.get("validated_head_sha", "")).strip(),
            }
        )
    return {
        "schema_id": "kt.sovereign.proofrunbundle_index.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if bundles else "FAIL",
        "validated_head_sha": head_sha,
        "minimum_scope_only": False,
        "representative_authority_lane_program_id": "program.red_assault.serious_v1",
        "cross_environment_controlled_variation_complete": False,
        "bundles": bundles,
    }


def build_representative_authority_lane_receipt(
    *,
    head_sha: str,
    generated_utc: str,
    bundle: Dict[str, Any],
) -> Dict[str, Any]:
    representative_proven = bool(bundle.get("representative_authority_lane_proven"))
    return {
        "schema_id": "kt.operator.representative_authority_lane_reproducibility_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if representative_proven and str(bundle.get("status", "")).strip() == "PASS" else "HOLD",
        "validated_head_sha": head_sha,
        "twocleanclone_bundle_ref": f"{DEFAULT_REPORT_ROOT_REL}/twocleanclone_proof.json",
        "proofrunbundle_index_ref": f"{DEFAULT_REPORT_ROOT_REL}/proofrunbundle_index.json",
        "representative_authority_lane_program_id": "program.red_assault.serious_v1",
        "representative_authority_lane_proof_id": "red_assault_serious_v1",
        "representative_authority_lane_proven": representative_proven,
        "minimum_scope_only": False,
        "reproducibility_band": "REPRESENTATIVE_AUTHORITY_LANE_SAME_MVE_ONLY",
        "cross_environment_controlled_variation_complete": False,
        "cross_environment_controlled_variation_status": "NOT_RUN",
        "candidate_worktree_execution_sealing_claimed": False,
        "published_head_authority_claimed": False,
        "h1_allowed": False,
        "notes": [
            "This receipt proves current-head clean-clone reproducibility for certify, safe-run hat_demo, and the representative authority lane program.red_assault.serious_v1.",
            "This receipt does not claim published-head authority.",
            "This receipt does not claim cross-environment controlled variation; it is same-MVE only until a second environment is proven.",
        ],
    }


def build_twocleanclone_diff_summary(*, head_sha: str, proofs: Sequence[Dict[str, Any]]) -> str:
    lines = []
    label_map = {
        "certify": "certify",
        "hat_demo": "hat-demo",
        "red_assault_serious_v1": "red-assault serious_v1",
    }
    for row in proofs:
        proof_id = str(row.get("proof_id", "")).strip()
        report = row.get("report") if isinstance(row.get("report"), dict) else {}
        clone_provenance = row.get("clone_provenance") if isinstance(row.get("clone_provenance"), dict) else {}
        clone_a = (clone_provenance.get("clone_a") or {}).get("path", "")
        clone_b = (clone_provenance.get("clone_b") or {}).get("path", "")
        lines.append(f"WS8 {label_map.get(proof_id, proof_id)} proof: {str(report.get('status', '')).strip() or 'UNKNOWN'}")
        lines.append(f"WS8 {label_map.get(proof_id, proof_id)} clones: {clone_a} and {clone_b}")
    compare_keys = list((proofs[0].get("report") or {}).get("compare_keys", [])) if proofs else []
    lines.append(f"Validated head: {head_sha}")
    lines.append(f"Compared keys: {', '.join(str(item) for item in compare_keys)}")
    lines.append("Representative authority lane: program.red_assault.serious_v1")
    lines.append("Cross-environment controlled variation: NOT_RUN")
    lines.append("Scope: clean-clone reproducibility with representative authority lane; same MVE only; not published-head authority")
    return "\n".join(lines) + "\n"


def run_ws8_current_head_bundle(*, root: Path) -> Dict[str, Any]:
    head_sha = _git(root, "rev-parse", "HEAD")
    generated_utc = utc_now_iso_z()
    clone_a = _clone_repo_at_head(source_root=root, head_sha=head_sha, clone_label="A")
    clone_b = _clone_repo_at_head(source_root=root, head_sha=head_sha, clone_label="B")
    proofs: List[Dict[str, Any]] = []

    for lane_spec in DEFAULT_WS8_LANE_SPECS:
        run_a = _run_lane_in_clone(clone_root=Path(str(clone_a["clone_root"])), clone_label="clean_a", head_sha=head_sha, lane_spec=lane_spec)
        run_b = _run_lane_in_clone(clone_root=Path(str(clone_b["clone_root"])), clone_label="clean_b", head_sha=head_sha, lane_spec=lane_spec)
        report = compare_runs(Path(run_a["compare_root"]), Path(run_b["compare_root"]))
        proof_run_dir_rel = _write_individual_proof_run(
            repo_root_path=root,
            head_sha=head_sha,
            proof_id=str(lane_spec["proof_id"]).strip(),
            program_id=str(lane_spec["program_id"]).strip(),
            run_a=Path(run_a["compare_root"]),
            run_b=Path(run_b["compare_root"]),
            report=report,
        )
        proofs.append(
            {
                "proof_id": str(lane_spec["proof_id"]).strip(),
                "program_id": str(lane_spec["program_id"]).strip(),
                "validated_head_sha": head_sha,
                "run_dir": proof_run_dir_rel,
                "clone_provenance": {
                    "clone_a": {
                        "clean": bool(clone_a["clean"]),
                        "head": str(clone_a["head"]).strip(),
                        "path": str(clone_a["clone_path"]).strip(),
                    },
                    "clone_b": {
                        "clean": bool(clone_b["clean"]),
                        "head": str(clone_b["head"]).strip(),
                        "path": str(clone_b["clone_path"]).strip(),
                    },
                },
                "report": report,
            }
        )

    bundle = build_twocleanclone_bundle_payload(head_sha=head_sha, generated_utc=generated_utc, proofs=proofs)
    proofrunbundle_index = build_proofrunbundle_index_payload(head_sha=head_sha, generated_utc=generated_utc, proofs=proofs)
    receipt = build_representative_authority_lane_receipt(head_sha=head_sha, generated_utc=generated_utc, bundle=bundle)
    diff_summary = build_twocleanclone_diff_summary(head_sha=head_sha, proofs=proofs)

    write_json_stable(root / DEFAULT_REPORT_ROOT_REL / "twocleanclone_proof.json", bundle)
    write_json_stable(root / DEFAULT_REPORT_ROOT_REL / "proofrunbundle_index.json", proofrunbundle_index)
    (root / DEFAULT_REPORT_ROOT_REL / "twocleanclone_diff_summary.txt").write_text(diff_summary, encoding="utf-8")
    write_json_stable(root / WS8_REPRESENTATIVE_RECEIPT_REL, receipt)

    return {
        "bundle": bundle,
        "proofrunbundle_index": proofrunbundle_index,
        "receipt": receipt,
        "diff_summary": diff_summary,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Compare two clean-clone runs.")
    ap.add_argument("--run-a", default="")
    ap.add_argument("--run-b", default="")
    ap.add_argument("--programs", default="")
    ap.add_argument("--output", default="")
    ap.add_argument("--bundle-current-head", action="store_true", help="Clone the current repo twice, run the WS8 lane set, and emit the tracked bundle reports.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        if bool(args.bundle_current_head):
            result = run_ws8_current_head_bundle(root=repo_root())
            receipt = result["receipt"]
            print(
                json.dumps(
                    {
                        "status": receipt["status"],
                        "validated_head_sha": receipt["validated_head_sha"],
                        "representative_authority_lane_proven": receipt["representative_authority_lane_proven"],
                        "cross_environment_controlled_variation_complete": receipt["cross_environment_controlled_variation_complete"],
                    },
                    sort_keys=True,
                    ensure_ascii=True,
                )
            )
            return 0 if receipt["status"] == "PASS" else 2

        if not str(args.run_a).strip() or not str(args.run_b).strip():
            raise RuntimeError("FAIL_CLOSED: --run-a and --run-b are required unless --bundle-current-head is used")

        run_dir = make_run_dir(cmd_name="twocleanclone-proof", requested_run_root=str(args.output))
        report = compare_runs(Path(args.run_a), Path(args.run_b))
        write_json_worm(run_dir / "reports" / "twocleanclone_proof.json", report, label="twocleanclone_proof.json")
        write_json_worm(
            run_dir / "reports" / "proofrunbundle_index.json",
            {"programs": str(args.programs), "run_a": str(args.run_a), "run_b": str(args.run_b)},
            label="proofrunbundle_index.json",
        )
        summary = "\n".join(str(x) for x in report.get("violations", [])) + ("\n" if report.get("violations") else "PASS\n")
        (run_dir / "reports" / "twocleanclone_diff_summary.txt").write_text(summary, encoding="utf-8")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.proof.twocleanclone",
                failure_name="REPLAY_NONDETERMINISTIC",
                message="; ".join(str(x) for x in report.get("violations", [])),
                next_actions=["Rerun both programs from clean clones and compare the normalized proof keys emitted in reports/twocleanclone_proof.json."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        run_dir = make_run_dir(cmd_name="twocleanclone-proof", requested_run_root=str(args.output))
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.proof.twocleanclone",
            failure_name="REPLAY_NONDETERMINISTIC",
            message=str(exc),
            next_actions=["Provide two run directories with the required Titanium proof artifacts."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
