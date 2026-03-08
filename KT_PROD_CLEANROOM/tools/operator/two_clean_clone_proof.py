from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import load_json, make_run_dir, write_failure_artifacts, write_json_worm


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


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Compare two clean-clone runs.")
    ap.add_argument("--run-a", required=True)
    ap.add_argument("--run-b", required=True)
    ap.add_argument("--programs", default="")
    ap.add_argument("--output", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="twocleanclone-proof", requested_run_root=str(args.output))
    try:
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
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.proof.twocleanclone",
            failure_name="REPLAY_NONDETERMINISTIC",
            message=str(exc),
            next_actions=["Provide two run directories with the required Titanium proof artifacts."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
