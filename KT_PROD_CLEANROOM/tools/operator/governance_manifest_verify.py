from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.hashpin import _manifest_path, _verify_hmac_sig, compute_all_targets
from tools.operator.titanium_common import canonical_file_sha256, load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm


def _verify_manifest(manifest_path: Path) -> Dict[str, Any]:
    root = repo_root()
    manifest = load_json(manifest_path)
    computed = compute_all_targets(root)
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []
    required_fields = {
        "packet_bundle_sha256": computed["packet_bundle"]["sha256"],
        "authority_os_sha256": computed["authority_os"]["sha256"],
        "titanium_work_order_sha256": computed["titanium_work_order"]["sha256"],
        "sku_registry_sha256": computed["sku_registry"]["sha256"],
        "ci_gate_definitions_sha256": computed["ci_gate_definitions"]["sha256"],
    }
    for field, expected in required_fields.items():
        actual = str(manifest.get(field, "")).strip()
        status = "PASS" if actual == expected else "FAIL"
        checks.append({"actual": actual, "expected": expected, "field": field, "status": status})
        if status != "PASS":
            failures.append(f"{field}:mismatch")

    if not isinstance(manifest.get("constitution_epoch"), int) or int(manifest.get("constitution_epoch", 0)) <= 0:
        failures.append("constitution_epoch:invalid")

    signatures = manifest.get("signatures")
    if not isinstance(signatures, list):
        failures.append("signatures:missing")
        signatures = []
    manifest_sha = canonical_file_sha256(manifest_path)
    signature_checks: List[Dict[str, Any]] = []
    for signer in ("OP1", "OP2"):
        row = next((x for x in signatures if isinstance(x, dict) and str(x.get("signer", "")).strip() == signer), None)
        if not isinstance(row, dict):
            failures.append(f"{signer}:missing")
            continue
        sig_path = (root / str(row.get("path", ""))).resolve()
        if not sig_path.exists():
            failures.append(f"{signer}:sig_missing")
            signature_checks.append({"signer": signer, "status": "FAIL"})
            continue
        signature_checks.append(_verify_hmac_sig(manifest_sha256=manifest_sha, signer=signer, sig_file=sig_path))

    return {
        "checks": checks,
        "manifest_path": manifest_path.as_posix(),
        "manifest_sha256": manifest_sha,
        "schema_id": "kt.operator.governance_manifest_verification.v1",
        "signature_checks": signature_checks,
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
        "env_keys_present": {
            "KT_HMAC_KEY_SIGNER_A": bool(os.environ.get("KT_HMAC_KEY_SIGNER_A")),
            "KT_HMAC_KEY_SIGNER_B": bool(os.environ.get("KT_HMAC_KEY_SIGNER_B")),
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify governance manifest and OP1/OP2 detached HMAC signatures.")
    ap.add_argument("--manifest", default="")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="governance-manifest-verify", requested_run_root=str(args.run_root))
    try:
        manifest_path = Path(str(args.manifest)).expanduser() if str(args.manifest).strip() else _manifest_path(repo_root())
        if not manifest_path.is_absolute():
            manifest_path = (repo_root() / manifest_path).resolve()
        report = _verify_manifest(manifest_path)
        write_json_worm(run_dir / "reports" / "governance_manifest_verification.json", report, label="governance_manifest_verification.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.governance.verify_manifest",
                failure_name="GOV_MANIFEST_INVALID",
                message="; ".join(report.get("failures", [])),
                next_actions=[
                    "Pin the governance manifest fields using tools.operator.hashpin.",
                    "Create OP1/OP2 detached HMAC signature files.",
                    "Rerun governance_manifest_verify.",
                ],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.governance.verify_manifest",
            failure_name="GOV_MANIFEST_INVALID",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/governance/governance_manifest.json and signature sidecars."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
