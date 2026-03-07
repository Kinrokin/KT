from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import make_run_dir, write_failure_artifacts, write_json_worm


def _payload_sha(path: Path, exclude_keys: set[str]) -> str:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    payload = {k: v for k, v in obj.items() if k not in exclude_keys}
    return sha256_hex(canonicalize_bytes(payload))


def verify_binding_loop(run_dir_target: Path) -> Dict[str, Any]:
    run_dir_target = run_dir_target.resolve()
    delivery_manifest = (run_dir_target / "delivery" / "delivery_manifest.json").resolve()
    constitutional_snapshot = (run_dir_target / "evidence" / "constitutional_snapshot.json").resolve()
    worm_manifest = (run_dir_target / "evidence" / "worm_manifest.json").resolve()
    for path in (delivery_manifest, constitutional_snapshot, worm_manifest):
        if not path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing binding-loop artifact: {path.as_posix()}")
    delivery_obj = json.loads(delivery_manifest.read_text(encoding="utf-8"))
    constitutional_obj = json.loads(constitutional_snapshot.read_text(encoding="utf-8"))
    worm_obj = json.loads(worm_manifest.read_text(encoding="utf-8"))
    delivery_claim = str(constitutional_obj.get("delivery_manifest_payload_sha256", "")).strip()
    worm_claim = str(delivery_obj.get("worm_manifest_payload_sha256", "")).strip()
    constitutional_claim = str(worm_obj.get("constitutional_snapshot_payload_sha256", "")).strip()
    actual_delivery = _payload_sha(delivery_manifest, {"worm_manifest_payload_sha256"})
    actual_worm = _payload_sha(worm_manifest, {"constitutional_snapshot_payload_sha256"})
    actual_constitutional = _payload_sha(constitutional_snapshot, {"delivery_manifest_payload_sha256"})
    failures = []
    if delivery_claim != actual_delivery:
        failures.append("delivery_manifest_payload_sha256")
    if worm_claim != actual_worm:
        failures.append("worm_manifest_payload_sha256")
    if constitutional_claim != actual_constitutional:
        failures.append("constitutional_snapshot_payload_sha256")
    return {
        "actual": {
            "constitutional_snapshot_payload_sha256": actual_constitutional,
            "delivery_manifest_payload_sha256": actual_delivery,
            "worm_manifest_payload_sha256": actual_worm,
        },
        "claims": {
            "constitutional_snapshot_payload_sha256": constitutional_claim,
            "delivery_manifest_payload_sha256": delivery_claim,
            "worm_manifest_payload_sha256": worm_claim,
        },
        "schema_id": "kt.operator.bindingloop_check.v1",
        "status": "PASS" if not failures else "FAIL",
        "violations": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Verify the Titanium three-way binding loop.")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="bindingloop-verify", requested_run_root=str(args.run_root))
    try:
        report = verify_binding_loop(Path(args.run_dir))
        report_path = run_dir / "reports" / ("bindingloop_check.json" if report["status"] == "PASS" else "bindingloop_violation_receipt.json")
        write_json_worm(report_path, report, label=report_path.name)
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.bindingloop.verify",
                failure_name="BINDING_LOOP_FAIL",
                message="; ".join(report.get("violations", [])),
                next_actions=["Rebuild constitutional_snapshot.json, delivery_manifest.json, and worm_manifest.json using a consistent payload-hash loop."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.bindingloop.verify",
            failure_name="BINDING_LOOP_FAIL",
            message=str(exc),
            next_actions=["Ensure the run emits Titanium binding-loop artifacts before verification."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
