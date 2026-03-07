from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.delivery.delivery_linter import lint_delivery_dir
from tools.operator.titanium_common import make_run_dir, write_failure_artifacts, write_json_worm


def _resolve_inputs(delivery_dir: Path) -> tuple[Path, Path, Path]:
    delivery_dir = delivery_dir.resolve()
    if (delivery_dir / "delivery_manifest.json").exists():
        run_dir = delivery_dir.parent.resolve()
        pack_manifest = json.loads((delivery_dir / "delivery_manifest.json").read_text(encoding="utf-8"))
        pack_dir = Path(str(pack_manifest.get("delivery_dir", ""))).expanduser()
        if not pack_dir.is_absolute():
            pack_dir = (delivery_dir.parent.parent / pack_dir).resolve()
        return run_dir, delivery_dir, pack_dir.resolve()
    if (delivery_dir / "delivery_pack_manifest.json").exists():
        pack_dir = delivery_dir
        return pack_dir.parent.parent.resolve(), pack_dir.parent.resolve(), pack_dir.resolve()
    raise RuntimeError(f"FAIL_CLOSED: unsupported delivery-dir layout: {delivery_dir.as_posix()}")


def validate_delivery_contract(delivery_dir: Path) -> Dict[str, Any]:
    run_dir, operator_delivery_dir, pack_dir = _resolve_inputs(delivery_dir)
    evidence_dir = (run_dir / "evidence").resolve()
    reports_dir = (run_dir / "reports").resolve()
    required = [
        operator_delivery_dir / "delivery_manifest.json",
        evidence_dir / "constitutional_snapshot.json",
        evidence_dir / "worm_manifest.json",
        evidence_dir / "evidence_core_merkle.json",
        evidence_dir / "replay.sh",
        evidence_dir / "replay.ps1",
        evidence_dir / "replay_receipt.json",
        evidence_dir / "secret_scan_report.json",
        operator_delivery_dir / "delivery_lint_report.json",
        reports_dir / "one_line_verdict.txt",
        reports_dir / "bindingloop_check.json",
        run_dir / "verdict.txt",
        reports_dir / "operator_fingerprint.json",
        reports_dir / "operator_intent.json",
    ]
    missing = [p.as_posix() for p in required if not p.exists()]
    if missing:
        raise RuntimeError("FAIL_CLOSED: delivery contract missing required artifacts: " + ",".join(missing))
    lint_report = lint_delivery_dir(delivery_dir=pack_dir)
    if str(lint_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: underlying delivery pack linter did not PASS")
    secret_report = json.loads((evidence_dir / "secret_scan_report.json").read_text(encoding="utf-8"))
    if str(secret_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: secret scan not PASS")
    operator_lint = json.loads((operator_delivery_dir / "delivery_lint_report.json").read_text(encoding="utf-8"))
    if str(operator_lint.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: operator delivery lint not PASS")
    return {
        "delivery_dir": operator_delivery_dir.as_posix(),
        "pack_dir": pack_dir.as_posix(),
        "schema_id": "kt.operator.delivery_contract_validation.v1",
        "status": "PASS",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate the KT Titanium delivery contract.")
    ap.add_argument("--delivery-dir", required=True)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="delivery-contract-validate", requested_run_root=str(args.run_root))
    try:
        report = validate_delivery_contract(Path(args.delivery_dir))
        write_json_worm(run_dir / "reports" / "delivery_contract_validation.json", report, label="delivery_contract_validation.json")
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.delivery.contract.validate",
            failure_name="DELIVERY_CONTRACT_FAIL",
            message=str(exc),
            next_actions=["Ensure the run emits the Titanium evidence-plane artifacts before delivery."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
