from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.delivery.delivery_linter import lint_delivery_dir  # noqa: E402
from tools.delivery.generate_delivery_pack import generate_delivery_pack  # noqa: E402
from tools.security.pack_guard_scan import scan_pack_and_write  # noqa: E402
from tools.verification.run_protocol_generator import build_run_protocol, write_run_protocol_pair  # noqa: E402
from tools.verification.fl3_validators import validate_schema_bound_object  # noqa: E402


def test_delivery_pack_generator_redacts_paths_and_ips(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    out_dir = tmp_path / "out"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # Evidence surfaces that must be redacted in delivery pack.
    (evidence_dir / "command_transcript.txt").write_text(
        "User path: C:\\\\Users\\\\rober\\\\Downloads\\\\file.txt\\nIP: 192.168.0.1\\n",
        encoding="utf-8",
    )

    # Evidence secret scan must exist and PASS (delivery generator requires it).
    report, summary = scan_pack_and_write(pack_root=evidence_dir, out_dir=evidence_dir, run_id="r" * 64, lane_id="EVIDENCE")
    assert report["status"] == "PASS"
    assert summary["status"] == "PASS"

    # Minimal run protocol pair required by delivery generator.
    protocol = build_run_protocol(
        {
            "run_id": "r" * 64,
            "lane_id": "FL4_SEAL",
            "timestamp_utc": "2026-01-01T00:00:00Z",
            "determinism_mode": "STRICT",
            "execution_environment_hash": "a" * 64,
            "governed_phase_start_hash": "b" * 64,
            "io_guard_status": "GUARDED",
            "base_model_id": "mistral-7b",
            "active_adapters": [{"adapter_id": "lobe.architect.v1", "adapter_hash": "c" * 64}],
            "replay_command": "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json",
            "replay_script_hash": "d" * 64,
            "secret_scan_result": "PASS",
            "bundle_root_hash": "e" * 64,
        }
    )
    write_run_protocol_pair(out_dir=evidence_dir, protocol=protocol)

    result = generate_delivery_pack(evidence_dir=evidence_dir, out_dir=out_dir)
    assert result["status"] == "PASS"

    delivery_dir = Path(result["delivery_dir"])
    redacted_text = (delivery_dir / "evidence" / "command_transcript.txt").read_text(encoding="utf-8")
    assert "C:\\\\Users\\\\rober" not in redacted_text
    assert "192.168.0.1" not in redacted_text

    exec_md = (delivery_dir / "reports" / "KT_EXEC_SUMMARY.md").read_text(encoding="utf-8")
    assert "{{" not in exec_md

    manifest_path = delivery_dir / "delivery_pack_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(manifest)
    assert manifest["schema_id"] == "kt.delivery_pack_manifest.v1"

    # Delivery secret scan artifacts must exist and PASS.
    dsum = json.loads((delivery_dir / "secret_scan_summary.json").read_text(encoding="utf-8"))
    validate_schema_bound_object(dsum)
    assert dsum["status"] == "PASS"

    zip_path = Path(result["zip_path"])
    sha_path = Path(str(zip_path) + ".sha256")
    assert zip_path.exists()
    assert sha_path.exists()

    lint_report = lint_delivery_dir(delivery_dir=delivery_dir)
    assert lint_report["status"] == "PASS"
