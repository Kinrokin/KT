from __future__ import annotations

import json
from pathlib import Path

from tools.operator.interface_freeze_validate import FROZEN_STATUS, INTERFACE_CONTRACT_SPECS, build_interface_freeze_receipt


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_frozen_contracts(root: Path) -> None:
    for relpath, spec in INTERFACE_CONTRACT_SPECS.items():
        payload = {
            "schema_id": spec["schema_id"],
            "contract_id": Path(relpath).stem.upper(),
            "status": FROZEN_STATUS,
            "wave_frozen": "WAVE_0_5_PACKAGE_IMPORT_CANON_AND_INTERFACE_FREEZE",
        }
        for key, values in spec["required_lists"].items():
            payload[key] = list(values)
        _write_json(root / relpath, payload)


def test_interface_freeze_passes_when_all_contracts_are_frozen(tmp_path: Path) -> None:
    _seed_frozen_contracts(tmp_path)
    receipt = build_interface_freeze_receipt(root=tmp_path)
    assert receipt["status"] == "PASS", receipt


def test_interface_freeze_fails_when_required_binding_targets_are_missing(tmp_path: Path) -> None:
    _seed_frozen_contracts(tmp_path)
    target = tmp_path / "KT_PROD_CLEANROOM" / "governance" / "kt_mutation_authority_v1.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["binding_targets"] = ["state_vault_writes"]
    _write_json(target, payload)

    receipt = build_interface_freeze_receipt(root=tmp_path)

    assert receipt["status"] == "FAIL"
    assert any("missing_binding_targets:KT_PROD_CLEANROOM/governance/kt_mutation_authority_v1.json" in item for item in receipt["failures"])


def test_interface_freeze_accepts_later_wave_frozen_benchmark_constitution_status(tmp_path: Path) -> None:
    _seed_frozen_contracts(tmp_path)
    benchmark = tmp_path / "KT_PROD_CLEANROOM" / "governance" / "kt_benchmark_constitution_v1.json"
    payload = json.loads(benchmark.read_text(encoding="utf-8"))
    payload["status"] = "FROZEN_W4_CURRENT_HEAD"
    _write_json(benchmark, payload)

    receipt = build_interface_freeze_receipt(root=tmp_path)

    assert receipt["status"] == "PASS", receipt
