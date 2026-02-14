from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.probes.probe_synthesizer import run_probe_synthesis  # noqa: E402


def _mk_audit_event(*, run_id: str, created_at: str, reason_codes: list[str]) -> dict:
    obj = {
        "schema_id": "kt.audit_event.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_event.v1.json"),
        "event_id": "0" * 64,
        "run_id": run_id,
        "lane_id": "FL4_SEAL",
        "event_kind": "FINALIZATION",
        "severity": "FAIL_CLOSED",
        "reason_codes": sorted(reason_codes),
        "component": "tools.verification.fl4_seal_verify",
        "summary": "fixture audit event",
        "evidence_paths": [],
        "created_at": created_at,
        "notes": None,
    }
    obj["event_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "event_id"})
    validate_object_with_binding(obj)
    return obj


def test_probe_synthesis_smoke_and_determinism(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events" / "fixtures"
    events_root.mkdir(parents=True, exist_ok=True)

    created_at = "2026-02-14T00:00:00Z"
    reason_code = "SECRET_LEAK_DETECTED"
    for i in range(3):
        ev = _mk_audit_event(run_id=f"RUN_{i}", created_at=created_at, reason_codes=[reason_code])
        (events_root / f"event_{i}.json").write_text(
            json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n"
        )

    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    r1 = run_probe_synthesis(
        vault_root=vault_root,
        out_dir=out1,
        min_support=3,
        proposal_cooldown_hours=1,
        allow_noncanonical_vault=True,
    )
    r2 = run_probe_synthesis(
        vault_root=vault_root,
        out_dir=out2,
        min_support=3,
        proposal_cooldown_hours=1,
        allow_noncanonical_vault=True,
    )
    assert r1["status"] == "PASS"
    assert r2["status"] == "PASS"
    assert r1["probe_count"] == 1
    assert r2["probe_count"] == 1

    m1 = json.loads((out1 / "probe_synthesis_manifest.json").read_text(encoding="utf-8"))
    r1_obj = json.loads((out1 / "probe_synthesis_report.json").read_text(encoding="utf-8"))
    m2 = json.loads((out2 / "probe_synthesis_manifest.json").read_text(encoding="utf-8"))
    r2_obj = json.loads((out2 / "probe_synthesis_report.json").read_text(encoding="utf-8"))

    validate_object_with_binding(m1)
    validate_object_with_binding(r1_obj)
    validate_object_with_binding(m2)
    validate_object_with_binding(r2_obj)

    assert m1 == m2
    assert r1_obj == r2_obj

