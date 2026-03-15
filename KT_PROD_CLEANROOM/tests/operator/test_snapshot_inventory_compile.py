from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.snapshot_inventory_compile import build_snapshot_reports  # noqa: E402
from tools.operator.titanium_common import semantically_equal_json  # noqa: E402


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "kt@example.test"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "KT Test"], cwd=root, check=True, capture_output=True)


def _seed_minimal_contract(root: Path) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM/reports/kt_historical_memory_ingestion_receipt.json",
        {
            "schema_id": "kt.operator.historical_memory_ingestion_receipt.v1",
            "status": "PASS",
            "compiled_head_commit": "0" * 40,
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
        {
            "schema_id": "kt.governance.trust_zone_registry.v2",
            "zones": [
                {"zone_id": "CANONICAL", "include": ["KT_PROD_CLEANROOM/governance/**", "KT_PROD_CLEANROOM/tools/operator/**", "KT_PROD_CLEANROOM/tests/**"], "exclude": ["KT_PROD_CLEANROOM/reports/**"]},
                {"zone_id": "LAB", "include": ["KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**"], "exclude": []},
                {"zone_id": "ARCHIVE", "include": ["KT_ARCHIVE/**"], "exclude": []},
                {"zone_id": "COMMERCIAL", "include": ["docs/**", "README.md", "LICENSE"], "exclude": []},
                {"zone_id": "GENERATED_RUNTIME_TRUTH", "include": ["KT_PROD_CLEANROOM/reports/**", "KT_PROD_CLEANROOM/exports/_truth/**"], "exclude": []},
                {"zone_id": "QUARANTINED", "include": ["KT_PROD_CLEANROOM/05_QUARANTINE/**"], "exclude": []},
            ],
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json",
        {
            "schema_id": "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2",
            "work_order_id": "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION",
        },
    )


def test_snapshot_reports_cover_every_file_and_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_contract(root)

    (root / "README.md").write_text("hello\n", encoding="utf-8")
    _write_json(root / "KT_PROD_CLEANROOM/governance/rules.json", {"ok": True})
    (root / "KT_PROD_CLEANROOM/tools/operator").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM/tools/operator/tool.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "KT_PROD_CLEANROOM/tests/operator").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM/tests/operator/test_sample.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    (root / "docs/guide.md").parent.mkdir(parents=True, exist_ok=True)
    (root / "docs/guide.md").write_text("# guide\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    first = build_snapshot_reports(root=root, generated_utc="2026-03-14T00:00:00Z")
    second = build_snapshot_reports(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert semantically_equal_json(first["manifest"], second["manifest"])
    assert semantically_equal_json(first["physical_inventory"], second["physical_inventory"])
    assert first["manifest"]["state_taint_status"] == "CLEAR"
    assert first["physical_inventory"]["coverage"]["inventory_file_count"] == first["physical_inventory"]["coverage"]["snapshot_scope_file_count"]
    assert len(first["manifest"]["files"]) == first["physical_inventory"]["coverage"]["snapshot_scope_file_count"]


def test_snapshot_reports_mark_critical_parse_failures_as_state_tainted(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_contract(root)

    (root / "KT_PROD_CLEANROOM/governance").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM/governance/bad.json").write_text("{bad", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    reports = build_snapshot_reports(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert reports["manifest"]["state_taint_status"] == "STATE_TAINTED"
    assert any(row["path"] == "KT_PROD_CLEANROOM/governance/bad.json" for row in reports["parse_failures"]["parse_failed_files"])
    assert any(row["path"] == "KT_PROD_CLEANROOM/governance/bad.json" for row in reports["parse_failures"]["tainting_files"])


def test_snapshot_reports_accept_bom_prefixed_json_in_critical_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_contract(root)

    (root / "KT_PROD_CLEANROOM/governance").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM/governance/bom.json").write_bytes(b"\xef\xbb\xbf{\n  \"ok\": true\n}\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    reports = build_snapshot_reports(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert reports["manifest"]["state_taint_status"] == "CLEAR"
    assert not any(row["path"] == "KT_PROD_CLEANROOM/governance/bom.json" for row in reports["parse_failures"]["parse_failed_files"])


def test_snapshot_reports_accept_legacy_report_text_without_false_taint(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_contract(root)

    (root / "KT_PROD_CLEANROOM/reports").mkdir(parents=True, exist_ok=True)
    (root / "KT_PROD_CLEANROOM/reports/legacy.md").write_bytes("Legacy report \u2014 sealed\n".encode("cp1252"))
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    reports = build_snapshot_reports(root=root, generated_utc="2026-03-14T00:00:00Z")

    assert reports["manifest"]["state_taint_status"] == "CLEAR"
    assert not any(row["path"] == "KT_PROD_CLEANROOM/reports/legacy.md" for row in reports["parse_failures"]["parse_failed_files"])
