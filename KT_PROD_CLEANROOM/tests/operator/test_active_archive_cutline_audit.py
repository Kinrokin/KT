from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.active_archive_cutline_audit import (  # noqa: E402
    BOUNDARY_MAP_REL,
    CROSS_REFERENCE_REGISTER_REL,
    QUARANTINE_PLAN_REL,
    build_ws1_outputs,
    build_ws1_receipt,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_ws1_outputs_enumerate_archive_surfaces_and_cross_references() -> None:
    root = repo_root()
    outputs = build_ws1_outputs(root)
    boundary_map = outputs[BOUNDARY_MAP_REL]
    cross_refs = outputs[CROSS_REFERENCE_REGISTER_REL]
    quarantine_plan = outputs[QUARANTINE_PLAN_REL]

    assert boundary_map["summary"]["archive_surface_count"] >= 1
    assert boundary_map["summary"]["embedded_archive_island_count"] >= 1
    assert any(row["archive_surface"] == "docs/audit/" for row in quarantine_plan["quarantine_entries"])
    assert any(row["archive_surface"].startswith("KT_TEMPLE_ROOT") for row in quarantine_plan["quarantine_entries"])
    assert any(row["archive_ref"] == "docs/audit/" for row in cross_refs["cross_references"])

    for row in cross_refs["cross_references"]:
        assert row["consumer_plane"]
        assert row["dependency_class"]
        assert row["relocation_consequence"]

    for row in quarantine_plan["quarantine_entries"]:
        assert row["proposed_archive_target"]
        assert row["relocation_consequences"]


def test_ws1_receipt_and_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first_outputs = build_ws1_outputs(root)
    second_outputs = build_ws1_outputs(root)
    for rel in first_outputs:
        assert semantically_equal_json(first_outputs[rel], second_outputs[rel]), rel

    first_receipt = build_ws1_receipt(root)
    second_receipt = build_ws1_receipt(root)
    first_receipt["step_report"]["timestamp"] = "NORMALIZED"
    second_receipt["step_report"]["timestamp"] = "NORMALIZED"
    assert semantically_equal_json(first_receipt, second_receipt)
