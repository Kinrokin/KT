from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.canonical_tree_execute import (  # noqa: E402
    ARCHIVE_MANIFEST_REL,
    CANONICAL_TREE_MANIFEST_REL,
    DEPRECATION_EXECUTION_LOG_REL,
    build_ws2_outputs,
    build_ws2_receipt,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_ws2_outputs_settle_archive_root_and_clear_hard_dependencies() -> None:
    root = repo_root()
    outputs = build_ws2_outputs(root)
    canonical_manifest = outputs[CANONICAL_TREE_MANIFEST_REL]
    archive_manifest = outputs[ARCHIVE_MANIFEST_REL]
    deprecation_log = outputs[DEPRECATION_EXECUTION_LOG_REL]

    assert "KT_ARCHIVE/**" in canonical_manifest["excluded_paths"]
    assert canonical_manifest["tracked_root_entries"] == [
        ".devcontainer",
        ".gitattributes",
        ".github",
        ".gitignore",
        "ci",
        "docs",
        "KT_ARCHIVE",
        "KT-Codex",
        "KT_PROD_CLEANROOM",
        "LICENSE",
        "README.md",
        "REPO_CANON.md",
        "run_kt_e2e.sh",
    ]
    assert canonical_manifest["archive_reference_summary"]["hard_violation_count"] == 0
    assert archive_manifest["archive_root"] == "KT_ARCHIVE"
    assert archive_manifest["tracked_file_count"] >= 1
    assert deprecation_log["archive_root_cutover"]["canonical_archive_root"] == "KT_ARCHIVE"


def test_ws2_receipt_and_outputs_are_semantically_deterministic() -> None:
    root = repo_root()
    first_outputs = build_ws2_outputs(root)
    second_outputs = build_ws2_outputs(root)
    for rel in first_outputs:
        assert semantically_equal_json(first_outputs[rel], second_outputs[rel], volatile_keys=("generated_at", "generated_utc"))

    first_receipt = build_ws2_receipt(root)
    second_receipt = build_ws2_receipt(root)
    first_receipt["step_report"]["timestamp"] = "NORMALIZED"
    second_receipt["step_report"]["timestamp"] = "NORMALIZED"
    assert semantically_equal_json(first_receipt, second_receipt, volatile_keys=("generated_at", "generated_utc"))
