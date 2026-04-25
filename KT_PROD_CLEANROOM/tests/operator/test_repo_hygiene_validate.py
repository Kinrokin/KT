from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.canonical_tree_execute import ARCHIVE_GITKEEP
from tools.operator.repo_hygiene_validate import build_ws13_outputs


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True, encoding="utf-8").strip()


def _init_repo(tmp_path: Path) -> str:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")
    return _git(tmp_path, "rev-parse", "--show-toplevel")


def _seed_required_tree(tmp_path: Path) -> None:
    for rel in [
        ".devcontainer/.gitkeep",
        ".github/.gitkeep",
        "ci/.gitkeep",
        "docs/.gitkeep",
        "KT-Codex/.gitkeep",
        ARCHIVE_GITKEEP,
        "KT_PROD_CLEANROOM/.gitkeep",
    ]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    for rel, text in {
        "README.md": "readme\n",
        "LICENSE": "license\n",
        "REPO_CANON.md": "canon\n",
        "run_kt_e2e.sh": "#!/bin/sh\n",
        ".gitattributes": "* text=auto\n",
        ".gitignore": "\n".join(
            [
                ".vscode/",
                ".venv*/",
                "__pycache__/",
                "*.secret",
                "autonomous_escalation_log.json",
                "autonomous_analysis.json",
                "epoch_escalation_log.json",
                "tmp/",
                "_runs/",
                "",
            ]
        ),
    }.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_canonical_tree_manifest.json",
        {
            "tracked_root_entries": [
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
            ],
            "excluded_paths": [
                ".env.secret",
                "autonomous_analysis.json",
                "autonomous_escalation_log.json",
                "epoch_escalation_log.json",
                "exports/**",
                "tmp/**",
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "canonical_scope_manifest.json",
        {
            "canonical_primary_surfaces": [
                "KT_PROD_CLEANROOM/governance/**",
                "KT_PROD_CLEANROOM/tools/operator/**",
                "KT_PROD_CLEANROOM/tools/verification/**",
            ]
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "trust_zone_registry.json",
        {
            "zones": [
                {
                    "zone_id": "CANONICAL",
                    "exclude": ["autonomous_*.json", "epoch_*.json"],
                }
            ]
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_final_completion_bundle.json",
        {"status": "PASS"},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_total_closure_campaign_completion_receipt.json",
        {"status": "PASS"},
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "reports" / "repo_hygiene_summary.json",
        {"status": "PASS_WITH_ALLOWED_CANDIDATE_DIRT"},
    )
    (tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator").mkdir(parents=True, exist_ok=True)
    (tmp_path / "KT_PROD_CLEANROOM" / "tests" / "operator").mkdir(parents=True, exist_ok=True)
    (tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator" / "repo_hygiene_validate.py").write_text("stub\n", encoding="utf-8")
    (tmp_path / "KT_PROD_CLEANROOM" / "tests" / "operator" / "test_repo_hygiene_validate.py").write_text("stub\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "seed")
    (tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator" / "repo_hygiene_validate.py").write_text("subject change\n", encoding="utf-8")
    (tmp_path / "KT_PROD_CLEANROOM" / "tests" / "operator" / "test_repo_hygiene_validate.py").write_text("subject change\n", encoding="utf-8")
    _git(tmp_path, "add", "KT_PROD_CLEANROOM/tools/operator/repo_hygiene_validate.py", "KT_PROD_CLEANROOM/tests/operator/test_repo_hygiene_validate.py")
    _git(tmp_path, "commit", "-m", "subject")


def test_repo_hygiene_validate_passes_when_root_is_clean(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_required_tree(tmp_path)

    outputs = build_ws13_outputs(tmp_path)

    assert outputs["inventory"]["secret_like_root_surfaces_present"] == []
    assert outputs["inventory"]["local_root_residue_present"] == []
    assert outputs["clean_state"]["status"] == "PASS"
    assert outputs["hygiene"]["status"] == "PASS"
    assert outputs["hygiene"]["pass_verdict"] == "REPO_HYGIENE_CLEANROOM_SETTLED"


def test_repo_hygiene_validate_fails_when_root_residue_remains(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_required_tree(tmp_path)
    (tmp_path / ".env.secret").write_text("secret\n", encoding="utf-8", newline="\n")
    (tmp_path / "autonomous_analysis.json").write_text("{}\n", encoding="utf-8", newline="\n")
    (tmp_path / "exports" / "_runs").mkdir(parents=True, exist_ok=True)

    outputs = build_ws13_outputs(tmp_path)

    assert ".env.secret" in outputs["inventory"]["secret_like_root_surfaces_present"]
    assert "autonomous_analysis.json" in outputs["inventory"]["local_root_residue_present"]
    assert "exports" in outputs["inventory"]["local_root_residue_present"]
    assert outputs["clean_state"]["status"] == "FAIL_CLOSED"
    assert outputs["hygiene"]["status"] == "FAIL_CLOSED"


def test_repo_hygiene_validate_allows_advisory_local_residue(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _seed_required_tree(tmp_path)
    (tmp_path / ".coverage").write_text("cov\n", encoding="utf-8", newline="\n")
    (tmp_path / ".pytest_wave2a").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".vscode").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tmp").mkdir(parents=True, exist_ok=True)

    outputs = build_ws13_outputs(tmp_path)

    assert outputs["inventory"]["blocking_local_root_residue_present"] == []
    assert ".coverage" in outputs["inventory"]["advisory_local_root_residue_present"]
    assert ".pytest_wave2a" in outputs["inventory"]["advisory_local_root_residue_present"]
    assert outputs["inventory"]["effective_root_entries_match_canonical_keep_set"] is True
    assert outputs["clean_state"]["status"] == "PASS"
    assert outputs["clean_state"]["git_status_clean"] is False
    assert outputs["hygiene"]["status"] == "PASS"
