from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import tournament_promotion_merge_law_validate as tpm


OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/governance/tournament_law.json",
    "KT_PROD_CLEANROOM/governance/promotion_engine_law.json",
    "KT_PROD_CLEANROOM/governance/merge_law.json",
    "KT_PROD_CLEANROOM/governance/b04_r3_tournament_promotion_merge_law_contract.json",
    "KT_PROD_CLEANROOM/governance/b04_r3_tournament_promotion_merge_terminal_state.json",
    "KT_PROD_CLEANROOM/tools/operator/tournament_promotion_merge_law_validate.py",
    "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json",
    "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json",
    "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json",
    "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(["git", "clone", "--quiet", str(root), str(clone_root)], cwd=str(tmp_path), check=True)
    for ref in OVERLAY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return clone_root


def test_tournament_promotion_merge_law_receipt_passes_on_current_repo() -> None:
    root = _repo_root()
    receipt = tpm.build_tournament_promotion_merge_law_receipt(root=root)

    assert receipt["status"] == "PASS"
    assert receipt["workstream_id"] == "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"
    assert receipt["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
    assert receipt["tournament_class_summary"]["class_ids"] == tpm.EXPECTED_TOURNAMENT_CLASSES
    assert receipt["promotion_rule_summary"]["router_candidate_pool_authorized_now"] is False
    assert receipt["merge_rule_summary"]["direct_router_admission_allowed"] is False


def test_tournament_promotion_merge_law_cli_emits_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    receipt_path = tmp_path / "tournament_promotion_merge_law_ratification_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.tournament_promotion_merge_law_validate",
            "--output",
            str(receipt_path),
        ],
        cwd=str(root / "KT_PROD_CLEANROOM"),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["tournament_promotion_merge_law_ratification_status"] == "PASS"
    assert payload["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_ARTIFACT_ONLY"
    assert receipt["next_lawful_move"] == "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"
