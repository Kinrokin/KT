from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_cohort0_router_proof_state_binding_tranche_flips_to_r6_blocked_hold(tmp_path: Path) -> None:
    root = _repo_root()
    work_root = tmp_path / "work"

    subprocess.run(["git", "clone", "--quiet", str(root), str(work_root)], cwd=str(tmp_path), check=True)
    clone_head = subprocess.check_output(["git", "-C", str(work_root), "rev-parse", "HEAD"], text=True).strip()

    copy_refs = [
        "KT_PROD_CLEANROOM/tools/operator/cohort0_router_proof_state_binding_tranche.py",
    ]
    for rel in copy_refs:
        src = root / rel
        dst = work_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    proof_receipt = {
        "status": "PASS",
        "workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF",
        "current_git_head": clone_head,
        "subject_head": clone_head,
        "next_lawful_move": "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF",
        "router_proof_summary": {
            "router_superiority_earned": False,
            "exact_superiority_outcome": "NOT_EARNED_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
        },
    }
    ordered_receipt = {
        "ordered_proof_outcome": "PASS_HOLD_STATIC_CANONICAL_BASELINE",
    }
    scorecard = {
        "superiority_earned": False,
    }
    shadow_receipt = {
        "status": "PASS",
    }
    followthrough = {
        "followthrough_posture": "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED",
    }
    promotion = {"status": "PASS"}
    merge = {"status": "PASS"}
    overlay = json.loads((work_root / "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json").read_text(encoding="utf-8"))
    overlay["next_counted_workstream_id"] = "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    _write_json(work_root / "proof.json", proof_receipt)
    _write_json(work_root / "ordered.json", ordered_receipt)
    _write_json(work_root / "scorecard.json", scorecard)
    _write_json(work_root / "shadow.json", shadow_receipt)
    _write_json(work_root / "followthrough.json", followthrough)
    _write_json(work_root / "promotion.json", promotion)
    _write_json(work_root / "merge.json", merge)
    _write_json(work_root / "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json", overlay)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(work_root / "KT_PROD_CLEANROOM")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONUTF8"] = "1"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.cohort0_router_proof_state_binding_tranche",
            "--router-proof-receipt",
            str(work_root / "proof.json"),
            "--router-ordered-proof-receipt",
            str(work_root / "ordered.json"),
            "--router-superiority-scorecard",
            str(work_root / "scorecard.json"),
            "--router-shadow-receipt",
            str(work_root / "shadow.json"),
            "--followthrough-report",
            str(work_root / "followthrough.json"),
            "--promotion-outcome-report",
            str(work_root / "promotion.json"),
            "--merge-outcome-report",
            str(work_root / "merge.json"),
            "--current-campaign-state-overlay",
            str(work_root / "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json"),
            "--next-counted-workstream-contract",
            str(work_root / "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json"),
            "--resume-blockers-receipt",
            str(work_root / "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json"),
            "--gate-d-decision-reanchor-packet",
            str(work_root / "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"),
            "--binding-report",
            str(work_root / "KT_PROD_CLEANROOM/reports/cohort0_router_proof_state_binding_receipt.json"),
        ],
        cwd=str(work_root / "KT_PROD_CLEANROOM"),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["next_lawful_move"] == "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"

    overlay_obj = json.loads((work_root / "KT_PROD_CLEANROOM/reports/current_campaign_state_overlay.json").read_text(encoding="utf-8"))
    next_obj = json.loads((work_root / "KT_PROD_CLEANROOM/reports/next_counted_workstream_contract.json").read_text(encoding="utf-8"))
    resume_obj = json.loads((work_root / "KT_PROD_CLEANROOM/reports/resume_blockers_receipt.json").read_text(encoding="utf-8"))
    reanchor_obj = json.loads((work_root / "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json").read_text(encoding="utf-8"))
    binding_obj = json.loads((work_root / "KT_PROD_CLEANROOM/reports/cohort0_router_proof_state_binding_receipt.json").read_text(encoding="utf-8"))

    assert overlay_obj["workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert overlay_obj["next_counted_workstream_id"] == "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
    assert overlay_obj["repo_state_executable_now"] is False
    assert next_obj["source_workstream_id"] == "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"
    assert next_obj["exact_next_counted_workstream_id"] == "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
    assert next_obj["execution_mode"] == "R6_NEXT_IN_ORDER_BLOCKED_PENDING_EARNED_SUPERIORITY__INITIAL_R5_PROOF_COMPLETE"
    assert next_obj["repo_state_executable_now"] is False
    assert resume_obj["exact_next_counted_workstream_id"] == "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
    assert resume_obj["repo_state_executable_now"] is False
    assert reanchor_obj["next_lawful_move"] == "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
    assert binding_obj["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_ROUTER_PROOF_STATE_BINDING_RECEIPT"
