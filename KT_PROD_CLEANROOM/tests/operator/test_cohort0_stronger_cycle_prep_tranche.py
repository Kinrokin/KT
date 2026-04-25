from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_cohort0_stronger_cycle_prep_tranche_binds_post_r5_ceiling(tmp_path: Path) -> None:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(["git", "clone", "--quiet", str(root), str(clone_root)], cwd=str(tmp_path), check=True)

    copy_refs = [
        "KT_PROD_CLEANROOM/tools/operator/cohort0_stronger_cycle_prep_tranche.py",
    ]
    for rel in copy_refs:
        src = root / rel
        dst = clone_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(clone_root / "KT_PROD_CLEANROOM") + os.pathsep + str(clone_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    authoritative_root = tmp_path / "authoritative"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.cohort0_stronger_cycle_prep_tranche",
            "--authoritative-root",
            str(authoritative_root),
            "--reports-root",
            str(clone_root / "KT_PROD_CLEANROOM" / "reports"),
        ],
        cwd=str(clone_root / "KT_PROD_CLEANROOM"),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["prep_posture"] == "STRONGER_NEW_CYCLE_REQUIRED__CHAOS_SPECIALIZE_CHAOS_TARGET_BOUND"
    assert payload["next_lawful_move"] == "PREPARE_SCHEMA_BOUND_CHAOS_A_INDIVIDUAL_HYPERTRAINING_CHAOS_B_EVIDENCE"

    authoritative_packet = json.loads((authoritative_root / "cohort0_stronger_cycle_prep_packet.json").read_text(encoding="utf-8"))
    tracked_packet = json.loads((clone_root / "KT_PROD_CLEANROOM" / "reports" / "cohort0_stronger_cycle_prep_packet.json").read_text(encoding="utf-8"))

    assert authoritative_packet["status"] == "PASS"
    assert authoritative_packet["current_cycle_ceiling_summary"]["router_superiority_earned"] is False
    assert authoritative_packet["current_cycle_ceiling_summary"]["canonical_router_status"] == "STATIC_CANONICAL_BASELINE_ONLY"
    assert authoritative_packet["current_cycle_ceiling_summary"]["non_stub_eval_entry_count"] == 13
    assert authoritative_packet["current_cycle_ceiling_summary"]["metric_probe_agreement_true_count"] == 11
    assert authoritative_packet["current_cycle_ceiling_summary"]["current_tournament_dominance_pair_count"] == 65
    assert authoritative_packet["current_cycle_ceiling_summary"]["admissible_parent_pair_count"] == 13
    assert len(authoritative_packet["stronger_cycle_sequence"]) == 7
    assert authoritative_packet["stronger_cycle_sequence"][0]["stage_id"] == "CHAOS_ROUND_A__ALL_13_SHARED_PRESSURE"
    assert authoritative_packet["stronger_cycle_sequence"][-1]["stage_id"] == "ROUTER_SHADOW_AND_R5_RERUN"
    assert tracked_packet["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_PREP_PACKET"
    assert tracked_packet["authoritative_stronger_cycle_prep_packet_ref"] == (authoritative_root / "cohort0_stronger_cycle_prep_packet.json").resolve().as_posix()
