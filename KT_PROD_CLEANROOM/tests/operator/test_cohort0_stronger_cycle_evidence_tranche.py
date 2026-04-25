from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_cohort0_stronger_cycle_evidence_tranche_binds_execution_surfaces(tmp_path: Path) -> None:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(["git", "clone", "--quiet", str(root), str(clone_root)], cwd=str(tmp_path), check=True)

    copy_refs = [
        "KT_PROD_CLEANROOM/tools/operator/cohort0_stronger_cycle_evidence_tranche.py",
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
            "tools.operator.cohort0_stronger_cycle_evidence_tranche",
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
    assert payload["evidence_posture"] == "STRONGER_CYCLE_EVIDENCE_READY__CHAOS_A_HYPERTRAINING_CHAOS_B_BOUND"
    assert payload["hypertraining_lane_count"] == 13
    assert payload["next_lawful_move"] == "EXECUTE_CHAOS_A_ON_NEW_AUTHORITATIVE_HEAD_WITH_REAL_STAGE_INPUTS"

    authoritative_packet = json.loads((authoritative_root / "cohort0_stronger_cycle_evidence_packet.json").read_text(encoding="utf-8"))
    tracked_packet = json.loads((clone_root / "KT_PROD_CLEANROOM" / "reports" / "cohort0_stronger_cycle_evidence_packet.json").read_text(encoding="utf-8"))
    chaos_a_registry = json.loads((authoritative_root / "chaos_round_a" / "forge_cohort0_registry_hf_lora.json").read_text(encoding="utf-8"))
    chaos_b_registry = json.loads((authoritative_root / "chaos_round_b" / "forge_cohort0_registry_hf_lora.json").read_text(encoding="utf-8"))
    hyper_contract = json.loads((authoritative_root / "individual_hypertraining" / "hypertraining_contract.json").read_text(encoding="utf-8"))
    first_config = json.loads(
        (authoritative_root / "individual_hypertraining" / "configs" / "lobe.alpha.v1.rapid_lora_config.json").read_text(encoding="utf-8")
    )

    assert authoritative_packet["status"] == "PASS"
    assert authoritative_packet["adapter_count"] == 13
    assert authoritative_packet["execution_input_contract"]["base_model_dir_required"] is True
    assert authoritative_packet["job_dir_manifest_strategy"]["mode"] == "REEXPORT_FROM_EVAL_REPORT_V2"
    assert authoritative_packet["current_cycle_ceiling_summary"]["router_superiority_earned"] is False
    assert authoritative_packet["current_cycle_ceiling_summary"]["admissible_parent_pair_count"] == 13

    assert chaos_a_registry["registry_id"] == "KT_OPERATOR_FORGE_COHORT0_STRONGER_CYCLE_CHAOS_A_V1"
    assert chaos_b_registry["registry_id"] == "KT_OPERATOR_FORGE_COHORT0_STRONGER_CYCLE_CHAOS_B_V1"
    assert chaos_a_registry["default_training_params"]["engine"] == "hf_lora"
    assert chaos_b_registry["default_training_params"]["training_mode"] == "lora"
    assert len(chaos_a_registry["adapters"]) == 13
    assert len(chaos_b_registry["adapters"]) == 13
    assert chaos_a_registry["adapters"][0]["training_params"]["seed"] == 1101
    assert chaos_b_registry["adapters"][0]["training_params"]["seed"] == 3101

    assert hyper_contract["status"] == "PASS"
    assert hyper_contract["lane_count"] == 13
    assert hyper_contract["lanes"][0]["job_dir_manifest_derivation"]["mode"] == "REEXPORT_FROM_EVAL_REPORT_V2"

    assert first_config["schema_id"] == "kt.operator.cohort0_hypertraining_config.unbound.v1"
    assert first_config["adapter_id"] == "lobe.alpha.v1"
    assert first_config["seed"] == 2101
    assert first_config["max_steps"] == 3

    assert tracked_packet["carrier_surface_role"] == "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_EVIDENCE_PACKET"
    assert tracked_packet["authoritative_stronger_cycle_evidence_packet_ref"] == (authoritative_root / "cohort0_stronger_cycle_evidence_packet.json").resolve().as_posix()
