from __future__ import annotations

import hashlib

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402


def _sha_seed(base_model_id: str, suite_id: str, entrant_hashes: list[str]) -> str:
    payload = base_model_id + "|" + suite_id + "|" + "|".join(entrant_hashes)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_epic15_schemas_validate() -> None:
    created_at = "2026-01-01T00:00:00Z"

    entrants = [
        {"adapter_root_hash": "1" * 64, "adapter_id": "lobe.alpha.v1", "adapter_version": "1"},
        {"adapter_root_hash": "2" * 64, "adapter_id": "lobe.beta.v1", "adapter_version": "1"},
    ]
    entrant_hashes = [e["adapter_root_hash"] for e in entrants]

    plan = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_plan.v1.json"),
        "tournament_plan_id": "",
        "base_model_id": "mistral-7b",
        "suite_id": "SUITE_X",
        "suite_root_hash": "a" * 64,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "b" * 64,
        "tournament_mode": "round_robin_v1",
        "epsilon": 0.01,
        "entrants": entrants,
        "seed": _sha_seed("mistral-7b", "SUITE_X", entrant_hashes),
        "created_at": created_at,
        "notes": None,
    }
    plan["tournament_plan_id"] = sha256_hex_of_obj(plan, drop_keys={"created_at", "tournament_plan_id"})
    validate_object_with_binding(plan)

    result = {
        "schema_id": "kt.tournament_result.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_result.v1.json"),
        "tournament_result_id": "",
        "tournament_plan_id": plan["tournament_plan_id"],
        "status": "PASS",
        "reason_codes": [],
        "base_model_id": plan["base_model_id"],
        "suite_id": plan["suite_id"],
        "decode_policy_id": plan["decode_policy_id"],
        "tournament_mode": plan["tournament_mode"],
        "epsilon": plan["epsilon"],
        "entrants": entrants,
        "champion_set": ["1" * 64],
        "dominance_pairs": [{"dominant_adapter_root_hash": "1" * 64, "dominated_adapter_root_hash": "2" * 64}],
        "created_at": created_at,
        "notes": None,
    }
    result["tournament_result_id"] = sha256_hex_of_obj(result, drop_keys={"created_at", "tournament_result_id"})
    validate_object_with_binding(result)

    merge_manifest = {
        "schema_id": "kt.merge_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.merge_manifest.v1.json"),
        "merge_manifest_id": "",
        "base_model_id": "mistral-7b",
        "role_tag": "ROLE_X",
        "merge_method": "ties_v1",
        "parents": entrants,
        "created_at": created_at,
        "notes": None,
    }
    merge_manifest["merge_manifest_id"] = sha256_hex_of_obj(merge_manifest, drop_keys={"created_at", "merge_manifest_id"})
    validate_object_with_binding(merge_manifest)

    rollback = {
        "schema_id": "kt.merge_rollback_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.merge_rollback_plan.v1.json"),
        "rollback_plan_id": "",
        "merge_manifest_id": merge_manifest["merge_manifest_id"],
        "steps": [
            {"step_id": "01_disable_routing", "action": "router.disable_adapter", "target": "child_adapter"},
            {"step_id": "02_reinstate_parents", "action": "router.enable_adapters", "target": "parents"},
        ],
        "created_at": created_at,
        "notes": None,
    }
    rollback["rollback_plan_id"] = sha256_hex_of_obj(rollback, drop_keys={"created_at", "rollback_plan_id"})
    validate_object_with_binding(rollback)

    merge_eval = {
        "schema_id": "kt.merge_eval_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.merge_eval_receipt.v1.json"),
        "merge_eval_receipt_id": "",
        "merge_manifest_id": merge_manifest["merge_manifest_id"],
        "status": "PASS",
        "reason_codes": [],
        "safety_regression": False,
        "utility_gate_pass": True,
        "tournament_result_ref": "KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/TOURNAMENT_X/tournament_result.json",
        "created_at": created_at,
        "notes": None,
    }
    merge_eval["merge_eval_receipt_id"] = sha256_hex_of_obj(merge_eval, drop_keys={"created_at", "merge_eval_receipt_id"})
    validate_object_with_binding(merge_eval)

    admission = {
        "schema_id": "kt.training_admission_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.training_admission_receipt.v1.json"),
        "admission_receipt_id": "",
        "lane_id": "FL4_TRAIN",
        "decision": "PASS",
        "reason_codes": [],
        "job_ref": "KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/JOB_X/job.json",
        "job_sha256": "c" * 64,
        "law_bundle_hash": "d" * 64,
        "failure_taxonomy_id": "e" * 64,
        "created_at": created_at,
        "notes": None,
    }
    admission["admission_receipt_id"] = sha256_hex_of_obj(admission, drop_keys={"created_at", "admission_receipt_id"})
    validate_object_with_binding(admission)

