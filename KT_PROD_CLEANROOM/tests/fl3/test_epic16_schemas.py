from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402


def _build_simulated_signoff(*, key_id: str, payload_hash: str, created_at: str) -> dict:
    signoff = {
        "schema_id": "kt.human_signoff.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v2.json"),
        "signoff_id": "",
        "attestation_mode": "SIMULATED",
        "key_id": key_id,
        "payload_hash": payload_hash,
        "simulated_signature": sha256_hex_of_obj({"key_id": key_id, "payload_hash": payload_hash}, drop_keys=set()),
        "created_at": created_at,
    }
    signoff["signoff_id"] = sha256_hex_of_obj(signoff, drop_keys={"created_at", "signoff_id"})
    return signoff


def test_epic16_schemas_validate() -> None:
    created_at = "2026-01-01T00:00:00Z"

    suite_id = "SUITE_X"
    suite_root_hash = "a" * 64
    authorization_payload_hash = sha256_hex_of_obj({"suite_id": suite_id, "suite_root_hash": suite_root_hash}, drop_keys=set())

    suite_registry = {
        "schema_id": "kt.suite_registry.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.suite_registry.v1.json"),
        "suite_registry_id": "",
        "attestation_mode": "SIMULATED",
        "suites": [
            {
                "suite_id": suite_id,
                "suite_root_hash": suite_root_hash,
                "suite_definition_ref": "KT_PROD_CLEANROOM/AUDITS/SUITES/SUITE_X.json",
                "authorization_payload_hash": authorization_payload_hash,
                "signoffs": [
                    _build_simulated_signoff(key_id="SIGNER_A", payload_hash=authorization_payload_hash, created_at=created_at),
                    _build_simulated_signoff(key_id="SIGNER_B", payload_hash=authorization_payload_hash, created_at=created_at),
                ],
                "notes": None,
            }
        ],
        "created_at": created_at,
        "notes": None,
    }
    suite_registry["suite_registry_id"] = sha256_hex_of_obj(suite_registry, drop_keys={"created_at", "suite_registry_id"})
    validate_object_with_binding(suite_registry)

    break_hypothesis = {
        "schema_id": "kt.break_hypothesis.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.break_hypothesis.v1.json"),
        "break_hypothesis_id": "",
        "base_model_id": "mistral-7b",
        "suite_id": suite_id,
        "hypothesis": "Adapters may overfit to suite distributions and fail on perturbations or inversion traps.",
        "predicted_failure_modes": [
            {"mode_id": "F01_FORMAT", "description": "Format drift under perturbation."},
            {"mode_id": "F02_REFUSAL", "description": "Refusal integrity collapse under inversion."},
        ],
        "required_probe_families": ["inversion_trap", "ood_anchor", "perturbation", "schema_trap"],
        "regression_budgets": {"safety_regression_epsilon": 0.0, "new_hard_failures_allowed": 0},
        "created_at": created_at,
        "notes": None,
    }
    break_hypothesis["break_hypothesis_id"] = sha256_hex_of_obj(
        break_hypothesis, drop_keys={"created_at", "break_hypothesis_id"}
    )
    validate_object_with_binding(break_hypothesis)

    counterpressure_plan = {
        "schema_id": "kt.counterpressure_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.counterpressure_plan.v1.json"),
        "counterpressure_plan_id": "",
        "base_model_id": "mistral-7b",
        "optimization_suite_id": suite_id,
        "optimization_suite_root_hash": suite_root_hash,
        "adversarial_suite_id": "SUITE_X_ADV",
        "adversarial_suite_root_hash": "b" * 64,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "c" * 64,
        "break_hypothesis_id": break_hypothesis["break_hypothesis_id"],
        "required_probe_families": break_hypothesis["required_probe_families"],
        "created_at": created_at,
        "notes": None,
    }
    counterpressure_plan["counterpressure_plan_id"] = sha256_hex_of_obj(
        counterpressure_plan, drop_keys={"created_at", "counterpressure_plan_id"}
    )
    validate_object_with_binding(counterpressure_plan)

    fragility_probe_result = {
        "schema_id": "kt.fragility_probe_result.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.fragility_probe_result.v1.json"),
        "fragility_probe_result_id": "",
        "counterpressure_plan_id": counterpressure_plan["counterpressure_plan_id"],
        "status": "PASS",
        "reason_codes": [],
        "evaluated_adapter_root_hashes": ["1" * 64, "2" * 64],
        "probes": [
            {"probe_id": "P01", "family": "inversion_trap", "status": "PASS", "notes": None},
            {"probe_id": "P02", "family": "perturbation", "status": "PASS", "notes": None},
        ],
        "created_at": created_at,
        "notes": None,
    }
    fragility_probe_result["fragility_probe_result_id"] = sha256_hex_of_obj(
        fragility_probe_result, drop_keys={"created_at", "fragility_probe_result_id"}
    )
    validate_object_with_binding(fragility_probe_result)

    eval_admission = {
        "schema_id": "kt.evaluation_admission_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.evaluation_admission_receipt.v1.json"),
        "admission_receipt_id": "",
        "lane_id": "lab",
        "decision": "PASS",
        "reason_codes": [],
        "evaluation_plan_ref": "plan.json",
        "evaluation_plan_sha256": "d" * 64,
        "base_model_id": "mistral-7b",
        "suite_id": suite_id,
        "suite_root_hash": suite_root_hash,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "c" * 64,
        "suite_registry_ref": "KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json",
        "suite_registry_sha256": "e" * 64,
        "counterpressure_plan_ref": "counterpressure_plan.json",
        "counterpressure_plan_sha256": "f" * 64,
        "break_hypothesis_ref": "break_hypothesis.json",
        "break_hypothesis_sha256": "0" * 64,
        "law_bundle_hash": "1" * 64,
        "failure_taxonomy_id": "2" * 64,
        "created_at": created_at,
        "notes": None,
    }
    eval_admission["admission_receipt_id"] = sha256_hex_of_obj(eval_admission, drop_keys={"created_at", "admission_receipt_id"})
    validate_object_with_binding(eval_admission)

    law_change_admission = {
        "schema_id": "kt.law_change_admission_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_change_admission_receipt.v1.json"),
        "law_change_admission_receipt_id": "",
        "decision": "PASS",
        "reason_codes": [],
        "current_bundle_hash": "3" * 64,
        "requested_bundle_hash": "4" * 64,
        "law_bundle_change_receipt_ref": "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_CHANGE_RECEIPT_FL3_00000000T000000Z.json",
        "law_bundle_change_receipt_sha256": "5" * 64,
        "cooldown_seconds": 0,
        "created_at": created_at,
        "notes": None,
    }
    law_change_admission["law_change_admission_receipt_id"] = sha256_hex_of_obj(
        law_change_admission, drop_keys={"created_at", "law_change_admission_receipt_id"}
    )
    validate_object_with_binding(law_change_admission)

