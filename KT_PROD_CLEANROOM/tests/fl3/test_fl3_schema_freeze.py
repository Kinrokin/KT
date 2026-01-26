from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_path, schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402


SCHEMA_FILES = [
    "fl3/kt.factory.organ_contract.v1.json",
    "fl3/kt.global_budget_state.v1.json",
    "fl3/kt.global_unlock.v1.json",
    "fl3/kt.factory.jobspec.v1.json",
    "fl3/kt.factory.dataset.v1.json",
    "fl3/kt.factory.judgement.v1.json",
    "fl3/kt.factory.train_manifest.v1.json",
    "fl3/kt.factory.eval_report.v1.json",
    "fl3/kt.factory.promotion.v1.json",
    "fl3/kt.factory.freeze_receipt.v1.json",
    "fl3/kt.reasoning_trace.v1.json",
    "fl3/kt.tournament_manifest.v1.json",
    "fl3/kt.blind_judgement_pack.v1.json",
    "fl3/kt.reveal_mapping.v1.json",
    "fl3/kt.signal_quality.v1.json",
    "fl3/kt.failure_contract.v1.json",
    "fl3/kt.human_signoff.v1.json",
    "fl3/kt.law_amendment.v1.json",
]


def _hash_file(name: str) -> str:
    return schema_path(name.replace(".json", ".hash")).read_text(encoding="utf-8").strip()


def test_fl3_schema_hash_files_match() -> None:
    for name in SCHEMA_FILES:
        assert schema_version_hash(name) == _hash_file(name)


def _sha_id(record: dict, drop_keys: set[str]) -> str:
    payload = {k: v for k, v in record.items() if k not in drop_keys}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def test_fl3_schema_validates_examples() -> None:
    # organ_contract
    organ = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": {
            "run_job": {
                "path": "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py",
                "sha256": "0" * 64,
            }
        },
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only", "lora"],
        "allowed_output_schemas": ["kt.factory.jobspec.v1"],
        "allowed_export_roots": ["KT_PROD_CLEANROOM/exports/adapters", "KT_PROD_CLEANROOM/exports/adapters_shadow"],
        "created_at": "2026-01-01T00:00:00Z",
    }
    organ["contract_id"] = _sha_id(organ, {"created_at", "contract_id"})
    validate_object_with_binding(organ)

    # human_signoff
    signoff1 = {
        "schema_id": "kt.human_signoff.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v1.json"),
        "signoff_id": "",
        "key_id": "alice",
        "payload_hash": "b" * 64,
        "hmac_signature": "c" * 64,
        "created_at": "2026-01-01T00:00:00Z",
    }
    signoff1["signoff_id"] = _sha_id(signoff1, {"created_at", "signoff_id"})
    validate_object_with_binding(signoff1)

    signoff2 = dict(signoff1)
    signoff2["key_id"] = "bob"
    signoff2["signoff_id"] = _sha_id(signoff2, {"created_at", "signoff_id"})
    validate_object_with_binding(signoff2)

    # global_unlock
    unlock = {
        "schema_id": "kt.global_unlock.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_unlock.v1.json"),
        "unlock_id": "",
        "payload_hash": "d" * 64,
        "reason_codes": ["A", "B"],
        "signoffs": [signoff1, signoff2],
        "created_at": "2026-01-01T00:00:00Z",
    }
    unlock["unlock_id"] = _sha_id(unlock, {"created_at", "unlock_id"})
    validate_object_with_binding(unlock)

    # global_budget_state
    budget = {
        "schema_id": "kt.global_budget_state.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_budget_state.v1.json"),
        "day_utc": "2026-01-01",
        "gpu_hours_used": 0.0,
        "jobs_run": 0,
        "lock_state": "OPEN",
        "last_t1_failure": None,
    }
    validate_object_with_binding(budget)

    # jobspec
    jobspec = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "lobe.architect.v1",
        "adapter_version": "1",
        "role": "ARCHITECT",
        "mode": "SMOKE",
        "run_kind": "STANDARD",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": "KT_PROD_CLEANROOM/exports/adapters_shadow",
        "export_promoted_root": "KT_PROD_CLEANROOM/exports/adapters",
    }
    jobspec["job_id"] = _sha_id(jobspec, {"job_id"})
    validate_object_with_binding(jobspec)

    # dataset
    dataset = {
        "schema_id": "kt.factory.dataset.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.dataset.v1.json"),
        "dataset_id": "",
        "job_id": jobspec["job_id"],
        "rows": [{"prompt": "x", "response": "y"}],
        "created_at": "2026-01-01T00:00:00Z",
    }
    dataset["dataset_id"] = _sha_id(dataset, {"created_at", "dataset_id"})
    validate_object_with_binding(dataset)

    # judgement
    judgement = {
        "schema_id": "kt.factory.judgement.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.judgement.v1.json"),
        "judgement_id": "",
        "job_id": jobspec["job_id"],
        "dataset_id": dataset["dataset_id"],
        "accepted_row_ids": ["0"],
        "rejected_row_ids": [],
        "judge_ref": "policy_c",
        "created_at": "2026-01-01T00:00:00Z",
    }
    judgement["judgement_id"] = _sha_id(judgement, {"created_at", "judgement_id"})
    validate_object_with_binding(judgement)

    # train_manifest
    train_manifest = {
        "schema_id": "kt.factory.train_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.train_manifest.v1.json"),
        "train_id": "",
        "job_id": jobspec["job_id"],
        "dataset_id": dataset["dataset_id"],
        "base_model_id": jobspec["base_model_id"],
        "training_mode": jobspec["training_mode"],
        "output_bundle": {"artifact_path": "KT_PROD_CLEANROOM/exports/adapters_shadow/x", "artifact_hash": "3" * 64},
        "created_at": "2026-01-01T00:00:00Z",
    }
    train_manifest["train_id"] = _sha_id(train_manifest, {"created_at", "train_id"})
    validate_object_with_binding(train_manifest)

    # eval_report
    eval_report = {
        "schema_id": "kt.factory.eval_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.eval_report.v1.json"),
        "eval_id": "",
        "job_id": jobspec["job_id"],
        "adapter_id": jobspec["adapter_id"],
        "adapter_version": jobspec["adapter_version"],
        "battery_id": "kt.eval.battery.fl3.smoke.v1",
        "results": {"schema_valid": True},
        "final_verdict": "PASS",
        "created_at": "2026-01-01T00:00:00Z",
    }
    eval_report["eval_id"] = _sha_id(eval_report, {"created_at", "eval_id"})
    validate_object_with_binding(eval_report)

    # promotion
    promotion = {
        "schema_id": "kt.factory.promotion.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.promotion.v1.json"),
        "promotion_id": "",
        "job_id": jobspec["job_id"],
        "decision": "REJECT",
        "reasons": ["4" * 64],
        "links": {"dataset_id": dataset["dataset_id"], "eval_id": eval_report["eval_id"]},
        "created_at": "2026-01-01T00:00:00Z",
    }
    promotion["promotion_id"] = _sha_id(promotion, {"created_at", "promotion_id"})
    validate_object_with_binding(promotion)

    # freeze_receipt (even if registry_write null)
    freeze = {
        "schema_id": "kt.factory.freeze_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.freeze_receipt.v1.json"),
        "freeze_id": "",
        "job_id": jobspec["job_id"],
        "adapter_id": jobspec["adapter_id"],
        "adapter_version": jobspec["adapter_version"],
        "bundle_hash": "5" * 64,
        "eval_hash": eval_report["eval_id"],
        "promotion_hash": promotion["promotion_id"],
        "registry_write": None,
        "created_at": "2026-01-01T00:00:00Z",
    }
    freeze["freeze_id"] = _sha_id(freeze, {"created_at", "freeze_id"})
    validate_object_with_binding(freeze)

    # reasoning_trace
    trace = {
        "schema_id": "kt.reasoning_trace.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.reasoning_trace.v1.json"),
        "trace_id": "",
        "steps": [{"type": "FINAL", "content": "hash-only"}],
        "final_output_hash": "e" * 64,
        "created_at": "2026-01-01T00:00:00Z",
    }
    trace["trace_id"] = _sha_id(trace, {"created_at", "trace_id"})
    validate_object_with_binding(trace)

    # blind_judgement_pack
    blind_pack = {
        "schema_id": "kt.blind_judgement_pack.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.blind_judgement_pack.v1.json"),
        "pack_id": "",
        "job_id": jobspec["job_id"],
        "items": [{"prompt_hash": "f" * 64, "candidate_hash": "1" * 64}],
        "created_at": "2026-01-01T00:00:00Z",
    }
    blind_pack["pack_id"] = _sha_id(blind_pack, {"created_at", "pack_id"})
    validate_object_with_binding(blind_pack)

    # reveal_mapping (sealed)
    reveal = {
        "schema_id": "kt.reveal_mapping.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.reveal_mapping.v1.json"),
        "mapping_id": "",
        "job_id": jobspec["job_id"],
        "sealed": True,
        "verdict_ref": None,
        "mappings": {},
        "created_at": "2026-01-01T00:00:00Z",
    }
    reveal["mapping_id"] = _sha_id(reveal, {"created_at", "mapping_id"})
    validate_object_with_binding(reveal)

    # tournament_manifest
    tournament = {
        "schema_id": "kt.tournament_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_manifest.v1.json"),
        "tournament_id": "",
        "job_id": jobspec["job_id"],
        "blind_pack_ref": "vault://blind/" + blind_pack["pack_id"],
        "reveal_mapping_ref": "vault://reveal/" + reveal["mapping_id"],
        "created_at": "2026-01-01T00:00:00Z",
    }
    tournament["tournament_id"] = _sha_id(tournament, {"created_at", "tournament_id"})
    validate_object_with_binding(tournament)

    # signal_quality
    signal = {
        "schema_id": "kt.signal_quality.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.signal_quality.v1.json"),
        "adapter_id": jobspec["adapter_id"],
        "adapter_version": jobspec["adapter_version"],
        "risk_estimate": 0.1,
        "governance_strikes": 0,
        "status": "CANDIDATE",
        "created_at": "2026-01-01T00:00:00Z",
    }
    validate_object_with_binding(signal)

    # failure_contract
    failure = {
        "schema_id": "kt.failure_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.failure_contract.v1.json"),
        "tiers": {
            "T1": {"auto_action": "LOCK", "event_type": "FL3_T1_HARD_CORRUPTION"},
            "T2": {"auto_action": "QUARANTINE", "event_type": "FL3_T2_HARD_GOVERNANCE"},
            "T3": {"auto_action": "REBREED", "event_type": "FL3_T3_SOFT_DRIFT"},
            "T4": {"auto_action": "RETRY", "event_type": "FL3_T4_SOFT_PERF"},
        },
        "created_at": "2026-01-01T00:00:00Z",
    }
    validate_object_with_binding(failure)

    # law_amendment
    amendment = {
        "schema_id": "kt.law_amendment.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.law_amendment.v1.json"),
        "amendment_id": "",
        "bundle_hash": "2" * 64,
        "signoffs": [signoff1, signoff2],
        "created_at": "2026-01-01T00:00:00Z",
    }
    amendment["amendment_id"] = _sha_id(amendment, {"created_at", "amendment_id"})
    validate_object_with_binding(amendment)
