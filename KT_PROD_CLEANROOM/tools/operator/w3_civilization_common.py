from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from schemas.schema_files import schema_version_hash
from core.runtime_registry import load_runtime_registry
from council.providers.adapter_abi_runtime import REQUIRED_FIELDS as LIVE_MANIFEST_FIELDS
from council.providers.adapter_abi_runtime import load_active_adapter_manifests
from tools.governance.promotion_rationale_collector import ensure_promotion_rationale_for_job_dir
from tools.operator.titanium_common import repo_root, utc_now_iso_z
from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.training.fl3_factory.run_job import EXIT_OK, main as run_job_main
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_rollback_drill import run_rollback_drill


UNIVERSAL_ADAPTER_ABI_V2_REL = "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v2.json"
CIVILIZATION_LOOP_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/civilization_loop_contract.json"
ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
RUNTIME_REGISTRY_DOC_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"
W3_SHADOW_EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/adapters_shadow/_w3_civilization"
W3_PROMOTED_EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/adapters/_w3_civilization"
W3_WORK_ROOT_REL = "KT_PROD_CLEANROOM/exports/w3_civilization_loop"


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _write_json(path: Path, obj: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(obj), indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def build_w3_organ_contract(*, root: Path) -> Dict[str, Any]:
    run_job_rel = "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py"
    entrypoints = {
        "run_job": {
            "path": run_job_rel,
            "sha256": sha256_file_normalized(root / run_job_rel),
        }
    }
    contract = {
        "schema_id": "kt.factory.organ_contract.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.organ_contract.v1.json"),
        "contract_id": "",
        "entrypoints": entrypoints,
        "allowed_base_models": ["mistral-7b"],
        "allowed_training_modes": ["head_only"],
        "allowed_output_schemas": sorted(
            [
                "kt.factory.jobspec.v1",
                "kt.training_admission_receipt.v1",
                "kt.factory.dataset.v1",
                "kt.reasoning_trace.v1",
                "kt.factory.judgement.v1",
                "kt.factory.train_manifest.v1",
                "kt.policy_bundle.v1",
                "kt.factory.eval_report.v2",
                "kt.signal_quality.v1",
                "kt.immune_snapshot.v1",
                "kt.epigenetic_summary.v1",
                "kt.fitness_region.v1",
                "kt.factory.promotion.v1",
                "kt.factory.phase_trace.v1",
                "kt.hash_manifest.v1",
                "kt.factory.job_dir_manifest.v1",
                "kt.blind_judgement_pack.v1",
                "kt.reveal_mapping.v1",
                "kt.tournament_manifest.v1",
            ]
        ),
        "allowed_export_roots": [
            "KT_PROD_CLEANROOM/exports/adapters",
            "KT_PROD_CLEANROOM/exports/adapters_shadow",
        ],
        "created_at": "1970-01-01T00:00:00Z",
    }
    contract["contract_id"] = sha256_json({k: v for k, v in contract.items() if k not in {"created_at", "contract_id"}})
    return contract


def build_w3_budget_state() -> Dict[str, Any]:
    return {
        "schema_id": "kt.global_budget_state.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.global_budget_state.v1.json"),
        "day_utc": "2026-01-01",
        "gpu_hours_used": 0.0,
        "jobs_run": 0,
        "lock_state": "OPEN",
        "last_t1_failure": None,
    }


def _build_signal_quality() -> Dict[str, Any]:
    return {
        "schema_id": "kt.signal_quality.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.signal_quality.v1.json"),
        "adapter_id": "lobe.ancestor_stub.v1",
        "adapter_version": "0",
        "risk_estimate": 0.1,
        "governance_strikes": 0,
        "status": "PROMOTED",
        "created_at": "2026-01-01T00:00:00Z",
    }


def build_w3_jobspec(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    signal = _build_signal_quality()
    job = {
        "schema_id": "kt.factory.jobspec.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.jobspec.v1.json"),
        "job_id": "",
        "adapter_id": "lobe.architect.v1",
        "adapter_version": f"w3_{current_head[:12]}",
        "role": "ARCHITECT",
        "mode": "SOVEREIGN",
        "run_kind": "TOURNAMENT",
        "base_model_id": "mistral-7b",
        "training_mode": "head_only",
        "seed": 42,
        "export_shadow_root": W3_SHADOW_EXPORT_ROOT_REL,
        "export_promoted_root": W3_PROMOTED_EXPORT_ROOT_REL,
        "tournament": {
            "entrants": [
                {
                    "adapter_id": signal["adapter_id"],
                    "adapter_version": signal["adapter_version"],
                    "signal_quality": signal,
                }
            ],
            "max_risk": 0.5,
            "max_strikes": 0,
        },
    }
    job["job_id"] = sha256_json({k: v for k, v in job.items() if k != "job_id"})
    return job


def build_adapter_abi_v2(*, root: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.adapter_abi.v2",
        "contract_id": "KT_ADAPTER_ABI_V2_W3_CURRENT_HEAD",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "ACTIVE",
        "supersedes_ref": "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v1.json",
        "claim_boundary": (
            "W3 unifies the two active same-host live adapter manifests and one bounded generated mutation candidate "
            "under one universal contract. It does not claim broader live adapter breadth, runtime cutover, or "
            "externality widening."
        ),
        "required_live_manifest_fields": list(LIVE_MANIFEST_FIELDS) + ["request_type_allowlist"],
        "required_generated_candidate_fields": [
            "adapter_id",
            "adapter_kind",
            "version",
            "execution_mode",
            "policy_profile",
            "budget_profile",
            "provenance_requirements",
            "challenge_hooks",
            "provider_id",
            "timeout_ms",
            "retry_policy",
            "circuit_breaker_policy",
            "rate_limit_profile",
            "replayability_class",
            "status",
            "io_schema_ref",
            "request_type_allowlist",
            "admission_receipt_ref",
            "eval_report_ref",
            "signal_quality_ref",
            "fitness_region_ref",
            "promotion_ref",
            "phase_trace_ref",
            "hash_manifest_ref",
            "job_dir_manifest_ref",
        ],
        "projection_classes": [
            {
                "adapter_class": "LIVE_RUNTIME_PROVIDER",
                "activation_rule": "must_exist_in_runtime_registry_and_active_manifest_set",
                "evidence_class": "E1_SAME_HOST_DETACHED_REPLAY_OR_NARROWER",
            },
            {
                "adapter_class": "GENERATED_MUTATION_CANDIDATE",
                "activation_rule": "must_be_factory_generated_eval_pass_fitness_A_and_promotion_receipted",
                "evidence_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            },
        ],
        "universal_hard_rules": [
            "one_contract_only",
            "all_live_adapters_and_generated_candidates_must_be_receipt_bound",
            "generated_candidates_must_not_be_narrated_as_live_runtime_before_separate_cutover",
            "no_generated_candidate_may_widen_externality_class",
        ],
        "stronger_claims_not_made": [
            "all_inventory_adapters_are_live_runtime",
            "generated_candidate_is_already_canonical_runtime_cutover",
            "adapter_breadth_has_widened_above_the_two_live_same_host_providers",
        ],
    }


def build_civilization_loop_contract(*, root: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.civilization_loop_contract.v1",
        "contract_id": "KT_CIVILIZATION_LOOP_CONTRACT_W3_CURRENT_HEAD",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "ACTIVE",
        "claim_boundary": (
            "W3 proves one bounded current-head tournament, promotion-decision, rollback, and learning-response loop. "
            "It does not prove automatic runtime cutover, benchmark superiority, cross-host replay, or public competition readiness."
        ),
        "exact_loop": [
            "candidate_generation",
            "blind_tournament_pack",
            "judgement",
            "train_manifest",
            "eval_report",
            "signal_quality",
            "fitness_region",
            "promotion_decision",
            "promotion_rationale",
            "rollback_drill",
            "learning_response_receipt",
        ],
        "required_law_refs": [
            "KT_PROD_CLEANROOM/governance/tournament_law.json",
            "KT_PROD_CLEANROOM/governance/promotion_engine_law.json",
            "KT_PROD_CLEANROOM/governance/rollback_law.json",
            "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v2.json",
        ],
        "canonical_influence_rule": (
            "The loop is canonical as current-head evidence, but materialized runtime cutover remains separately gated. "
            "Promotion decision is real; automatic product or runtime widening remains forbidden."
        ),
        "forbidden_claims_not_made": [
            "generated_candidate_has_cut_over_the_active_runtime",
            "externality_class_has_widened_above_E1",
            "router_or_lobe_superiority_is_earned",
            "public_tournament_showability_is_unblocked",
        ],
    }


def _job_dir(root: Path, job: Mapping[str, Any]) -> Path:
    return (root / str(job["export_shadow_root"]) / str(job["job_id"])).resolve()


def _rollback_work_dir(root: Path, job: Mapping[str, Any]) -> Path:
    return (root / W3_WORK_ROOT_REL / "rollback" / str(job["job_id"])).resolve()


def _required_job_files() -> Iterable[str]:
    return (
        "job.json",
        "training_admission_receipt.json",
        "dataset.json",
        "reasoning_trace.json",
        "judgement.json",
        "train_manifest.json",
        "eval_report.json",
        "signal_quality.json",
        "immune_snapshot.json",
        "epigenetic_summary.json",
        "fitness_region.json",
        "promotion.json",
        "phase_trace.json",
        "hash_manifest.json",
        "job_dir_manifest.json",
        "blind_pack.json",
        "reveal_mapping.sealed.json",
        "reveal_mapping.json",
        "tournament_manifest.json",
    )


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _build_live_adapter_row(*, root: Path, manifest: Any) -> Dict[str, Any]:
    return {
        "adapter_id": manifest.adapter_id,
        "adapter_kind": manifest.adapter_kind,
        "version": manifest.version,
        "execution_mode": manifest.execution_mode,
        "policy_profile": manifest.policy_profile,
        "budget_profile": manifest.budget_profile,
        "provenance_requirements": list(manifest.provenance_requirements),
        "challenge_hooks": list(manifest.challenge_hooks),
        "provider_id": manifest.provider_id,
        "timeout_ms": manifest.timeout_ms,
        "retry_policy": dict(manifest.retry_policy),
        "circuit_breaker_policy": dict(manifest.circuit_breaker_policy),
        "rate_limit_profile": dict(manifest.rate_limit_profile),
        "replayability_class": manifest.replayability_class,
        "status": manifest.status,
        "io_schema_ref": manifest.io_schema_ref,
        "request_type_allowlist": list(manifest.request_type_allowlist),
        "adapter_class": "LIVE_RUNTIME_PROVIDER",
        "manifest_path_ref": _rel(root, manifest.manifest_path),
    }


def _build_generated_candidate_row(*, root: Path, cycle: Mapping[str, Any]) -> Dict[str, Any]:
    job = cycle["job"]
    return {
        "adapter_id": job["adapter_id"],
        "adapter_kind": "GENERATED_TOURNAMENT_CANDIDATE",
        "version": job["adapter_version"],
        "execution_mode": "GENERATED_TOURNAMENT",
        "policy_profile": "w3.current_head.civilization_loop",
        "budget_profile": "kt.global_budget_state.v1",
        "provenance_requirements": [
            "training_admission_receipt",
            "reasoning_trace",
            "eval_report",
            "signal_quality",
            "fitness_region",
            "promotion_receipt",
            "rollback_drill",
        ],
        "challenge_hooks": ["tournament", "promotion_decision", "rollback_drill", "learning_response"],
        "provider_id": "generated.fl3_factory",
        "timeout_ms": 20000,
        "retry_policy": {"max_attempts": 0},
        "circuit_breaker_policy": {"cooldown_ms": 0, "threshold": 1},
        "rate_limit_profile": {"max_calls_per_window": 1, "quota_cap": 1, "window_ms": 60000},
        "replayability_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
        "status": "GENERATED_PROMOTABLE_CANDIDATE" if cycle["promotion"]["decision"] == "PROMOTE" else "GENERATED_REJECTED_CANDIDATE",
        "io_schema_ref": "kt.factory.job_dir_manifest.v1",
        "request_type_allowlist": ["evaluation", "mutation", "tournament"],
        "adapter_class": "GENERATED_MUTATION_CANDIDATE",
        "admission_receipt_ref": f"{cycle['job_dir_ref']}/training_admission_receipt.json",
        "eval_report_ref": f"{cycle['job_dir_ref']}/eval_report.json",
        "signal_quality_ref": f"{cycle['job_dir_ref']}/signal_quality.json",
        "fitness_region_ref": f"{cycle['job_dir_ref']}/fitness_region.json",
        "promotion_ref": f"{cycle['job_dir_ref']}/promotion.json",
        "phase_trace_ref": f"{cycle['job_dir_ref']}/phase_trace.json",
        "hash_manifest_ref": f"{cycle['job_dir_ref']}/hash_manifest.json",
        "job_dir_manifest_ref": f"{cycle['job_dir_ref']}/job_dir_manifest.json",
    }


def required_live_manifest_fields() -> list[str]:
    return list(LIVE_MANIFEST_FIELDS) + ["request_type_allowlist"]


def validate_projection_fields(*, row: Mapping[str, Any], required_fields: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for field in required_fields:
        value = row.get(field)
        if value is None:
            missing.append(str(field))
            continue
        if isinstance(value, str) and not value.strip():
            missing.append(str(field))
        elif isinstance(value, (list, dict)) and not value:
            missing.append(str(field))
    return missing


def run_w3_cycle(*, root: Path | None = None) -> Dict[str, Any]:
    active_root = root or repo_root()
    contract = build_w3_organ_contract(root=active_root)
    budget = build_w3_budget_state()
    job = build_w3_jobspec(root=active_root)
    job_dir = _job_dir(active_root, job)
    if job_dir.exists():
        shutil.rmtree(job_dir)

    with tempfile.TemporaryDirectory() as td:
        temp_root = Path(td)
        job_path = temp_root / "job.json"
        contract_path = temp_root / "contract.json"
        budget_path = temp_root / "budget.json"
        _write_json(job_path, job)
        _write_json(contract_path, contract)
        _write_json(budget_path, budget)
        rc = int(run_job_main(["--job", str(job_path), "--organ-contract", str(contract_path), "--budget-state", str(budget_path)]))
        if rc != EXIT_OK:
            raise RuntimeError(f"FAIL_CLOSED: W3 factory cycle failed rc={rc}")

    missing = [name for name in _required_job_files() if not (job_dir / name).exists()]
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: W3 job_dir missing required artifacts: {sorted(missing)}")

    rationale = ensure_promotion_rationale_for_job_dir(job_dir=job_dir, lane_id="W3_CURRENT_HEAD")
    rollback_dir = _rollback_work_dir(active_root, job)
    rollback_report = run_rollback_drill(registry_path=(active_root / RUNTIME_REGISTRY_DOC_REL).resolve(), work_dir=rollback_dir)
    live_manifests = load_active_adapter_manifests()
    runtime_registry = load_runtime_registry()
    cycle = {
        "current_git_head": _git_head(active_root),
        "job": job,
        "contract": contract,
        "budget": budget,
        "job_dir": job_dir,
        "job_dir_ref": _rel(active_root, job_dir),
        "blind_pack": _load_json(job_dir / "blind_pack.json"),
        "reveal_mapping_sealed": _load_json(job_dir / "reveal_mapping.sealed.json"),
        "reveal_mapping": _load_json(job_dir / "reveal_mapping.json"),
        "tournament_manifest": _load_json(job_dir / "tournament_manifest.json"),
        "judgement": _load_json(job_dir / "judgement.json"),
        "train_manifest": _load_json(job_dir / "train_manifest.json"),
        "eval_report": _load_json(job_dir / "eval_report.json"),
        "signal_quality": _load_json(job_dir / "signal_quality.json"),
        "fitness_region": _load_json(job_dir / "fitness_region.json"),
        "promotion": _load_json(job_dir / "promotion.json"),
        "phase_trace": _load_json(job_dir / "phase_trace.json"),
        "hash_manifest": _load_json(job_dir / "hash_manifest.json"),
        "job_dir_manifest": _load_json(job_dir / "job_dir_manifest.json"),
        "promotion_rationale": rationale,
        "rollback_report": rollback_report,
        "rollback_work_dir_ref": _rel(active_root, rollback_dir),
        "runtime_registry_path_ref": RUNTIME_REGISTRY_DOC_REL,
        "live_manifests": {adapter_id: _build_live_adapter_row(root=active_root, manifest=manifest) for adapter_id, manifest in live_manifests.items()},
        "runtime_registry": runtime_registry,
    }
    cycle["generated_candidate"] = _build_generated_candidate_row(root=active_root, cycle=cycle)
    return cycle
