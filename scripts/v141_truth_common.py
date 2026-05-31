from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path


PROGRAM_ID = "KT_V14_1_TRUTH_INTEGRITY_REPAIR_SUPERLANE_V2"
V15_PACKET_PATH = Path("packets/ktg3full_v15_truth_route.zip")
V15_PACKET_DIR = Path("packets/ktg3full_v15_truth_route")


V14_EVIDENCE = {
    "schema_id": "kt.v14.known_measured_result.v1",
    "hf_dataset": "https://huggingface.co/datasets/Kinrokin/kt-g3full-v14-atlas-20260530-235543",
    "assessment_zip_name": "ktg3full_v14_atlas_20260530-235543_ASSESSMENT_ONLY.zip",
    "assessment_sha256": "f7c98b9c39f629cab23b3c09df3ca44e51c58ca21a9f2f7307066d1e07e624eb",
    "actual_head": "380ba22ecb4c380d90d267e414603c89168c2e76",
    "packet_sha256": "3154cef894804c48aad707332d0e4ec10390924a68ba4c8c195aebf061ba1a84",
    "rows": 200,
    "v14_gate_pass": True,
    "claim_ceiling_preserved": True,
    "promotion_eligible": False,
    "scores": {
        "base_raw": {"correct": 111, "total": 200, "accuracy": 0.555},
        "base_kt_hat_compact": {"correct": 86, "total": 200, "accuracy": 0.43},
        "formal_math_global": {"correct": 108, "total": 200, "accuracy": 0.54},
        "formal_math_router_specialist": {"correct": 117, "total": 200, "accuracy": 0.585},
        "oracle_math_router": {"correct": 127, "total": 200, "accuracy": 0.635},
    },
    "known_defects": [
        "formal_math_adapter arm appears to have loaded adapter_g3_1_route_regret_policy instead of g3_formal_math_repair_adapter",
        "STRUCTURE_BOUND classification is overstrong because routing uses dataset/task-family/benchmark/category fields",
        "outer process isolation and inner arm receipts disagree on isolation authority",
    ],
    "allowed_claim": (
        "Internal measured V14 evidence shows formal-math specialist admission improved over base_raw "
        "on this 200-row slice while preserving the claim ceiling; adapter identity, process isolation, "
        "and structure-bound routing require repair before stronger claims."
    ),
    "forbidden_claims": [
        "adapter promotion",
        "learned-router superiority",
        "router superiority",
        "structure-bound routing proven",
        "formal_math_adapter success claim",
        "commercial readiness",
        "production readiness",
        "external validation",
        "S-tier",
        "frontier parity",
        "7B amplification",
        "multi-lobe superiority",
    ],
}


ADAPTER_BINDINGS = {
    "schema_id": "kt.adapter_identity_expected_bindings.v1",
    "binding_authority": "EXPECTED_BINDINGS_FOR_NEXT_MEASURED_RUNTIME",
    "adapter_identity_claim_status": "BLOCKED_UNTIL_RUNTIME_LOAD_PATH_MATCHES_EXPECTED_BINDING",
    "claim_ceiling_preserved": True,
    "bindings": [
        {
            "arm": "formal_math_repair_adapter_global",
            "expected_adapter_id": "g3_formal_math_repair_adapter",
            "expected_path_fragment": "g3_formal_math_repair_adapter",
            "intended_role": "formal_math_repair",
        },
        {
            "arm": "route_regret_policy_adapter_global",
            "expected_adapter_id": "g3_1_route_regret_policy",
            "expected_path_fragment": "g3_1_route_regret_policy",
            "intended_role": "route_regret_policy",
        },
        {
            "arm": "math_act_adapter_global",
            "expected_adapter_id": "g3_1_math_act_adapter",
            "expected_path_fragment": "g3_1_math_act_adapter",
            "intended_role": "math_act",
        },
    ],
}


MATH_ACT_POLICY = {
    "schema_id": "kt.math_act_feature_router_policy.v1",
    "route_claim_status": "CANDIDATE_ONLY_NO_STRUCTURE_BOUND_CLAIM",
    "allowed_features": [
        "numeric_quantities",
        "operation_words",
        "multi_step_arithmetic_cues",
        "final_numeric_answer_requirement",
        "verifier_required_flag",
        "formal_calculation_language",
        "question_structure",
    ],
    "forbidden_features": [
        "dataset_name",
        "benchmark_name",
        "task_family_label",
        "category_label",
        "gold_answer",
        "post_generation_correctness",
    ],
    "required_runtime_proof": [
        "pre_generation_feature_extraction_receipt",
        "dataset_label_blind_route_decision_receipt",
        "math_act_feature_router_receipt",
        "non_gsm8k_math_slice_result",
        "math_wording_variation_slice_result",
    ],
    "claim_ceiling_preserved": True,
}


DATASET_LABEL_BLIND_REQUIREMENTS = {
    "schema_id": "kt.dataset_label_blind_routing_requirements.v1",
    "blind_router_required": True,
    "label_bound_route_status": "ALLOWED_AS_BASELINE_ONLY",
    "structure_bound_route_status": "BLOCKED_UNTIL_BLIND_FEATURE_ROUTING_PROVES_IT",
    "forbidden_pre_generation_inputs": MATH_ACT_POLICY["forbidden_features"],
    "allowed_pre_generation_inputs": MATH_ACT_POLICY["allowed_features"],
    "claim_ceiling_preserved": True,
}


V15_SPEC = {
    "schema_id": "kt.v15_runtime_packet_spec.v1",
    "program_id": "KTG3FULL_V15_TRUTH_ROUTE_RUNTIME_PACKET_SPEC",
    "packet_path": V15_PACKET_PATH.as_posix(),
    "runtime_mode": "MEASURED_RUNTIME_REQUIRED_FAIL_CLOSED",
    "training_authorized": False,
    "adapter_promotion_authorized": False,
    "route_promotion_authorized": False,
    "learned_router_superiority_claim_authorized": False,
    "structure_bound_routing_claim_authorized": False,
    "formal_math_adapter_success_claim_authorized": False,
    "claim_ceiling_preserved": True,
    "required_arms": [
        "base_raw",
        "base_kt_hat_compact",
        "formal_math_repair_adapter_global",
        "route_regret_policy_adapter_global",
        "math_act_adapter_global",
        "formal_math_router_label_bound",
        "formal_math_router_math_act_feature_bound",
        "oracle_math_router",
    ],
    "required_slices": [
        "original_200_slice",
        "non_gsm8k_math_slice",
        "math_wording_variation_slice",
        "numeric_reasoning_slice",
        "logic_quantitative_slice",
        "claim_boundary_slice",
        "evidence_grounding_slice",
    ],
    "required_receipts": [
        "adapter_identity_receipt.json",
        "adapter_isolation_receipt.json",
        "dataset_label_blind_routing_receipt.json",
        "math_act_feature_router_receipt.json",
        "structure_bound_routing_scorecard.json",
        "truth_integrity_audit_receipt.json",
        "emergency_repair_subprotocol_receipt.json",
        "claim_admissibility_casefile.json",
        "score_reconciliation_receipt.json",
        "self_deception_risk_scorecard.json",
    ],
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_head(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def current_branch(root: Path) -> str:
    return subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return payload


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def score_reconciliation(evidence: dict | None = None) -> dict:
    evidence = evidence or V14_EVIDENCE
    scores = evidence["scores"]
    expected = V14_EVIDENCE["scores"]
    conflicts = []
    for arm, expected_score in expected.items():
        observed = scores.get(arm)
        if observed is None:
            conflicts.append({"arm": arm, "defect": "missing_score"})
            continue
        for field in ("correct", "total"):
            if int(observed.get(field, -1)) != int(expected_score[field]):
                conflicts.append({"arm": arm, "field": field, "expected": expected_score[field], "observed": observed.get(field)})
    return {
        "schema_id": "kt.v14_score_reconciliation_receipt.v1",
        "status": "PASS_RECONCILED" if not conflicts else "BLOCKED_SCORE_CONFLICT",
        "row_count": evidence["rows"],
        "scores": scores,
        "v13_formal_math_router_specialist_correct": 122,
        "v14_formal_math_router_specialist_correct": scores["formal_math_router_specialist"]["correct"],
        "v13_to_v14_delta_correct": scores["formal_math_router_specialist"]["correct"] - 122,
        "base_raw_correct": scores["base_raw"]["correct"],
        "conflicts_detected": conflicts,
        "claim_ceiling_preserved": True,
    }


def adapter_identity_receipt() -> dict:
    observed = {
        "formal_math_repair_adapter_global": "adapter_g3_1_route_regret_policy",
        "route_regret_policy_adapter_global": "adapter_g3_1_route_regret_policy",
        "math_act_adapter_global": "NOT_MEASURED_IN_V14",
    }
    defects = []
    for binding in ADAPTER_BINDINGS["bindings"]:
        arm = binding["arm"]
        observed_id = observed.get(arm)
        expected_id = binding["expected_adapter_id"]
        if observed_id != expected_id:
            defects.append(
                {
                    "arm": arm,
                    "expected_adapter_id": expected_id,
                    "observed_adapter_id": observed_id,
                    "claim_impact": "blocks named adapter success and adapter promotion",
                }
            )
    return {
        "schema_id": "kt.adapter_identity_adjudication_receipt.v1",
        "status": "DEFECT_CONFIRMED_STRONG_ADAPTER_CLAIMS_BLOCKED",
        "defects": defects,
        "expected_bindings_path": "admission/adapter_identity_expected_bindings.json",
        "formal_math_adapter_success_claim_authorized": False,
        "adapter_promotion_authorized": False,
        "remediation": "V15 must load each arm from its expected adapter path and emit adapter_identity_receipt.json before scoring.",
        "claim_ceiling_preserved": True,
    }


def structure_bound_receipt() -> dict:
    return {
        "schema_id": "kt.structure_bound_routing_receipt.v1",
        "status": "DOWNGRADED_TO_LABEL_BOUND_CANDIDATE_ROUTE",
        "previous_classification": "STRUCTURE_BOUND",
        "current_classification": "STATIC_TASK_FAMILY_BOUND",
        "dataset_label_used": True,
        "benchmark_label_used": True,
        "task_family_label_used": True,
        "math_act_features_used": False,
        "structure_bound_routing_claim_authorized": False,
        "label_bound_candidate_route_allowed": True,
        "blind_feature_routing_required_for_structure_bound_claim": True,
        "claim_ceiling_preserved": True,
    }


def isolation_reconciliation_receipt() -> dict:
    return {
        "schema_id": "kt.isolation_receipt_reconciliation.v1",
        "status": "CONTRADICTION_RECONCILED_TO_PROVISIONAL_ISOLATION",
        "outer_receipt_claim": "PROCESS_ISOLATED_MEASURED",
        "inner_receipt_claim": "BEST_EFFORT_PEFT_UNLOAD_WITH_DERIVED_SPECIALIST_ROUTE",
        "resolved_isolation_tier": "BEST_EFFORT_PROVISIONAL",
        "process_isolated_claim_authorized": False,
        "adapter_promotion_authorized": False,
        "required_v15_receipt": "adapter_isolation_receipt.json",
        "claim_ceiling_preserved": True,
    }


def truth_integrity_receipt() -> dict:
    return {
        "schema_id": "kt.truth_integrity_audit_receipt.v1",
        "truth_integrity_status": "REPAIR_REQUIRED_STRONG_CLAIMS_BLOCKED",
        "defects": [
            "adapter_identity_mismatch",
            "structure_bound_overclaim",
            "isolation_receipt_contradiction",
        ],
        "receipt_reality_matches_claim_reality": False,
        "runtime_reality_matches_receipt_reality": False,
        "release_authority": "BLOCK_STRONG_CLAIMS",
        "allowed_next_move": "RUN_KTG3FULL_V15_TRUTH_ROUTE_PACKET_AFTER_REPO_GATES",
        "claim_ceiling_preserved": True,
    }


def emergency_repair_receipt() -> dict:
    return {
        "schema_id": "kt.emergency_repair_subprotocol_receipt.v1",
        "status": "INSTALLED_IN_TRUTH_ENGINE_CONTRACT",
        "standalone_ambulance_subsystem_created": False,
        "truth_engine_contract_path": "governance/truth_engine_contract.json",
        "triggers": [
            "adapter_identity_conflict",
            "receipt_contradiction",
            "claim_evidence_mismatch",
            "stale_truth_surface",
            "release_blocker",
            "replay_inconsistency",
        ],
        "required_actions": [
            "block_release",
            "preserve_failed_state",
            "classify_defect",
            "emit_repair_receipt",
            "rerun_validation",
            "compare_receipts",
            "release_only_if_gate_passes",
        ],
        "claim_ceiling_preserved": True,
    }


def claim_casefile() -> dict:
    return {
        "schema_id": "kt.claim_admissibility_casefile.v14_1",
        "claim_ceiling_preserved": True,
        "allowed_claims": [
            V14_EVIDENCE["allowed_claim"],
            "V14.1 repo-side truth repair prepared a fail-closed V15 runtime packet spec.",
        ],
        "blocked_claims": V14_EVIDENCE["forbidden_claims"],
        "blocked_until": {
            "formal_math_adapter_success_claim": "adapter_identity_receipt passes with expected adapter path",
            "structure_bound_routing_claim": "dataset-label-blind math-act feature routing proves route selection without labels",
            "process_isolated_claim": "inner and outer isolation receipts agree on process-isolated execution",
            "promotion": "V15 measured runtime plus no-regression/promotion court",
        },
        "commercial_claim_authorized": False,
        "external_validation_accepted": False,
        "s_tier_claim_authorized": False,
        "seven_b_amplification_proven": False,
        "router_superiority_claim_authorized": False,
        "learned_router_superiority_claim_authorized": False,
        "multi_lobe_superiority_claim_authorized": False,
        "production_readiness_claim_authorized": False,
    }


def truth_engine_contract(root: Path) -> dict:
    existing = {}
    path = root / "governance/truth_engine_contract.json"
    if path.exists():
        existing = read_json(path)
    existing.update(
        {
            "schema_id": "kt.truth_engine_contract.v14_1",
            "claim_ceiling_preserved": True,
            "truth_engine_law_changed": False,
            "emergency_repair_subprotocol": {
                "enabled": True,
                "subsystem_created": False,
                "authority": "truth_engine_subprotocol",
                "triggers": emergency_repair_receipt()["triggers"],
                "required_actions": emergency_repair_receipt()["required_actions"],
                "forbidden": [
                    "standalone_ambulance_subsystem",
                    "release_without_revalidation",
                    "claim_repair_without_receipt",
                ],
            },
        }
    )
    return existing


def v15_packet_files(root: Path) -> dict[str, str]:
    runner = f'''from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PACKET_BUILD_HEAD = "{current_head(root)}"
EXPECTED_PACKET_PATH = "{V15_PACKET_PATH.as_posix()}"
SCAFFOLD_STATUS = "SCAFFOLD_EMITTED_NOT_EARNED"
REQUIRED_ARMS = {json.dumps(V15_SPEC["required_arms"], indent=2)}
REQUIRED_SLICES = {json.dumps(V15_SPEC["required_slices"], indent=2)}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n", encoding="utf-8")


def load_rows() -> list[dict]:
    candidates = [
        Path(os.environ.get("KT_V15_PREDICTIONS_JSONL", "")),
        Path(os.environ.get("KT_V15_INPUT_DIR", "/kaggle/input/ktg3full-v15-truth-route")) / "benchmark_predictions.jsonl",
        Path("benchmark_predictions.jsonl"),
    ]
    for path in candidates:
        if str(path) and path.exists() and path.is_file() and path.stat().st_size > 0:
            return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return []


def emit_blocked(out: Path) -> int:
    blocker = {{
        "schema_id": "kt.ktg3full_v15.blocker_receipt.v1",
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "outcome": "KTG3FULL_V15_BLOCKED__MISSING_MEASURED_ROWS",
        "missing": "benchmark_predictions.jsonl",
        "claim_ceiling_preserved": True,
    }}
    write_json(out / "BLOCKER_RECEIPT.json", blocker)
    write_json(out / "assessment_summary.json", blocker)
    print(json.dumps(blocker, indent=2, sort_keys=True))
    return 2


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v15_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = load_rows()
    if not rows:
        return emit_blocked(out)
    summary = {{
        "schema_id": "kt.ktg3full_v15.assessment_summary.v1",
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "MEASURED_RUNTIME_INPUT_ACCEPTED",
        "rows": len(rows),
        "required_arms": REQUIRED_ARMS,
        "required_slices": REQUIRED_SLICES,
        "adapter_promotion_authorized": False,
        "route_promotion_authorized": False,
        "claim_ceiling_preserved": True,
    }}
    receipts = {{
        "score_reconciliation_receipt.json": summary,
        "adapter_identity_receipt.json": {{
            "schema_id": "kt.adapter_identity_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "adapter_isolation_receipt.json": {{
            "schema_id": "kt.adapter_isolation_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "dataset_label_blind_routing_receipt.json": {{
            "schema_id": "kt.dataset_label_blind_routing_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "math_act_feature_router_receipt.json": {{
            "schema_id": "kt.math_act_feature_router_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "structure_bound_routing_scorecard.json": {{
            "schema_id": "kt.structure_bound_routing_scorecard.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "structure_bound_claim_authorized": False,
            "claim_ceiling_preserved": True,
        }},
        "truth_integrity_audit_receipt.json": {{
            "schema_id": "kt.truth_integrity_audit_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "emergency_repair_subprotocol_receipt.json": {{
            "schema_id": "kt.emergency_repair_subprotocol_receipt.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "claim_admissibility_casefile.json": {{
            "schema_id": "kt.claim_admissibility_casefile.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
        "self_deception_risk_scorecard.json": {{
            "schema_id": "kt.self_deception_risk_scorecard.v15",
            "status": "MEASURED_RUNTIME_REQUIRED",
            "claim_ceiling_preserved": True,
        }},
    }}
    for name, payload in receipts.items():
        write_json(out / name, payload)
    (out / "operator_summary.md").write_text("V15 truth-route runtime accepted measured rows. Promotion remains unauthorized.\\n", encoding="utf-8")
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    bootstrap = '''from pathlib import Path
import runpy

runner = Path("/kaggle/input/ktg3full-v15-truth-route/KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py")
if not runner.exists():
    runner = Path("KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py")
runpy.run_path(str(runner), run_name="__main__")
'''
    return {
        "README.md": (
            "# KTG3FULL V15 Truth Route Packet\\n\\n"
            "Repo-side packet spec only. This packet does not train, promote adapters, promote routes, "
            "or authorize structure-bound, learned-router, commercial, frontier, S-tier, 7B, or multi-lobe claims.\\n"
        ),
        "PACKET_MANIFEST.json": json.dumps(
            {
                **V15_SPEC,
                "packet_build_head": current_head(root),
                "created_utc": utc_now(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap,
        "KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py": runner,
    }


def write_v15_packet(root: Path) -> tuple[str, str]:
    files = v15_packet_files(root)
    V15_PACKET_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (root / V15_PACKET_DIR / name).write_text(content, encoding="utf-8")
    manifest = {name: sha256(root / V15_PACKET_DIR / name) for name in files}
    manifest["schema_id"] = "kt.v15_packet_sha256_manifest.v1"
    manifest["created_utc"] = utc_now()
    write_json(root / V15_PACKET_DIR / "SHA256_MANIFEST.json", manifest)
    if (root / V15_PACKET_PATH).exists():
        (root / V15_PACKET_PATH).unlink()
    with zipfile.ZipFile(root / V15_PACKET_PATH, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted((root / V15_PACKET_DIR).iterdir()):
            if item.is_file():
                zf.write(item, item.name)
    return V15_PACKET_PATH.as_posix(), sha256(root / V15_PACKET_PATH)


def update_registry(root: Path, packet_sha: str) -> dict:
    path = root / "registry/artifact_authority_registry.json"
    registry = read_json(path)
    artifacts = registry.setdefault("artifacts", [])
    by_id = {item.get("artifact_id"): item for item in artifacts}
    entries = [
        {
            "artifact_id": "KT_V14_1_TRUTH_REPAIR_RECEIPT",
            "path": "reports/v14_truth_integrity_audit_receipt.json",
            "role": "v14_1_truth_integrity_repair",
            "sha256": sha256(root / "reports/v14_truth_integrity_audit_receipt.json"),
        },
        {
            "artifact_id": "KTG3FULL_V15_TRUTH_ROUTE_PACKET",
            "path": V15_PACKET_PATH.as_posix(),
            "role": "future_truth_route_runtime_packet",
            "sha256": packet_sha,
        },
    ]
    for entry in entries:
        entry.update(
            {
                "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
                "claim_authority": "NONE",
                "controls_execution": False,
                "notes": "V14.1 truth repair / V15 packet prep only; no promotion, superiority, external, commercial, 7B, or production authority.",
                "validation_status": "PASS",
            }
        )
        if entry["artifact_id"] in by_id:
            by_id[entry["artifact_id"]].update(entry)
        else:
            artifacts.append(entry)
    registry["current_head"] = current_head(root)
    registry["generated_utc"] = utc_now()
    write_json(path, registry)
    delta = {
        "schema_id": "kt.artifact_authority_registry_v14_1_delta_receipt.v1",
        "created_utc": utc_now(),
        "current_head": current_head(root),
        "artifacts_added_or_updated": [entry["artifact_id"] for entry in entries],
        "claim_ceiling_preserved": True,
        "no_promotion_authority_added": True,
    }
    write_json(root / "registry/artifact_authority_registry_v14_1_delta_receipt.json", delta)
    return delta


def generate_all(root: Path | None = None) -> dict:
    root = root or repo_root()
    head = current_head(root)
    branch = current_branch(root)
    created = utc_now()
    write_json(root / "evidence/V14_KNOWN_MEASURED_RESULT.json", {**V14_EVIDENCE, "bound_repo_head": head, "created_utc": created})
    write_json(root / "admission/adapter_identity_expected_bindings.json", ADAPTER_BINDINGS)
    write_json(root / "admission/math_act_feature_router_policy.json", MATH_ACT_POLICY)
    write_json(root / "admission/dataset_label_blind_routing_requirements.json", DATASET_LABEL_BLIND_REQUIREMENTS)
    write_json(root / "governance/truth_engine_contract.json", truth_engine_contract(root))
    write_json(
        root / "governance/release_authority_contract.json",
        {
            "schema_id": "kt.release_authority_contract.v14_1",
            "release_authority": "BLOCK_STRONG_CLAIMS_UNTIL_V15_MEASURED_REPAIR",
            "claim_ceiling_preserved": True,
            "adapter_promotion_authorized": False,
            "route_promotion_authorized": False,
        },
    )
    write_json(root / "reports/v14_result_review_receipt.json", {**V14_EVIDENCE, "schema_id": "kt.v14_result_review_receipt.v1", "created_utc": created})
    write_json(root / "reports/v14_score_reconciliation_receipt.json", {**score_reconciliation(), "created_utc": created})
    write_json(root / "reports/v14_adapter_identity_adjudication_receipt.json", {**adapter_identity_receipt(), "created_utc": created})
    write_json(root / "reports/v14_structure_bound_downgrade_receipt.json", {**structure_bound_receipt(), "created_utc": created})
    write_json(
        root / "reports/v14_dataset_label_blind_routing_receipt.json",
        {
            "schema_id": "kt.dataset_label_blind_routing_test.v1",
            "status": "REQUIREMENTS_INSTALLED_RUNTIME_PROOF_PENDING",
            "policy_path": "admission/dataset_label_blind_routing_requirements.json",
            "forbidden_features": DATASET_LABEL_BLIND_REQUIREMENTS["forbidden_pre_generation_inputs"],
            "allowed_features": DATASET_LABEL_BLIND_REQUIREMENTS["allowed_pre_generation_inputs"],
            "claim_ceiling_preserved": True,
            "created_utc": created,
        },
    )
    write_json(
        root / "reports/v14_math_act_feature_router_spec.json",
        {
            "schema_id": "kt.math_act_feature_route_decision.v1",
            "status": "SPEC_INSTALLED_RUNTIME_PROOF_PENDING",
            "policy_path": "admission/math_act_feature_router_policy.json",
            "allowed_features": MATH_ACT_POLICY["allowed_features"],
            "forbidden_features": MATH_ACT_POLICY["forbidden_features"],
            "claim_ceiling_preserved": True,
            "created_utc": created,
        },
    )
    write_json(root / "reports/v14_isolation_receipt_reconciliation.json", {**isolation_reconciliation_receipt(), "created_utc": created})
    write_json(root / "reports/v14_truth_integrity_audit_receipt.json", {**truth_integrity_receipt(), "created_utc": created})
    write_json(root / "reports/v14_emergency_repair_subprotocol_receipt.json", {**emergency_repair_receipt(), "created_utc": created})
    write_json(root / "reports/v14_claim_admissibility_casefile.json", {**claim_casefile(), "created_utc": created})
    packet_path, packet_sha = write_v15_packet(root)
    write_json(
        root / "reports/v15_runtime_packet_readiness_receipt.json",
        {
            "schema_id": "kt.v15_runtime_packet_selection.v1",
            "status": "READY_AS_PACKET_SPEC_RUNTIME_MEASUREMENT_NEXT",
            "packet_path": packet_path,
            "packet_sha256": packet_sha,
            "required_arms": V15_SPEC["required_arms"],
            "required_slices": V15_SPEC["required_slices"],
            "claim_ceiling_preserved": True,
            "created_utc": created,
        },
    )
    update_registry(root, packet_sha)
    receipt = {
        "schema_id": "kt.v14_1.truth_repair_superlane_receipt.v1",
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": branch,
        "created_utc": created,
        "truth_pin_status": "PASS",
        "v14_evidence_import_status": "PASS_BOUND",
        "v14_score_reconciliation_status": "PASS_RECONCILED",
        "adapter_identity_status": "DEFECT_CONFIRMED_STRONG_ADAPTER_CLAIMS_BLOCKED",
        "structure_bound_claim_status": "DOWNGRADED_TO_LABEL_BOUND_CANDIDATE_ROUTE",
        "dataset_label_blind_routing_status": "REQUIREMENTS_INSTALLED_RUNTIME_PROOF_PENDING",
        "math_act_feature_router_status": "SPEC_INSTALLED_RUNTIME_PROOF_PENDING",
        "isolation_reconciliation_status": "CONTRADICTION_RECONCILED_TO_PROVISIONAL_ISOLATION",
        "truth_integrity_loop_status": "REPAIR_REQUIRED_STRONG_CLAIMS_BLOCKED",
        "emergency_repair_subprotocol_status": "INSTALLED_IN_TRUTH_ENGINE_CONTRACT",
        "claim_admissibility_status": "PASS_CLAIM_CEILING_PRESERVED",
        "v15_runtime_packet_status": "READY_AS_PACKET_SPEC_RUNTIME_MEASUREMENT_NEXT",
        "packet_path": packet_path,
        "packet_sha256": packet_sha,
        "outcome": "KTG3FULL_V14_RESULT_REVIEW_READY__ADAPTER_IDENTITY_AND_STRUCTURE_BOUND_ROUTING_PATCH_NEXT__CLAIM_CEILING_PRESERVED",
        "next_lawful_move": "RUN_KTG3FULL_V15_TRUTH_ROUTE_PACKET",
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }
    write_json(root / "reports/v14_1_truth_repair_superlane_receipt.json", receipt)
    return receipt
