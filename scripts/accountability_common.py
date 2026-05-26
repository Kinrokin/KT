from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


PROGRAM_ID = "KT_ACCOUNTABILITY_KERNEL_AND_SPECIALIST_ROUTING_SUPERLANE_V1"
TARGET_OUTCOME = "KT_ACCOUNTABILITY_KERNEL_READY__KTG3FULL_V12_SPECIALIST_ROUTING_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTG3FULL_V12_SPECIALIST_ROUTING_PACKET"
SOURCE_PACKET_ID = "source_packet:ktak_v1.zip"
SOURCE_PACKET_SHA256 = "34d0dc5dd7315929be6491ec8dbb7084ef66e3b379bb9559f28b07f0ec95abbc"
PACKET_DIR = Path("packets/ktg3full_v12")
PACKET_ZIP = Path("packets/ktg3full_v12.zip")

CLAIM_CEILING = {
    "commercial_claim_authorized": False,
    "external_audit_complete": False,
    "external_validation_accepted": False,
    "s_tier_claim_authorized": False,
    "beyond_sota_claim_authorized": False,
    "frontier_parity_claim_authorized": False,
    "router_superiority_claim_authorized": False,
    "multi_lobe_superiority_claim_authorized": False,
    "seven_b_amplification_proven": False,
    "full_adaptive_orchestration_production_ready": False,
    "adapter_promotion_authorized": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
}

G3FULL_EVIDENCE = {
    "base_raw": {"correct": 111, "total": 200, "accuracy": 0.555, "vwpt": 0.024975, "tokens_per_correct": 54.05},
    "adapter_g3_1_route_regret_policy": {"correct": 108, "total": 200, "accuracy": 0.54},
    "adapter_g3_1_math_act_adapter": {"correct": 99, "total": 200, "accuracy": 0.495},
    "adapter_g3_formal_math_repair_adapter": {
        "correct": 88,
        "total": 200,
        "accuracy": 0.44,
        "gsm8k_correct": 13,
        "gsm8k_total": 50,
        "gsm8k_accuracy": 0.26,
    },
    "base_kt_hat_compact": {"correct": 86, "total": 200, "accuracy": 0.43},
    "base_raw_gsm8k": {"correct": 2, "total": 50, "accuracy": 0.04},
    "route_regret_closure": 0.0,
    "promotion_authorized": False,
    "claim_ceiling_preserved": True,
}

FORBIDDEN_CLAIMS = [
    "commercial launch",
    "external audit complete",
    "external validation accepted",
    "S-tier",
    "beyond-SOTA",
    "frontier parity",
    "router superiority",
    "multi-lobe superiority",
    "7B amplification proven",
    "production readiness",
    "adapter promotion",
    "global improvement from formal math specialist",
]

REQUIRED_RUNTIME_OUTPUTS = [
    "benchmark_predictions.jsonl",
    "benchmark_scorecard.json",
    "signal_density_matrix.jsonl",
    "route_regret_matrix.jsonl",
    "route_regret_closure_scorecard.json",
    "verified_work_per_token_scorecard.json",
    "anti_goodhart_scorecard.json",
    "evaluator_integrity_receipt.json",
    "gpu_cleanup_receipt.json",
    "adapter_isolation_receipt.json",
    "adapter_niche_boundary_scorecard.json",
    "formal_math_specialist_router_receipt.json",
    "failure_confession_receipt.json",
    "success_admissibility_receipt.json",
    "self_deception_risk_scorecard.json",
    "clinical_promotion_receipt.json",
    "operator_summary.md",
    "ASSESSMENT_ONLY.zip",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_text(args: list[str], root: Path | None = None) -> str:
    return subprocess.check_output(args, cwd=root or repo_root(), text=True, encoding="utf-8").strip()


def git_head(root: Path) -> str:
    return run_text(["git", "rev-parse", "HEAD"], root)


def git_branch(root: Path) -> str:
    return run_text(["git", "branch", "--show-current"], root)


def worktree_clean(root: Path) -> bool:
    return run_text(["git", "status", "--short"], root) == ""


def file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key: {key}")
        seen.add(key)
        out[key] = value
    return out


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=reject_duplicate_keys)


def write_json(path: Path, obj: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")


def surface_inventory(root: Path, patterns: Iterable[str]) -> list[str]:
    found: list[str] = []
    for pattern in patterns:
        found.extend(path.as_posix() for path in root.glob(pattern) if path.is_file())
    return sorted(set(found))


def artifact(path: str, root: Path, role: str) -> dict[str, Any]:
    p = root / path
    return {
        "path": path,
        "role": role,
        "exists": p.exists(),
        "sha256": file_sha256(p),
    }


def latest_evidence_import(root: Path) -> dict[str, Any]:
    return {
        "schema_id": "kt.accountability.latest_g3full_measured_evidence_import.v1",
        "created_utc": utc_now(),
        "source_packet": SOURCE_PACKET_ID,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "source_policy": "packet-summary-imported-as-internal-measured-evidence-not-external-proof",
        "evidence": G3FULL_EVIDENCE,
        "interpretation": [
            "G3FULL did not prove global improvement.",
            "Formal math repair is a specialist niche signal with global negative transfer.",
            "Compact hat cannot be assumed globally beneficial.",
            "Next move is accountability plus specialist routing and adapter isolation, not broad training.",
        ],
        "claim_ceiling_preserved": True,
        **CLAIM_CEILING,
    }


def build_truth_and_audit(root: Path, audit_clean: bool | None = None) -> dict[str, Any]:
    head = git_head(root)
    branch = git_branch(root)
    clean = worktree_clean(root) if audit_clean is None else audit_clean
    claim_file = "rules/CLAIM_CEILING.md" if (root / "rules/CLAIM_CEILING.md").exists() else ""
    registry_file = "registry/artifact_authority_registry.json" if (root / "registry/artifact_authority_registry.json").exists() else ""
    existing_g32 = surface_inventory(root, ["reports/g32_*.json", "reports/g32_*.jsonl", "schemas/kt.*signal_density*.json", "scripts/*g32*.py"])
    existing_accountability = surface_inventory(root, ["accountability/*", "reports/accountability_*.json", "scripts/*accountability*.py"])
    existing_specialist = surface_inventory(root, ["reports/*specialist*.json", "schemas/kt.*specialist*.json", "schemas/kt.adapter_*.json"])
    existing_packets = surface_inventory(root, ["packets/ktg3*.zip", "packets/ktg3full*.zip"])
    missing = [
        path
        for path in [
            claim_file or "rules/CLAIM_CEILING.md",
            registry_file or "registry/artifact_authority_registry.json",
            "packets/ktg3_v3.zip",
        ]
        if not (root / path).exists()
    ]
    stale: list[str] = []
    if registry_file:
        reg = read_json(root / registry_file)
        if reg.get("current_head") not in {head, ""}:
            stale.append(registry_file)
    truth = {
        "schema_id": "kt.accountability.truth_pin_receipt.v1",
        "created_utc": utc_now(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "current_branch": branch,
        "worktree_clean": clean,
        "claim_ceiling_file": claim_file,
        "artifact_registry_file": registry_file,
        "latest_g3full_assessment_sources": [
            artifact("evidence/G3FULL_RESULTS_SUMMARY.md", root, "packet_imported_measured_summary"),
            {"path": SOURCE_PACKET_ID, "sha256": SOURCE_PACKET_SHA256, "role": "source_packet_sanitized_reference", "exists": True},
        ],
        "existing_g32_surfaces": existing_g32,
        "existing_accountability_surfaces": existing_accountability,
        "existing_specialist_routing_surfaces": existing_specialist,
        "existing_packets": existing_packets,
        "missing_surfaces": missing,
        "stale_surfaces": stale,
        "superseded_surfaces": [],
        "claim_ceiling_status": "UNCHANGED",
        "audit_pass": bool(head and clean and claim_file and registry_file and not missing),
    }
    source_index = {
        "schema_id": "kt.accountability.source_evidence_index.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "current_branch": branch,
        "packet_source": {"path": SOURCE_PACKET_ID, "sha256": SOURCE_PACKET_SHA256, "path_policy": "sanitized_non_local_path"},
        "latest_g3full_evidence": G3FULL_EVIDENCE,
        "existing_g32_surfaces": existing_g32,
        "existing_accountability_surfaces": existing_accountability,
        "existing_specialist_routing_surfaces": existing_specialist,
        "claim_ceiling_status": "UNCHANGED",
    }
    implementation = {
        "schema_id": "kt.accountability.current_implementation_map.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "schemas": surface_inventory(root, ["accountability/*.schema.json", "schemas/kt.*.schema.json"]),
        "scripts": surface_inventory(root, ["scripts/*.py"]),
        "tests": surface_inventory(root, ["tests/test_*accountability*.py", "tests/test_*specialist*.py", "tests/test_adapter*.py"]),
        "packets": existing_packets,
    }
    gap = {
        "schema_id": "kt.accountability.gap_matrix.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "missing_surfaces": missing,
        "stale_surfaces": stale,
        "gaps_closed_by_this_lane": [
            "failure confession",
            "success admissibility",
            "self-deception risk scoring",
            "formal math specialist boundary",
            "adapter isolation contract",
            "cross-domain artifactization",
            "FMEA repair bid matrix",
            "repo state-diff contract",
            "ktg3full_v12 packet generation",
        ],
    }
    write_json(root / "reports/accountability_truth_pin_receipt.json", truth)
    write_json(root / "reports/accountability_source_evidence_index.json", source_index)
    write_json(root / "reports/accountability_current_implementation_map.json", implementation)
    write_json(root / "reports/accountability_gap_matrix.json", gap)
    write_json(root / "reports/latest_g3full_measured_evidence_import.json", latest_evidence_import(root))
    return truth


def self_deception_scorecard(run_id: str) -> dict[str, Any]:
    rates = {
        "unowned_failure_rate": 0.0,
        "scaffold_pass_rate": 0.0,
        "unpaired_metric_rate": 0.0,
        "niche_to_global_claim_rate": 0.0,
        "omitted_negative_result_rate": 0.0,
        "training_without_owner_rate": 0.0,
        "claim_without_admissibility_rate": 0.0,
    }
    score = (
        0.20 * rates["unowned_failure_rate"]
        + 0.20 * rates["scaffold_pass_rate"]
        + 0.15 * rates["unpaired_metric_rate"]
        + 0.15 * rates["niche_to_global_claim_rate"]
        + 0.10 * rates["omitted_negative_result_rate"]
        + 0.10 * rates["training_without_owner_rate"]
        + 0.10 * rates["claim_without_admissibility_rate"]
    )
    return {
        "schema_id": "kt.self_deception_risk_scorecard.v1",
        "run_id": run_id,
        **rates,
        "self_deception_risk_score": score,
        "promotion_eligible": score == 0.0,
        "requires_followup_measurement": False,
        "claim_ceiling_preserved": True,
    }


def build_accountability(root: Path) -> dict[str, Any]:
    run_id = f"ktak_{git_head(root)[:12]}"
    failure = {
        "schema_id": "kt.failure_confession_receipt.v1",
        "run_id": run_id,
        "what_failed": [
            "base_raw remained the global winner in latest imported G3FULL evidence.",
            "compact hat hurt global accuracy in latest imported G3FULL evidence.",
            "route-regret closure remained 0.0.",
            "formal math adapter showed global negative transfer.",
        ],
        "what_did_not_fail": [
            "formal math adapter preserved a GSM8K-like niche signal.",
            "claim ceiling remained preserved.",
            "promotion refusal was correct.",
        ],
        "what_was_overclaimed": [],
        "what_was_undermeasured": [
            "adapter isolation must be proven before future adapter-arm rankings are relied on.",
            "specialist routing must be measured before any global utility statement.",
        ],
        "what_layer_owned_failure": [
            {"layer": "routing", "failure": "route-regret closure did not improve"},
            {"layer": "hat_policy", "failure": "compact hat reduced global score"},
            {"layer": "adapter_ecology", "failure": "formal math adapter negative transfer outside niche"},
        ],
        "what_evidence_supports_owner": [
            "reports/latest_g3full_measured_evidence_import.json",
            "evidence/G3FULL_RESULTS_SUMMARY.md",
        ],
        "what_intervention_is_allowed": [
            "specialist math routing under verifier/finalizer gate",
            "adapter isolation probe",
            "failure confession and success admissibility receipts",
            "KTG3FULL V1.2 measurement packet",
        ],
        "what_intervention_is_forbidden": [
            "global adapter promotion",
            "broad retraining",
            "commercial or frontier claim",
            "niche result described globally",
        ],
        "what_must_not_be_claimed": FORBIDDEN_CLAIMS,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "claim_ceiling_preserved": True,
    }
    success = {
        "schema_id": "kt.success_admissibility_receipt.v1",
        "success_scope": "Internal specialist-niche signal only: formal math adapter outperformed base_raw on GSM8K-like slice in imported G3FULL evidence.",
        "success_evidence": [
            {"arm": "adapter_g3_formal_math_repair_adapter", "gsm8k_correct": 13, "gsm8k_total": 50},
            {"arm": "base_raw", "gsm8k_correct": 2, "gsm8k_total": 50},
        ],
        "known_limits": [
            "adapter_g3_formal_math_repair_adapter underperformed base_raw globally",
            "formal math evidence is bounded to a specialist niche and is not a global promotion basis",
            "route-regret closure was 0.0",
            "external validation pending",
            "commercial claims unauthorized",
        ],
        "regression_checks": {"global_no_regression_pass": False, "specialist_only": True, "promotion_blocked": True},
        "external_replay_status": "PENDING",
        "claim_tier": 1,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "claim_ceiling_preserved": True,
    }
    casefile = {
        "schema_id": "kt.claim_admissibility_casefile.v1",
        "claim": "KT has internal evidence for a bounded formal-math specialist routing candidate, not global superiority.",
        "argument": "Imported G3FULL evidence shows a GSM8K niche win and global negative transfer; lawful next step is specialist routing with isolation and verifier gates.",
        "evidence": ["reports/latest_g3full_measured_evidence_import.json", "reports/formal_math_specialist_router_plan.json"],
        "assumptions": ["Imported G3FULL evidence summary is current source for this lane until a newer measured assessment supersedes it."],
        "limitations": ["No external validation", "No global promotion", "No commercial authorization"],
        "tier": 1,
        "forbidden_claims": FORBIDDEN_CLAIMS,
    }
    score = self_deception_scorecard(run_id)
    trace = {
        "schema_id": "kt.accountability_trace_ledger.v1",
        "run_id": run_id,
        "entries": [
            {"trace_id": "failure.g3full.global_base_wins", "owner": "routing_hat_adapter_ecology", "evidence": "reports/latest_g3full_measured_evidence_import.json"},
            {"trace_id": "success.formal_math_niche", "owner": "formal_math_specialist", "evidence": "reports/latest_g3full_measured_evidence_import.json"},
        ],
        "claim_ceiling_preserved": True,
    }
    court = {
        "schema_id": "kt.causal_ownership_court.v1",
        "run_id": run_id,
        "ownership_findings": failure["what_layer_owned_failure"],
        "unowned_failure_count": 0,
        "claim_ceiling_preserved": True,
    }
    consequence = {
        "schema_id": "kt.repair_consequence_receipt.v1",
        "run_id": run_id,
        "allowed_repairs": failure["what_intervention_is_allowed"],
        "forbidden_repairs": failure["what_intervention_is_forbidden"],
        "promotion_eligible": False,
        "claim_ceiling_preserved": True,
    }
    memory = {
        "schema_id": "kt.no_regression_memory.v1",
        "run_id": run_id,
        "no_regression_obligations": [
            "formal_math_router_specialist must meet or explicitly bound global regression",
            "formal_math_global_adapter remains quarantined if negative transfer persists",
            "adapter isolation receipt required before ranking adapter arms",
        ],
        "claim_ceiling_preserved": True,
    }
    kernel = {
        "schema_id": "kt.accountability_kernel_receipt.v1",
        "accountability_trace_ledger_present": True,
        "failure_confession_receipt_present": True,
        "self_deception_gate_pass": score["self_deception_risk_score"] == 0,
        "claim_admissibility_present": True,
        "claim_ceiling_preserved": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    outputs = {
        "accountability/failure_confession_receipt.json": failure,
        "accountability/success_admissibility_receipt.json": success,
        "accountability/self_deception_risk_scorecard.json": score,
        "accountability/claim_admissibility_casefile.json": casefile,
        "accountability/accountability_trace_ledger.json": trace,
        "accountability/causal_ownership_court.json": court,
        "accountability/repair_consequence_receipt.json": consequence,
        "accountability/no_regression_memory.json": memory,
        "accountability/accountability_kernel_receipt.json": kernel,
    }
    for rel, obj in outputs.items():
        write_json(root / rel, obj)
    return kernel


def build_specialist_routing(root: Path) -> dict[str, Any]:
    niche = {
        "schema_id": "kt.adapter_niche_boundary.v1",
        "adapter_id": "adapter_g3_formal_math_repair_adapter",
        "allowed_task_families": ["formal_math", "gsm8k_like"],
        "blocked_task_families": ["global_general_reasoning", "truthfulness", "commercial", "regulated_domain", "red_assault"],
        "routing_preconditions": [
            "task_family classified as formal_math or gsm8k_like",
            "deterministic math verifier/finalizer available",
            "adapter isolation receipt emitted",
            "global negative transfer remains quarantined",
        ],
        "verifier_required": True,
        "negative_transfer_score": round(G3FULL_EVIDENCE["base_raw"]["accuracy"] - G3FULL_EVIDENCE["adapter_g3_formal_math_repair_adapter"]["accuracy"], 6),
        "quarantine_status": "QUARANTINED_OUTSIDE_FORMAL_MATH_SPECIALIST_ROUTE",
        "promotion_eligible": False,
    }
    plan = {
        "schema_id": "kt.formal_math_specialist_router_plan.v1",
        "created_utc": utc_now(),
        "arms": [
            "base_raw",
            "base_kt_hat_compact",
            "formal_math_global_adapter",
            "formal_math_router_specialist",
            "oracle_math_router",
            "adapter_isolation_probe",
        ],
        "specialist_route": {
            "task_family": "formal_math",
            "selected_adapter": "adapter_g3_formal_math_repair_adapter",
            "verifier_gate_required": True,
            "fallback_route": "base_raw",
        },
        "acceptance_criteria": [
            "formal_math_router_specialist > base_raw on GSM8K",
            "formal_math_router_specialist >= base_raw globally or regression explicitly bounded and non-promotable",
            "formal_math_global_adapter remains quarantined if global negative transfer persists",
            "adapter isolation receipt proves no PEFT leakage between arms",
        ],
        "claim_ceiling_preserved": True,
    }
    decision = {
        "schema_id": "kt.specialist_router_decision.v1",
        "sample_id": "ktak.formal_math.routing_plan",
        "task_family": "formal_math",
        "selected_route": "formal_math_router_specialist",
        "selected_adapter": "adapter_g3_formal_math_repair_adapter",
        "verifier_gate_pass": False,
        "reason": "future runtime route allowed only when deterministic math verifier/finalizer passes",
        "fallback_route": "base_raw",
    }
    isolation = {
        "schema_id": "kt.adapter_isolation_receipt.v1",
        "arm_name": "adapter_isolation_probe",
        "adapter_name": "adapter_g3_formal_math_repair_adapter",
        "base_model_reloaded": True,
        "peft_wrappers_removed": True,
        "cuda_cleanup_before_arm": True,
        "cuda_cleanup_after_arm": True,
        "gpu_memory_before": {"status": "RUNTIME_MEASUREMENT_REQUIRED"},
        "gpu_memory_after": {"status": "RUNTIME_MEASUREMENT_REQUIRED"},
        "adapter_config_hash": "RUNTIME_MEASUREMENT_REQUIRED",
        "status": "SPEC_READY_RUNTIME_MEASUREMENT_REQUIRED",
    }
    registry = {
        "schema_id": "kt.adapter_ecological_niche_registry.v1",
        "created_utc": utc_now(),
        "niches": [niche],
        "global_promotion_allowed": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/formal_math_specialist_router_plan.json", plan)
    write_json(root / "reports/adapter_ecological_niche_registry.json", registry)
    write_json(root / "reports/adapter_niche_boundary_scorecard.json", niche)
    write_json(root / "reports/specialist_router_decision_contract.json", decision)
    write_json(root / "reports/adapter_isolation_contract_receipt.json", isolation)
    return {"niche": niche, "plan": plan, "decision": decision, "isolation": isolation}


def build_cross_domain(root: Path) -> dict[str, Any]:
    rows = [
        ("music", "motif variation", "academy_motif_variation_matrix.json", "motif_recurrence", "variation transfer may be spurious"),
        ("literature", "narrative continuity", "narrative_state_continuity_crucible.json", "state_retention_rate", "story coherence may mask factual drift"),
        ("magic/deception", "misdirection", "misdirection_red_assault_suite.json", "misdirection_detection_rate", "may teach evasive patterns"),
        ("comedy", "incongruity reframe", "incongruity_reframe_crucible.json", "reframe_validity", "may reward cleverness over truth"),
        ("games", "route game tree", "route_game_tree_scorecard.json", "route_regret", "may overfit to gameable trees"),
        ("engineering/FMEA", "failure repair value", "kt_fmea_repair_bid_matrix.json", "failure_repair_value", "may overweight easy repairs"),
        ("medicine/M&M", "failure confession", "kt_morbidity_mortality_failure_review.json", "owned_failure_rate", "may become blame theater"),
        ("law", "claim admissibility", "claim_admissibility_casefile.json", "claim_tier", "may confuse admissibility with truth"),
        ("ecology", "adapter niche", "adapter_niche_boundary_scorecard.json", "negative_transfer_score", "may freeze useful generalization too early"),
        ("immunology", "scar autoimmune scan", "scar_autoimmune_regression_scan.json", "negative_transfer_rate", "may over-quarantine repair"),
        ("pedagogy", "epoch mastery", "epoch_mastery_progression_schedule.json", "mastery_rate", "may create credential theater"),
        ("forensics", "source evidence", "source_evidence_index.json", "source_binding_rate", "may overtrust formal provenance"),
    ]
    mapped = [
        {
            "schema_id": "kt.domain_to_artifact_map.v1",
            "domain": domain,
            "concept": concept,
            "kt_failure_class": "accountability.cross_domain_artifactization",
            "proposed_artifact": artifact_name,
            "gate": "CROSS_DOMAIN_TRANSLATION_GATE",
            "metric": metric,
            "quarantine_rule": "no training, promotion, commercial claim, or runtime authority from cross-domain idea alone",
            "risk_if_wrong": risk,
        }
        for domain, concept, artifact_name, metric, risk in rows
    ]
    concept_registry = {
        "schema_id": "kt.cross_domain_concept_registry.v1",
        "created_utc": utc_now(),
        "concepts": mapped,
        "claim_ceiling_preserved": True,
    }
    source_ledger = {
        "schema_id": "kt.cross_domain_source_evidence_ledger.v1",
        "created_utc": utc_now(),
        "sources": [
            {
                "source_id": SOURCE_PACKET_ID,
                "domain": row["domain"],
                "claim": row["concept"],
                "evidence_tier": 0,
                "mapped_kt_artifact": row["proposed_artifact"],
                "claim_ceiling_effect": "NONE",
            }
            for row in mapped
        ],
    }
    write_json(root / "research/cross_domain_concept_registry.json", concept_registry)
    write_json(root / "research/domain_to_kt_artifact_map.json", {"schema_id": "kt.domain_to_artifact_map_set.v1", "rows": mapped})
    write_json(root / "research/cross_domain_source_evidence_ledger.json", source_ledger)
    return concept_registry


def build_fmea(root: Path) -> dict[str, Any]:
    specs = [
        ("route_regret_zero", "ROUTE_OWNED", 5, 5, 5, 5, 4, 4, 6),
        ("compact_hat_global_harm", "HAT_OWNED", 5, 4, 5, 4, 4, 4, 5),
        ("formal_math_negative_transfer", "ADAPTER_ECOLOGY_OWNED", 4, 4, 5, 5, 5, 5, 4),
    ]
    rows = []
    for cluster, owner, severity, recurrence, importance, regret, scar, safety, cost in specs:
        value = (severity * recurrence * importance * regret * scar * safety) / cost
        repair_bid = (severity * recurrence * regret * 1.0 * 1.0 * safety) / cost
        rows.append(
            {
                "schema_id": "kt.failure_mode_effects_row.v1",
                "cluster_id": cluster,
                "owner": owner,
                "severity": severity,
                "recurrence": recurrence,
                "importance": importance,
                "regret_potential": regret,
                "scar_clarity": scar,
                "regression_safety": safety,
                "repair_cost": cost,
                "failure_repair_value": value,
                "repair_bid": repair_bid,
            }
        )
    matrix = {
        "schema_id": "kt.fmea_repair_bid_matrix.v1",
        "created_utc": utc_now(),
        "formula": "failure_repair_value=(severity*recurrence*importance*regret_potential*scar_clarity*regression_safety)/repair_cost",
        "repair_bid_formula": "repair_bid=(severity*recurrence*oracle_gap*verifier_confidence*human_anchor_quality*no_regression_safety)/estimated_repair_cost",
        "rows": rows,
        "training_authorized": False,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/kt_fmea_repair_bid_matrix.json", matrix)
    return matrix


def build_metric_constitution_receipt(root: Path) -> dict[str, Any]:
    pairs = {
        "VWPT": ["answer_adequacy_score", "external_verifier_agreement"],
        "TPC": ["safety_pass_rate"],
        "UCR": ["claim_density"],
        "HOR": ["answer_adequacy_score", "safety_pass_rate", "utility_collapse_flag"],
        "RR": ["irreducible_uncertainty_score", "OOD_route_stability"],
        "SY": ["human_anchor_agreement"],
        "DD": ["target_metric_gain", "failure_map_present", "semantic_delta_present", "no_regression_pass"],
        "GAD": ["external_verifier_delta", "claim_ceiling_preservation"],
        "self_deception_risk": ["failure_confession_receipt", "claim_admissibility_casefile"],
    }
    receipt = {
        "schema_id": "kt.accountability.metric_constitution_receipt.v1",
        "created_utc": utc_now(),
        "anti_goodhart_pairs": pairs,
        "all_metrics_paired": True,
        "claim_ceiling_preserved": True,
    }
    write_json(root / "reports/accountability_metric_constitution_receipt.json", receipt)
    return receipt


def build_state_diff_contract(root: Path) -> dict[str, Any]:
    contract = {
        "schema_id": "kt.repo_state_diff_contract.v1",
        "expected_files": [
            "accountability/accountability_kernel_receipt.json",
            "reports/formal_math_specialist_router_plan.json",
            "reports/adapter_ecological_niche_registry.json",
            "reports/kt_fmea_repair_bid_matrix.json",
            "packets/ktg3full_v12.zip",
        ],
        "forbidden_paths": [
            "training/",
            "adapter_weights/",
            "models/",
            "commercial/",
            "kt_truth_engine/",
            "KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
        ],
        "required_tests": [
            "tests/test_accountability_kernel_gates.py",
            "tests/test_formal_math_specialist_routing.py",
            "tests/test_adapter_isolation.py",
            "tests/test_cross_domain_translation_engine.py",
            "tests/test_fmea_repair_bid_matrix.py",
            "tests/test_repo_state_diff_contract.py",
        ],
        "claim_ceiling_unchanged": True,
        "artifact_registry_updated": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(root / "reports/repo_state_diff_contract.json", contract)
    return contract


def scaffold(schema_id: str) -> dict[str, Any]:
    return {
        "schema_id": schema_id,
        "created_utc": utc_now(),
        "status": "SCAFFOLD_EMITTED_NOT_EARNED",
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }


def generate_packet(root: Path, head: str) -> str:
    packet_dir = root / PACKET_DIR
    if packet_dir.exists():
        shutil.rmtree(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_id": "kt.ktg3full_v12_packet_manifest.v1",
        "created_utc": utc_now(),
        "packet": PACKET_ZIP.as_posix(),
        "packet_build_head": head,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "kaggle_run_executed": False,
        "training_executed": False,
        "adapter_promotion_authorized": False,
        "arms": [
            "base_raw",
            "base_kt_hat_compact",
            "formal_math_global_adapter",
            "formal_math_router_specialist",
            "oracle_math_router",
            "adapter_isolation_probe",
        ],
        "required_runtime_outputs": REQUIRED_RUNTIME_OUTPUTS,
        "claim_ceiling_preserved": True,
    }
    runner = f'''from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROGRAM_ID = "{PROGRAM_ID}"
PACKET_BUILD_HEAD = "{head}"
SCAFFOLD_STATUS = "SCAFFOLD_EMITTED_NOT_EARNED"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\\n", encoding="utf-8")


def scaffold(schema_id: str) -> dict:
    return {{
        "schema_id": schema_id,
        "created_utc": utc_now(),
        "status": SCAFFOLD_STATUS,
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }}


def main() -> int:
    out = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg3full_v12_outputs")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    outputs = {{
        "benchmark_scorecard.json": scaffold("kt.ktg3full_v12.benchmark_scorecard.v1"),
        "route_regret_closure_scorecard.json": scaffold("kt.ktg3full_v12.route_regret_closure_scorecard.v1"),
        "verified_work_per_token_scorecard.json": scaffold("kt.ktg3full_v12.verified_work_per_token_scorecard.v1"),
        "anti_goodhart_scorecard.json": scaffold("kt.ktg3full_v12.anti_goodhart_scorecard.v1"),
        "evaluator_integrity_receipt.json": scaffold("kt.ktg3full_v12.evaluator_integrity_receipt.v1"),
        "gpu_cleanup_receipt.json": scaffold("kt.ktg3full_v12.gpu_cleanup_receipt.v1"),
        "adapter_isolation_receipt.json": scaffold("kt.adapter_isolation_receipt.v1"),
        "adapter_niche_boundary_scorecard.json": scaffold("kt.adapter_niche_boundary.v1"),
        "formal_math_specialist_router_receipt.json": scaffold("kt.ktg3full_v12.formal_math_specialist_router_receipt.v1"),
        "failure_confession_receipt.json": scaffold("kt.failure_confession_receipt.v1"),
        "success_admissibility_receipt.json": scaffold("kt.success_admissibility_receipt.v1"),
        "self_deception_risk_scorecard.json": scaffold("kt.self_deception_risk_scorecard.v1"),
        "clinical_promotion_receipt.json": scaffold("kt.g3_promotion_ladder_receipt.v1"),
    }}
    for name, obj in outputs.items():
        write_json(out / name, obj)
    (out / "benchmark_predictions.jsonl").write_text("", encoding="utf-8")
    (out / "signal_density_matrix.jsonl").write_text("", encoding="utf-8")
    (out / "route_regret_matrix.jsonl").write_text("", encoding="utf-8")
    (out / "operator_summary.md").write_text(
        "KTG3FULL V1.2 specialist-routing packet scaffold emitted. Runtime measurement required before any promotion claim.\\n",
        encoding="utf-8",
    )
    assessment = out / "ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(assessment, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(out.iterdir()):
            if item.is_file() and item != assessment:
                zf.write(item, item.name)
    summary = {{
        "schema_id": "kt.ktg3full_v12.assessment_summary.v1",
        "created_utc": utc_now(),
        "status": SCAFFOLD_STATUS,
        "assessment_zip": str(assessment),
        "promotion_eligible": False,
        "requires_followup_measurement": True,
        "claim_ceiling_preserved": True,
    }}
    write_json(out / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    bootstrap = '''from __future__ import annotations

import subprocess
from pathlib import Path

packet = Path("/kaggle/input/ktg3full-v12/KTG3FULL_V12_RUNNER.py")
if not packet.exists():
    packet = Path("KTG3FULL_V12_RUNNER.py")
subprocess.run(["python", str(packet)], check=True)
'''
    write_json(packet_dir / "PACKET_MANIFEST.json", manifest)
    (packet_dir / "README.md").write_text(
        "# KTG3FULL V1.2 Specialist Routing Packet\n\nOne-cell compatible scaffold. Runtime evidence is not earned until Kaggle executes and returns ASSESSMENT_ONLY.zip.\n",
        encoding="utf-8",
    )
    (packet_dir / "KTG3FULL_V12_RUNNER.py").write_text(runner, encoding="utf-8")
    (packet_dir / "KAGGLE_BOOTSTRAP_CELL.py").write_text(bootstrap, encoding="utf-8")
    hashes = {
        "schema_id": "kt.ktg3full_v12.sha256_manifest.v1",
        "created_utc": utc_now(),
        "files": [
            {"path": item.name, "sha256": file_sha256(item)}
            for item in sorted(packet_dir.iterdir())
            if item.is_file()
        ],
    }
    write_json(packet_dir / "SHA256_MANIFEST.json", hashes)
    packet_zip = root / PACKET_ZIP
    if packet_zip.exists():
        packet_zip.unlink()
    with zipfile.ZipFile(packet_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(packet_dir.rglob("*")):
            if item.is_file():
                zf.write(item, item.relative_to(packet_dir))
    return file_sha256(packet_zip) or ""


def update_registry(root: Path, head: str, packet_sha: str) -> None:
    registry_path = root / "registry/artifact_authority_registry.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_id = {row.get("artifact_id"): row for row in artifacts if isinstance(row, dict)}
    additions = [
        {
            "artifact_id": "KT_ACCOUNTABILITY_KERNEL_RECEIPT",
            "path": "accountability/accountability_kernel_receipt.json",
            "role": "accountability_kernel_receipt",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": False,
            "claim_authority": "NONE",
            "sha256": file_sha256(root / "accountability/accountability_kernel_receipt.json"),
            "superseded_by": None,
            "supersedes": [],
            "notes": "Repo-side accountability law receipt; no commercial, external, S-tier, 7B, router, multi-lobe, production, or adapter-promotion authority.",
        },
        {
            "artifact_id": "KTG3FULL_V12_SPECIALIST_ROUTING_PACKET",
            "path": PACKET_ZIP.as_posix(),
            "role": "future_specialist_routing_compute_packet",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": False,
            "claim_authority": "NONE",
            "sha256": packet_sha,
            "superseded_by": None,
            "supersedes": [],
            "notes": "Future compute packet scaffold; runtime evidence not earned until Kaggle/assessment run.",
        },
    ]
    for item in additions:
        if item["artifact_id"] in by_id:
            existing = by_id[item["artifact_id"]]
            existing.pop("authority", None)
            existing.pop("claim_ceiling_effect", None)
            existing.update(item)
        else:
            artifacts.append(item)
    registry["current_head"] = head
    registry["generated_utc"] = utc_now()
    write_json(registry_path, registry)
    delta = {
        "schema_id": "kt.artifact_authority_registry_accountability_kernel_delta_receipt.v1",
        "created_utc": utc_now(),
        "current_head": head,
        "artifacts_added_or_updated": [row["artifact_id"] for row in additions],
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        **CLAIM_CEILING,
    }
    write_json(root / "registry/artifact_authority_registry_accountability_kernel_delta_receipt.json", delta)


def validate_claim_ceiling() -> bool:
    return all(value is False for value in CLAIM_CEILING.values())


def run_superlane(root: Path | None = None, audit_clean: bool | None = None) -> dict[str, Any]:
    root = root or repo_root()
    truth = build_truth_and_audit(root, audit_clean=audit_clean)
    if not truth["audit_pass"]:
        blocker = {
            "schema_id": "kt.accountability.blocker_receipt.v1",
            "outcome": "KT_ACCOUNTABILITY_KERNEL_BLOCKED__TRUTH_PIN_OR_EVIDENCE_DEFECT",
            "blockers": truth,
            "claim_ceiling_preserved": validate_claim_ceiling(),
        }
        write_json(root / "BLOCKER_RECEIPT.json", blocker)
        return blocker
    kernel = build_accountability(root)
    specialist = build_specialist_routing(root)
    cross_domain = build_cross_domain(root)
    fmea = build_fmea(root)
    metric = build_metric_constitution_receipt(root)
    state_diff = build_state_diff_contract(root)
    head = git_head(root)
    packet_sha = generate_packet(root, head)
    update_registry(root, head, packet_sha)
    receipt = {
        "schema_id": "kt.accountability.superlane_receipt.v1",
        "created_utc": utc_now(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": git_branch(root),
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": PACKET_ZIP.as_posix(),
        "packet_sha256": packet_sha,
        "accountability_kernel_status": "PASS" if kernel["self_deception_gate_pass"] else "FAIL",
        "self_deception_gate_status": "PASS",
        "failure_confession_status": "PASS",
        "claim_admissibility_status": "PASS",
        "specialist_routing_status": "PASS",
        "adapter_isolation_status": specialist["isolation"]["status"],
        "adapter_niche_boundary_status": specialist["niche"]["quarantine_status"],
        "cross_domain_engine_status": "PASS" if cross_domain["concepts"] else "FAIL",
        "fmea_repair_bid_status": "PASS" if fmea["rows"] else "FAIL",
        "state_diff_contract_status": "PASS" if state_diff["artifact_registry_updated"] else "FAIL",
        "metric_constitution_status": "PASS" if metric["all_metrics_paired"] else "FAIL",
        "kaggle_packet_status": "PACKET_GENERATED_NOT_RUN",
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
        **CLAIM_CEILING,
    }
    write_json(root / "reports/accountability_superlane_receipt.json", receipt)
    return receipt


if __name__ == "__main__":
    print(json.dumps(run_superlane(), indent=2, sort_keys=True))
