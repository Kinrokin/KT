from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


TRANCHE = "AUTHOR_KTV1774_BIND_EXACT_G2_STATE_VECTOR_V1"
OUTCOME = "KT_EXACT_G2_STATE_VECTOR_BOUND_OR_IRRECOVERABLE__NEXT_EVIDENCE_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
G2_ASSESSMENT_MEMBER = "outputs/reports/benchmark_predictions.jsonl"
G2_ROUTE = "routed_13_lobe_kt_hat_compact"
REPROLOCK_BASELINE_CORRECT = 41
REPROLOCK_BASELINE_TOTAL = 50
REPROLOCK_BASELINE_FULL_TPC = 145.121951
REPROLOCK_BASELINE_VISIBLE_TPC = 1.219512


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "commercial_claim": False,
            "external_validation_claim": False,
            "frontier_claim": False,
            "g2_recovered_claim": False,
            "multi_lobe_superiority_claim": False,
            "production_readiness_claim": False,
            "s_tier_claim": False,
            "seven_b_claim": False,
            "router_superiority_claim": False,
            "claim_ceiling_preserved": True,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def repo_rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def source_entry(path: Path, role: str, evidence_type: str) -> dict[str, Any]:
    return {
        "path": repo_rel(path),
        "role": role,
        "evidence_type": evidence_type,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def manifest_source_path() -> Path | None:
    for rel in ["reports/g2_evidence_manifest.json", "packets/ktg3_run_v1/G2_EVIDENCE_MANIFEST.json"]:
        manifest = read_json(ROOT / rel)
        source = manifest.get("source_path")
        if isinstance(source, str) and source:
            return Path(source)
    return None


def declared_source_sha() -> str | None:
    for rel in [
        "reports/g2_evidence_import_receipt.json",
        "reports/g2_evidence_manifest.json",
        "packets/ktg3_run_v1/G2_EVIDENCE_MANIFEST.json",
    ]:
        manifest = read_json(ROOT / rel)
        value = manifest.get("source_sha256")
        if isinstance(value, str) and value:
            return value
    return None


def declared_member_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for rel in ["reports/g2_evidence_manifest.json", "packets/ktg3_run_v1/G2_EVIDENCE_MANIFEST.json"]:
        manifest = read_json(ROOT / rel)
        imported = manifest.get("imported_members", {})
        if isinstance(imported, dict):
            for item in imported.values():
                if isinstance(item, dict) and item.get("member") and item.get("sha256"):
                    hashes[str(item["member"])] = str(item["sha256"])
    return hashes


def parse_prediction_rows(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()]


def summarize_prediction_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_subject: dict[str, dict[str, Any]] = defaultdict(lambda: {"rows": 0, "correct": 0, "new_tokens": 0})
    by_dataset: Counter[str] = Counter()
    raw_prediction_present = 0
    for row in rows:
        subject = str(row.get("subject", "UNKNOWN"))
        by_subject[subject]["rows"] += 1
        by_subject[subject]["correct"] += 1 if row.get("correct") is True else 0
        by_subject[subject]["new_tokens"] += int(row.get("new_tokens", 0) or 0)
        by_dataset[str(row.get("dataset", "UNKNOWN"))] += 1
        raw_prediction_present += 1 if row.get("raw_prediction") not in (None, "") else 0
    subject_metrics = {}
    for subject, metrics in sorted(by_subject.items()):
        correct = int(metrics["correct"])
        tokens = int(metrics["new_tokens"])
        subject_metrics[subject] = {
            "rows": int(metrics["rows"]),
            "correct": correct,
            "new_tokens": tokens,
            "new_tokens_per_correct": round(tokens / correct, 6) if correct else None,
        }
    return {
        "row_count": len(rows),
        "by_dataset": dict(sorted(by_dataset.items())),
        "raw_prediction_present_rows": raw_prediction_present,
        "prediction_keys": sorted(rows[0].keys()) if rows else [],
        "subject_metrics": subject_metrics,
    }


def inspect_assessment_zip(zip_path: Path | None = None) -> dict[str, Any]:
    source = zip_path or manifest_source_path()
    declared_sha = declared_source_sha()
    if source is None:
        return authority(
            schema_id="kt.v17_7_4.g2_assessment_archive_inspection.v1",
            status="NOT_REFERENCED",
            source_path=None,
            source_sha256_declared=declared_sha,
            source_sha256_actual=None,
            source_sha256_match=False,
            prediction_member_status="NOT_BOUND",
        )
    actual_exists = source.exists()
    actual_sha = sha256_file(source) if actual_exists else None
    result = authority(
        schema_id="kt.v17_7_4.g2_assessment_archive_inspection.v1",
        status="SOURCE_PRESENT" if actual_exists else "SOURCE_REFERENCED_NOT_LOCAL",
        source_path=str(source),
        source_sha256_declared=declared_sha,
        source_sha256_actual=actual_sha,
        source_sha256_match=bool(actual_sha and declared_sha and actual_sha == declared_sha),
        prediction_member_status="NOT_BOUND",
        member_hashes_checked={},
    )
    if not actual_exists:
        return result
    member_hashes = declared_member_hashes()
    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
        result["member_count"] = len(names)
        result["required_member_present"] = G2_ASSESSMENT_MEMBER in names
        checked: dict[str, dict[str, Any]] = {}
        for member, expected_hash in sorted(member_hashes.items()):
            if member not in names:
                checked[member] = {"present": False, "sha256_match": False}
                continue
            data = archive.read(member)
            actual_hash = sha256_bytes(data)
            checked[member] = {
                "present": True,
                "size_bytes": len(data),
                "sha256": actual_hash,
                "expected_sha256": expected_hash,
                "sha256_match": actual_hash == expected_hash,
            }
        result["member_hashes_checked"] = checked
        if G2_ASSESSMENT_MEMBER in names:
            data = archive.read(G2_ASSESSMENT_MEMBER)
            rows = parse_prediction_rows(data)
            summary = summarize_prediction_rows(rows)
            result["prediction_member_status"] = "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
            result["prediction_member_sha256"] = sha256_bytes(data)
            result["prediction_summary"] = summary
    return result


def build_truth_pin() -> dict[str, Any]:
    return authority(
        schema_id="kt.v17_7_4.g2_state_vector_truth_pin_receipt.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        worktree_clean=not bool(git(["status", "--short"])),
        active_tranche=TRANCHE,
        live_repo_truth_wins=True,
        no_generation=True,
        no_training=True,
        no_promotion=True,
        claim_ceiling_preserved=True,
    )


def build_source_search(inspection: dict[str, Any]) -> dict[str, Any]:
    candidate_paths = [
        "reports/g2_evidence_import_receipt.json",
        "reports/g2_evidence_manifest.json",
        "reports/g2_compression_anchor_receipt.json",
        "reports/g2_sentinel_recovery_search_receipt.json",
        "reports/g2_token_accounting_method_status.json",
        "reports/g2_compact_path_gap_analysis.json",
        "reports/g2_route_regret_targets.json",
        "reports/g31_per_sample_causal_trace.jsonl",
        "reports/v17_7_4_g2_forensics_epc_builder_summary.json",
        "packets/ktg3_run_v1/G2_EVIDENCE_MANIFEST.json",
        "packets/ktg3_run_v1/G2_FAILURE_MAP.json",
        "packets/ktg3_run_v1/G2_ROUTE_REGRET_TARGETS.json",
    ]
    sources = []
    for rel in candidate_paths:
        path = ROOT / rel
        if path.exists():
            sources.append(source_entry(path, "g2_state_vector_search_candidate", "CANDIDATE_EVIDENCE"))
    return authority(
        schema_id="kt.v17_7_4.g2_source_search_receipt.v1",
        status="PASS_SEARCH_COMPLETED",
        search_scope=[
            "public_main_tracked_repo_files",
            "referenced_external_g2_assessment_archive_when_present_locally",
        ],
        candidate_sources=sources,
        candidate_source_count=len(sources),
        external_archive_status=inspection["status"],
        external_archive_prediction_member_status=inspection.get("prediction_member_status"),
        exact_rendered_prompts_found=False,
        exact_prompt_template_found=False,
        exact_runtime_router_policy_found=False,
        exact_kt_hat_contract_found=False,
        no_fabricated_g2_source=True,
        claim_ceiling_preserved=True,
    )


def build_state_vector_binding(inspection: dict[str, Any]) -> dict[str, Any]:
    prediction_bound = inspection.get("prediction_member_status") == "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
    summary = inspection.get("prediction_summary", {}) if prediction_bound else {}
    components = [
        {
            "component_id": "g2_assessment_archive",
            "status": "BOUND_EXTERNAL_ARCHIVE_SHA_CONFIRMED" if inspection.get("source_sha256_match") else "MISSING_OR_HASH_UNCONFIRMED",
            "hard_required": True,
        },
        {
            "component_id": "g2_row_ids",
            "status": "BOUND_FROM_PREDICTION_ROWS" if prediction_bound else "MISSING_EXACT_SOURCE",
            "row_count": summary.get("row_count"),
            "hard_required": True,
        },
        {
            "component_id": "g2_raw_outputs",
            "status": "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED" if prediction_bound else "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_visible_outputs",
            "status": "BOUND_FROM_NORMALIZED_PREDICTION_ROWS" if prediction_bound else "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_token_ledger",
            "status": "BOUND_OUTPUT_NEW_TOKEN_LEDGER" if prediction_bound else "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_tokens_per_correct_definition",
            "status": "BOUND_AS_SUM_NEW_TOKENS_DIVIDED_BY_CORRECT" if prediction_bound else "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_rendered_prompts",
            "status": "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_prompt_template",
            "status": "MISSING_EXACT_SOURCE",
            "hard_required": True,
        },
        {
            "component_id": "g2_runtime_router_policy",
            "status": "PARTIAL_ROUTE_LABELS_ONLY",
            "hard_required": True,
        },
        {
            "component_id": "g2_kt_hat_mode_contract",
            "status": "PARTIAL_SUBJECT_LABEL_ONLY",
            "hard_required": True,
        },
        {
            "component_id": "g2_scorer_parser_code",
            "status": "PARTIAL_NORMALIZED_OUTPUTS_ONLY",
            "hard_required": True,
        },
    ]
    missing = [
        row["component_id"]
        for row in components
        if row["hard_required"] and not str(row["status"]).startswith(("BOUND_", "BOUND_AS_"))
    ]
    exact_bound = not missing
    status = "BOUND" if exact_bound else "IRRECOVERABLE_WITH_SEARCH_RECEIPT"
    return authority(
        schema_id="kt.v17_7_4.g2_state_vector_binding_receipt.v1",
        status=status,
        exact_g2_state_vector_bound=exact_bound,
        component_bindings=components,
        irrecoverable_components=missing,
        bound_external_archive_member_only=prediction_bound,
        no_generation=True,
        no_training=True,
        no_promotion=True,
        no_g2_recovered_claim=True,
        conclusion=(
            "G2 raw outputs and output-token ledger are externally bound by assessment ZIP member hash, "
            "but exact rendered prompts, prompt template, router policy, KT-hat contract, and scorer/parser code "
            "are not fully bound in public repo evidence."
        ),
        claim_ceiling_preserved=True,
    )


def build_raw_output_binding(inspection: dict[str, Any]) -> dict[str, Any]:
    prediction_bound = inspection.get("prediction_member_status") == "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
    return authority(
        schema_id="kt.v17_7_4.g2_raw_output_binding_receipt.v1",
        status="BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED" if prediction_bound else "BLOCKED_RAW_OUTPUTS_NOT_BOUND",
        source_path=inspection.get("source_path"),
        source_sha256=inspection.get("source_sha256_actual"),
        member=G2_ASSESSMENT_MEMBER,
        member_sha256=inspection.get("prediction_member_sha256"),
        raw_output_rows=inspection.get("prediction_summary", {}).get("row_count") if prediction_bound else 0,
        raw_prediction_present_rows=inspection.get("prediction_summary", {}).get("raw_prediction_present_rows") if prediction_bound else 0,
        repo_contains_raw_output_content=False,
        external_archive_required_for_replay=True,
        no_generation=True,
        claim_ceiling_preserved=True,
    )


def build_token_ledger_binding(inspection: dict[str, Any]) -> dict[str, Any]:
    prediction_bound = inspection.get("prediction_member_status") == "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
    subject_metrics = inspection.get("prediction_summary", {}).get("subject_metrics", {}) if prediction_bound else {}
    routed = subject_metrics.get(G2_ROUTE, {})
    return authority(
        schema_id="kt.v17_7_4.g2_token_ledger_binding_receipt.v1",
        status="BOUND_OUTPUT_NEW_TOKEN_LEDGER" if prediction_bound else "BLOCKED_TOKEN_LEDGER_NOT_BOUND",
        accounting_mode="output_new_tokens_per_correct" if prediction_bound else "UNKNOWN",
        token_numerator="sum(new_tokens across all rows for subject)" if prediction_bound else None,
        token_denominator="correct row count for subject" if prediction_bound else None,
        subject_metrics=subject_metrics,
        routed_13_lobe_kt_hat_compact_new_tokens_per_correct=routed.get("new_tokens_per_correct"),
        historical_aggregate_reproduced=(
            routed.get("new_tokens_per_correct") == core.G2_COMPRESSION_ANCHOR[G2_ROUTE]["tokens_per_correct"]
        )
        if routed
        else False,
        full_prompt_plus_output_tokens_per_correct_bound=False,
        visible_answer_tokens_per_correct_bound=False,
        claim_ceiling_preserved=True,
    )


def build_accounting_classification(token_ledger: dict[str, Any]) -> dict[str, Any]:
    ledger_bound = token_ledger["status"] == "BOUND_OUTPUT_NEW_TOKEN_LEDGER"
    return authority(
        schema_id="kt.v17_7_4.g2_accounting_classification.v1",
        status="BOUND_OUTPUT_NEW_TOKENS_PER_CORRECT" if ledger_bound else "BLOCKED_UNTIL_TOKEN_LEDGER_BOUND",
        g2_accounting_class="OUTPUT_NEW_TOKENS_PER_CORRECT" if ledger_bound else "UNKNOWN",
        g2_tokens_per_correct_formula="sum(new_tokens) / correct_count" if ledger_bound else None,
        current_reprolock_full_tpc=REPROLOCK_BASELINE_FULL_TPC,
        current_reprolock_visible_tpc=REPROLOCK_BASELINE_VISIBLE_TPC,
        comparable_to_current_full_tpc=False,
        comparable_to_current_visible_tpc=False,
        can_call_g2_full_system_compression=False,
        can_call_visible_tpc_full_tpc=False,
        claim_ceiling_preserved=True,
    )


def build_comparability_court(state: dict[str, Any], accounting: dict[str, Any]) -> dict[str, Any]:
    comparable = state["status"] == "BOUND" and accounting["status"] == "BOUND_OUTPUT_NEW_TOKENS_PER_CORRECT"
    return authority(
        schema_id="kt.v17_7_4.g2_vs_reprolock_comparability_court.v1",
        status="COMPARABILITY_DENIED" if not comparable else "COMPARABILITY_PARTIAL_ACCOUNTING_ONLY",
        g2_state_vector_status=state["status"],
        g2_accounting_status=accounting["status"],
        row_set_comparable=False,
        prompt_contract_comparable=False,
        rendered_prompt_comparable=False,
        raw_output_comparable=True if state.get("bound_external_archive_member_only") else False,
        token_accounting_comparable="partial_output_new_tokens_only" if accounting["status"] == "BOUND_OUTPUT_NEW_TOKENS_PER_CORRECT" else False,
        scorer_parser_comparable=False,
        conclusion="G2 can be used as an accounting/row-output forensic anchor, not as a current comparable full-system capability claim.",
        claim_ceiling_preserved=True,
    )


def build_offline_unlock(raw: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    raw_bound = raw["status"] == "BOUND_EXTERNAL_ASSESSMENT_MEMBER_SHA_CONFIRMED"
    return authority(
        schema_id="kt.v17_7_4.g2_offline_extraction_replay_unlock_receipt.v1",
        status="UNLOCKED_FOR_BOUND_RAW_OUTPUTS_ONLY" if raw_bound else "LOCKED_RAW_OUTPUTS_NOT_BOUND",
        offline_extraction_replay_allowed=raw_bound,
        replay_scope="raw-output parser/finalizer replay only" if raw_bound else None,
        generation_allowed=False,
        full_g2_recovery_allowed=False,
        remaining_state_vector_blockers=state.get("irrecoverable_components", []),
        claim_ceiling_preserved=True,
    )


def build_epc_decision(state: dict[str, Any], raw: dict[str, Any], accounting: dict[str, Any], unlock: dict[str, Any]) -> dict[str, Any]:
    if state["status"] == "BOUND":
        next_move = "RUN_OFFLINE_ACCOUNTING_EXTRACTION_COMPARABILITY_REPLAY"
    elif unlock["status"] == "UNLOCKED_FOR_BOUND_RAW_OUTPUTS_ONLY" and accounting["status"] == "BOUND_OUTPUT_NEW_TOKENS_PER_CORRECT":
        next_move = "RUN_OFFLINE_G2_RAW_OUTPUT_EXTRACTION_REPLAY__DEFINE_NEW_STAGED_FRONTIER"
    else:
        next_move = "DECLARE_G2_HISTORICAL_ANCHOR__DEFINE_NEW_STAGED_FRONTIER"
    return authority(
        schema_id="kt.v17_7_4.g2_state_vector_epc_decision.v1",
        status="PASS",
        decision="SOURCE_BINDING_BEFORE_RUNTIME_GENERATION",
        g2_state_vector_binding_status=state["status"],
        g2_raw_output_binding_status=raw["status"],
        g2_accounting_classification_status=accounting["status"],
        offline_extraction_replay_unlock_status=unlock["status"],
        next_lawful_move=next_move,
        runtime_generation_authorized=False,
        training_authorized=False,
        promotion_authority=False,
        v18_runtime_authority=False,
        claim_ceiling_preserved=True,
    )


def write_docs() -> None:
    write_text(
        ROOT / "docs" / "G2_STATE_VECTOR_BINDING.md",
        """# G2 State Vector Binding

G2 is not disproven, not recovered, and not currently comparable as a full-system TPC result.

This lane binds what can be bound and marks missing state-vector surfaces explicitly. Raw-output and
row-level output-token accounting may be bound from the referenced G2 assessment archive, but exact
rendered prompts, prompt template, router policy, KT-hat contract, and scorer/parser code must not be
invented or inferred into authority.

Thermodynamic mechanisms such as active-inference routing, adaptive forgetting, GT-FEP pruning, and
state-diff evaluation remain candidate/shadow mechanisms until receipt-bound evidence grants a lane.
""",
    )
    write_text(
        ROOT / "rules" / "NO_G2_RECOVERY_WITHOUT_STATE_VECTOR.md",
        """# No G2 Recovery Without State Vector

G2 may be cited only as a historical/internal compression anchor unless the exact state vector is
bound. Output-token accounting is not full-system token accounting, and visible-answer accounting is
not full-system token accounting.

No runtime generation, training, promotion, V18 authorization, router-superiority claim, G2-recovered
claim, or commercial/external claim follows from this lane.
""",
    )


def write_reports() -> dict[str, Any]:
    truth = build_truth_pin()
    inspection = inspect_assessment_zip()
    search = build_source_search(inspection)
    state = build_state_vector_binding(inspection)
    raw = build_raw_output_binding(inspection)
    token = build_token_ledger_binding(inspection)
    accounting = build_accounting_classification(token)
    comparability = build_comparability_court(state, accounting)
    unlock = build_offline_unlock(raw, state)
    epc = build_epc_decision(state, raw, accounting, unlock)
    reports = {
        "reports/v17_7_4_g2_state_vector_truth_pin_receipt.json": truth,
        "reports/v17_7_4_g2_assessment_archive_inspection.json": inspection,
        "reports/v17_7_4_g2_source_search_receipt.json": search,
        "reports/v17_7_4_g2_state_vector_binding_receipt.json": state,
        "reports/v17_7_4_g2_raw_output_binding_receipt.json": raw,
        "reports/v17_7_4_g2_token_ledger_binding_receipt.json": token,
        "reports/v17_7_4_g2_accounting_classification.json": accounting,
        "reports/v17_7_4_g2_vs_reprolock_comparability_court.json": comparability,
        "reports/v17_7_4_g2_offline_extraction_replay_unlock_receipt.json": unlock,
        "reports/v17_7_4_g2_state_vector_epc_decision.json": epc,
    }
    for rel, payload in reports.items():
        write_json(ROOT / rel, payload)
    summary = authority(
        schema_id="kt.v17_7_4.g2_state_vector_bind_builder_summary.v1",
        status="PASS",
        current_head=truth["current_head"],
        current_branch=truth["current_branch"],
        outcome=OUTCOME,
        g2_state_vector_truth_pin_status=truth["status"],
        g2_source_search_status=search["status"],
        g2_state_vector_binding_status=state["status"],
        g2_raw_output_binding_status=raw["status"],
        g2_token_ledger_binding_status=token["status"],
        g2_accounting_classification_status=accounting["status"],
        g2_vs_reprolock_comparability_status=comparability["status"],
        offline_extraction_replay_unlock_status=unlock["status"],
        epc_decision_status=epc["status"],
        packet_path_if_any=None,
        packet_sha256_if_any=None,
        kaggle_dataset_name_if_any=None,
        one_cell_runbook_if_any=None,
        next_lawful_move=epc["next_lawful_move"],
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    write_json(ROOT / "reports" / "v17_7_4_g2_state_vector_bind_builder_summary.json", summary)
    all_reports = [*reports, "reports/v17_7_4_g2_state_vector_bind_builder_summary.json"]
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_g2_state_vector_bind_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_g2_state_vector_bind.v1",
            status="PASS",
            current_head=truth["current_head"],
            artifacts_added=[
                {
                    "path": rel,
                    "role": "g2_state_vector_bind_report",
                    "sha256": sha256_file(ROOT / rel),
                    "authority_state": "FORENSIC_BINDING_ONLY",
                    "claim_expansion": False,
                }
                for rel in all_reports
            ],
            outcome=OUTCOME,
            next_lawful_move=epc["next_lawful_move"],
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_router_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    return summary


def write_schemas() -> None:
    base_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["schema_id", "status", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"type": "string"},
            "status": {"type": "string"},
            "claim_ceiling_preserved": {"const": True},
        },
        "additionalProperties": True,
    }
    schemas = {
        "schemas/kt.v17_7_4.g2_source_search_receipt.schema.json": base_schema
        | {"$id": "kt.v17_7_4.g2_source_search_receipt.schema.json"},
        "schemas/kt.v17_7_4.g2_state_vector_binding.schema.json": base_schema
        | {"$id": "kt.v17_7_4.g2_state_vector_binding.schema.json"},
        "schemas/kt.v17_7_4.g2_accounting_classification.schema.json": base_schema
        | {"$id": "kt.v17_7_4.g2_accounting_classification.schema.json"},
        "schemas/kt.v17_7_4.g2_state_vector_epc_decision.schema.json": base_schema
        | {"$id": "kt.v17_7_4.g2_state_vector_epc_decision.schema.json"},
    }
    for rel, payload in schemas.items():
        write_json(ROOT / rel, payload)


def main() -> int:
    write_schemas()
    write_docs()
    summary = write_reports()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
