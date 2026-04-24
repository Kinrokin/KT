from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_gate_f_common as common


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def seed_gate_f_base(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    product = root / "KT_PROD_CLEANROOM" / "product"
    docs = root / "KT_PROD_CLEANROOM" / "docs" / "commercial"

    _write_json(
        reports / "cohort0_successor_gate_d_post_clear_branch_law_packet.json",
        {
            "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_branch_law_packet.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "canonical_live_branch_status": {
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open": True,
                "same_head_counted_reentry_admissible_now": True,
            },
        },
    )
    _write_json(
        reports / "cohort0_successor_gate_d_post_clear_branch_law_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_branch_law_receipt.v1",
            "status": "PASS",
            "subject_head": "head-123",
            "gate_d_cleared_on_successor_line": True,
            "gate_e_open": True,
        },
    )
    _write_json(
        reports / "cohort0_successor_gate_d_post_clear_supersession_note.json",
        {
            "schema_id": "kt.operator.cohort0_successor_gate_d_post_clear_supersession_note.v1",
            "status": "PASS",
            "successor_line_supersedes_prior_same_head_failure_for_live_branch_posture": True,
        },
    )
    _write_json(
        reports / "cohort0_successor_master_orchestrator_receipt.json",
        {
            "schema_id": "kt.operator.cohort0_successor_master_orchestrator_receipt.v1",
            "status": "PASS",
            "current_branch_posture": common.CURRENT_POSTURE,
            "subject_head": "head-123",
        },
    )
    _write_json(
        product / "deployment_profiles.json",
        {
            "schema_id": "kt.product.deployment_profiles_source.v1",
            "status": "ACTIVE",
            "profiles": [
                {
                    "profile_id": "local_verifier_mode",
                    "install_to_pass_fail_minutes": 15,
                    "max_externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
                }
            ],
        },
    )
    _write_json(
        product / "client_wrapper_spec.json",
        {
            "schema_id": "kt.product.client_wrapper_spec.v1",
            "status": "ACTIVE",
            "entrypoints": [
                {"entrypoint_id": "verify_packet", "command": "python -m tools.operator.public_verifier"},
                {"entrypoint_id": "detached_pass_fail", "command": "python -m tools.operator.public_verifier_detached_validate"},
            ],
            "pass_fail_surface_refs": list(common.ACTIVE_WEDGE_RECEIPT_REFS),
        },
    )
    _write_json(
        product / "support_boundary.json",
        {
            "schema_id": "kt.product.support_boundary.v1",
            "status": "ACTIVE",
            "support_tier": "BOUNDED_E1_OPERATOR_GUIDANCE_ONLY",
            "supported_surfaces": ["same_host_verifier_packet_generation"],
            "unsupported_surfaces": ["multi_tenant_runtime", "enterprise_readiness_claims"],
            "runtime_cutover_allowed": False,
            "no_training_default": True,
        },
    )
    _write_json(
        product / "final_product_truth_boundary.json",
        {"schema_id": "kt.product.final_truth_boundary.v1", "status": "PASS"},
    )
    _write_text(product / "one_page_product_truth_surface.md", "E1 bounded verifier wedge only.\n")
    _write_text(product / "operator_runbook_v2.md", "Runbook only.\n")
    _write_text(docs / "E1_BOUNDED_TRUST_WEDGE.md", "Buyer-safe wedge.\n")
    _write_text(docs / "E1_DEMO_SCRIPT.md", "Demo.\n")

    _write_json(reports / "product_install_15m_receipt.json", {"schema_id": "kt.product.install_15m_receipt.v1", "status": "PASS"})
    _write_json(
        reports / "operator_handoff_receipt.json",
        {
            "schema_id": "kt.product.operator_handoff_receipt.v1",
            "status": "PASS",
            "handoff_bundle_refs": ["KT_PROD_CLEANROOM/product/operator_runbook_v2.md"],
            "independent_operator_target_minutes": 15,
        },
    )
    _write_json(reports / "kt_operator_greenline_receipt.json", {"schema_id": "kt.operator.operator_greenline_receipt.v1", "status": "PASS"})
    _write_json(
        reports / "commercial_truth_packet.json",
        {
            "schema_id": "kt.e1.commercial_truth_packet.v1",
            "status": "PASS",
            "externality_class_max": "E1_SAME_HOST_DETACHED_REPLAY",
        },
    )
    _write_json(
        reports / "kt_product_surface_manifest.json",
        {
            "schema_id": "kt.product_surface_manifest.v1",
            "status": "ACTIVE",
            "surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
        },
    )
    _write_json(
        reports / "kt_product_surface_receipt.json",
        {
            "schema_id": "kt.operator.ws19.product_surface_receipt.v1",
            "status": "PASS",
            "campaign_completion_status": "STILL_BLOCKED",
        },
    )
    _write_json(
        reports / "kt_product_wedge_activation_receipt.json",
        {
            "schema_id": "kt.child_campaign.product_wedge_activation_receipt.v1",
            "status": "PASS",
            "scope": "CHILD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY",
        },
    )
    _write_json(reports / "public_verifier_kit.json", {"schema_id": "kt.e1.public_verifier_kit.v1", "status": "PASS"})
    _write_json(
        reports / "kt_public_verifier_detached_receipt.json",
        {"schema_id": "kt.operator.public_verifier_detached_receipt.v1", "status": "PASS"},
    )
    _write_json(
        reports / "external_audit_packet_manifest.json",
        {"schema_id": "kt.external_audit_packet_manifest.v2", "status": "PASS"},
    )
    _write_json(
        reports / "live_validation_index.json",
        {
            "schema_id": "kt.live_validation_index.v1",
            "checks": [
                {
                    "check_id": "operator_clean_clone_smoke",
                    "status": "PASS",
                    "summary": "operator clean-clone smoke passed",
                }
            ],
        },
    )
    return reports
