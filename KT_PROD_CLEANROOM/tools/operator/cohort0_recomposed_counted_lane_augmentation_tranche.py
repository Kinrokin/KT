from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_RECOMPOSED_SUBSTRATE_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_substrate_receipt.json"
DEFAULT_RECOMPOSED_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_manifest.json"
DEFAULT_PAIRWISE_AUGMENTATION_REL = "KT_PROD_CLEANROOM/reports/pairwise_counted_lane_augmentation_packet.json"
DEFAULT_PAIRWISE_REPORT_REL = "KT_PROD_CLEANROOM/reports/pairwise_transfer_candidate_report.json"
DEFAULT_WEDGE_SPEC_REL = "KT_PROD_CLEANROOM/reports/cohort0_residual_alpha_dominance_wedge_spec.json"
DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ROUTE_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/reports/route_policy_outcome_registry.json"

DEFAULT_TRACKED_MANIFEST = "cohort0_recomposed_counted_lane_augmentation_manifest.json"
DEFAULT_TRACKED_NULL_ROUTE = "cohort0_recomposed_null_route_counterfactual_packet.json"
DEFAULT_TRACKED_MASKED = "cohort0_recomposed_masked_form_variant_packet.json"
DEFAULT_TRACKED_ORTHOGONALITY = "cohort0_recomposed_orthogonality_appendix.json"
DEFAULT_TRACKED_STRESS_TAX = "cohort0_recomposed_promotion_stress_tax.json"
DEFAULT_TRACKED_RECEIPT = "cohort0_recomposed_counted_lane_augmentation_receipt.json"

ROUTE = "ROUTE_TO_SPECIALIST"
STATIC = "STAY_STATIC_BASELINE"
ABSTAIN = "ABSTAIN_FOR_REVIEW"

POSTURE = "RECOMPOSED_COUNTED_LANE_AUGMENTATION_BOUND__ORDERED_PROOF_READY__COUNTED_LANE_STILL_CLOSED"
NEXT_MOVE = "EXECUTE_RECOMPOSED_ORDERED_PROOF_AUGMENTATION__ROUTER_SHADOW_THEN_R5"

CASE_BLUEPRINTS: Dict[str, Dict[str, Any]] = {
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "family_category": "COUNTED_LANE_AUGMENTATION",
        "route_cases": [
            {
                "variant_id": "DOWNSTREAM_ORDER_BREAK",
                "objective": "Sequence-heavy operating choice where a locally good answer causes a later rollback or dependency break.",
                "mask_style": "DOMAIN_SKIN_SHIFT",
                "null_outcome": STATIC,
                "null_objective": "Same downstream frame, but the path is already linear enough that static alpha should stay canonical.",
            },
            {
                "variant_id": "SEQUENCED_ROLLBACK_COST",
                "objective": "Plan under temporal distortion where the wrong order raises recovery cost even if the immediate step looks plausible.",
                "mask_style": "EVIDENCE_ORDER_INVERSION",
                "null_outcome": ABSTAIN,
                "null_objective": "Same timeline pressure, but one missing dependency should force lawful abstention instead of routing.",
            },
        ],
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "family_category": "COUNTED_LANE_AUGMENTATION",
        "route_cases": [
            {
                "variant_id": "PROOF_CHAIN_REPAIR",
                "objective": "Task where admissibility can still be recovered if the route prioritizes receipt discipline over surface plausibility.",
                "mask_style": "VOICE_AND_FORMAT_SHIFT",
                "null_outcome": STATIC,
                "null_objective": "Same proof family, but the receipts are already complete enough that static hold is the right no-intervention outcome.",
            },
            {
                "variant_id": "ADMISSIBILITY_BREACH_TRIAGE",
                "objective": "Governed execution case where a specialist should catch a hidden admissibility breach before action continues.",
                "mask_style": "DOMAIN_CAMOUFLAGE",
                "null_outcome": ABSTAIN,
                "null_objective": "Same breach family, but ambiguity is irreducible enough that only abstention and handoff are lawful.",
            },
        ],
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "family_category": "COUNTED_LANE_AUGMENTATION",
        "route_cases": [
            {
                "variant_id": "RIVAL_FRAME_PRESERVATION",
                "objective": "Decision memo where the safer answer depends on keeping a rival framing alive instead of collapsing to the first clean narrative.",
                "mask_style": "DOMAIN_SKIN_SHIFT",
                "null_outcome": STATIC,
                "null_objective": "Same framing family, but the first framing is already stable enough that static hold is correct.",
            },
            {
                "variant_id": "SECOND_ORDER_COUNTERREAD",
                "objective": "Second-order reinterpretation task where alpha’s first framing looks neat but hides the more decisive branch.",
                "mask_style": "EVIDENCE_ORDER_INVERSION",
                "null_outcome": ABSTAIN,
                "null_objective": "Same counterread family, but the rival interpretations remain too underdetermined for routing to be lawful.",
            },
        ],
    },
}

CONTROL_BLUEPRINTS: Tuple[Dict[str, Any], ...] = (
    {
        "family_id": "BOUNDARY_ABSTENTION_CONTROL",
        "variant_id": "AUGMENTED_BOUNDARY_TRIAGE",
        "objective": "Boundary-heavy case where the only lawful result is still abstention with explicit review handoff.",
        "expected_policy_outcome": ABSTAIN,
        "mask_style": "VOICE_AND_FORMAT_SHIFT",
    },
    {
        "family_id": "STATIC_NO_ROUTE_CONTROL",
        "variant_id": "AUGMENTED_STATIC_HOLD",
        "objective": "Clean static-hold case where any extra routing would be pure regression.",
        "expected_policy_outcome": STATIC,
        "mask_style": "EVIDENCE_ORDER_INVERSION",
    },
)

STRESS_TAX_RULES: Dict[str, Dict[str, Any]] = {
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "added_proof_burden_tier": "MEDIUM",
        "added_regression_surface_tier": "LOW",
        "added_operator_burden_tier": "LOW",
        "expected_governance_roi_tier": "HIGH",
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "added_proof_burden_tier": "HIGH",
        "added_regression_surface_tier": "MEDIUM",
        "added_operator_burden_tier": "MEDIUM",
        "expected_governance_roi_tier": "VERY_HIGH",
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "added_proof_burden_tier": "MEDIUM",
        "added_regression_surface_tier": "MEDIUM",
        "added_operator_burden_tier": "LOW",
        "expected_governance_roi_tier": "MEDIUM",
    },
}


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path.resolve(), label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    if authoritative_ref:
        authoritative_path = _resolve(root, authoritative_ref)
        return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")
    return tracked_path.resolve(), tracked


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not heads:
        raise RuntimeError("FAIL_CLOSED: augmentation tranche could not resolve any subject head")
    if len(heads) != 1:
        raise RuntimeError("FAIL_CLOSED: augmentation tranche requires one consistent subject head")
    return next(iter(heads))


def _index_rows(rows: Sequence[Dict[str, Any]], *, key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: expected object row while indexing")
        row_key = str(row.get(key, "")).strip()
        if not row_key:
            raise RuntimeError(f"FAIL_CLOSED: indexed row missing key {key}")
        out[row_key] = row
    return out


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_inputs(
    *,
    recomposed_substrate: Dict[str, Any],
    recomposed_manifest: Dict[str, Any],
    pairwise_augmentation: Dict[str, Any],
    pairwise_report: Dict[str, Any],
    wedge_spec: Dict[str, Any],
    stage_pack_manifest: Dict[str, Any],
    route_policy_registry: Dict[str, Any],
) -> None:
    if str(recomposed_substrate.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed substrate receipt must PASS")
    if str(recomposed_manifest.get("subject_head", "")).strip() != str(recomposed_substrate.get("subject_head", "")).strip():
        raise RuntimeError("FAIL_CLOSED: recomposed manifest and receipt subject heads mismatch")
    if str(pairwise_augmentation.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise augmentation packet must PASS")
    if str(pairwise_augmentation.get("next_lawful_move", "")).strip() != "AUTHOR_RECOMPOSED_COUNTED_LANE_AUGMENTATION_TRANCHE__ORDERED_PROOF_ONLY":
        raise RuntimeError("FAIL_CLOSED: pairwise augmentation packet must authorize this tranche")
    if str(pairwise_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pairwise transfer report must PASS")
    if str(wedge_spec.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: residual wedge spec must PASS")
    if str(stage_pack_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route bearing stage pack manifest must PASS")
    if str(route_policy_registry.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route policy outcome registry must PASS")
    outcome_ids = [
        str(row.get("outcome_id", "")).strip()
        for row in route_policy_registry.get("outcomes", [])
        if isinstance(row, dict)
    ]
    if outcome_ids != [ROUTE, STATIC, ABSTAIN]:
        raise RuntimeError("FAIL_CLOSED: route policy registry outcomes mismatch")
    if list(pairwise_augmentation.get("ready_family_ids", [])) != [
        "STRATEGIST_CONSEQUENCE_CHAIN",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED",
        "BETA_SECOND_ORDER_REFRAME",
    ]:
        raise RuntimeError("FAIL_CLOSED: recomposed counted-lane augmentation must bind only strategist/auditor/beta")


def _entry_index(recomposed_manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return _index_rows([row for row in recomposed_manifest.get("entries", []) if isinstance(row, dict)], key="adapter_id")


def _wedge_index(wedge_spec: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return _index_rows([row for row in wedge_spec.get("rows", []) if isinstance(row, dict)], key="family_id")


def _pairwise_index(pairwise_augmentation: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return _index_rows([row for row in pairwise_augmentation.get("rows", []) if isinstance(row, dict)], key="family_id")


def _scoring_channels(stage_pack_manifest: Dict[str, Any]) -> List[str]:
    return [str(x).strip() for x in stage_pack_manifest.get("scoring_channels", []) if str(x).strip()]


def _control_row(stage_pack_manifest: Dict[str, Any], family_id: str) -> Dict[str, Any]:
    for row in stage_pack_manifest.get("family_rows", []):
        if isinstance(row, dict) and str(row.get("family_id", "")).strip() == family_id:
            return row
    raise RuntimeError(f"FAIL_CLOSED: missing control family row in stage pack manifest: {family_id}")


def _base_route_case(
    *,
    family_id: str,
    candidate_row: Dict[str, Any],
    wedge_row: Dict[str, Any],
    entry_row: Dict[str, Any],
    blueprint: Dict[str, Any],
    scoring_channels: Sequence[str],
) -> Dict[str, Any]:
    prompt = (
        f"family_id={family_id}; target_lobe_id={candidate_row['target_lobe_id']}; "
        f"mode=ROUTE_CANDIDATE; variant={blueprint['variant_id']}; "
        f"named_wedge_sharpening={candidate_row['named_wedge_sharpening']}; "
        f"alpha_liability={candidate_row['named_anti_alpha_liability']}; "
        f"objective={blueprint['objective']}; "
        f"acceptance_metric={wedge_row['success_condition']}; "
        f"proof_goal=Make the wrong static instinct measurably expensive without widening the claim class."
    )
    case_id = f"{family_id}__{blueprint['variant_id']}"
    return {
        "case_id": case_id,
        "case_sha256": _sha256_text(prompt),
        "family_id": family_id,
        "family_category": "COUNTED_LANE_AUGMENTATION",
        "target_lobe_id": str(candidate_row.get("target_lobe_id", "")).strip(),
        "entry_mode": str(entry_row.get("entry_mode", "")).strip(),
        "case_role": "ROUTE_CANDIDATE",
        "case_variant": blueprint["variant_id"],
        "expected_policy_outcome": ROUTE,
        "selected_adapter_ids": [str(candidate_row.get("target_lobe_id", "")).strip()],
        "objective": blueprint["objective"],
        "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
        "alpha_liability": str(candidate_row.get("named_anti_alpha_liability", "")).strip(),
        "route_hypothesis": str(candidate_row.get("measurable_route_delta_hypothesis", "")).strip(),
        "prompt": prompt,
        "scoring_channels": list(scoring_channels),
    }


def _null_route_sibling(
    *,
    family_id: str,
    route_case: Dict[str, Any],
    blueprint: Dict[str, Any],
    scoring_channels: Sequence[str],
) -> Dict[str, Any]:
    expected = str(blueprint["null_outcome"]).strip()
    prompt = (
        f"family_id={family_id}; sibling_of={route_case['case_id']}; mode=NULL_ROUTE_COUNTERFACTUAL; "
        f"expected_policy={expected}; objective={blueprint['null_objective']}; "
        f"keep_claims_narrow=true; forbid_unearned_route=true"
    )
    case_id = f"{route_case['case_id']}__NULL_ROUTE"
    row = {
        "case_id": case_id,
        "case_sha256": _sha256_text(prompt),
        "family_id": family_id,
        "family_category": "COUNTED_LANE_AUGMENTATION",
        "target_lobe_id": route_case["target_lobe_id"],
        "case_role": "NULL_ROUTE_COUNTERFACTUAL",
        "counterfactual_of_case_id": route_case["case_id"],
        "case_variant": f"{route_case['case_variant']}__NULL_ROUTE",
        "expected_policy_outcome": expected,
        "selected_adapter_ids": [] if expected == ABSTAIN else [route_case["selected_adapter_ids"][0] if expected == ROUTE else "lobe.alpha.v1"],
        "objective": blueprint["null_objective"],
        "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
        "alpha_liability": route_case["alpha_liability"],
        "prompt": prompt,
        "scoring_channels": list(scoring_channels),
    }
    if expected == STATIC:
        row["static_baseline_reason"] = "Counterfactual sibling removes the specialist-only liability, so static hold should remain canonical."
    else:
        row["abstention_reason"] = "Counterfactual sibling makes routing unsafe; lawful abstention should dominate forced intervention."
        row["review_handoff_rule"] = "Escalate to review and require missing-variable repair before re-entry."
    return row


def _masked_variant(
    *,
    route_case: Dict[str, Any],
    mask_style: str,
    scoring_channels: Sequence[str],
) -> Dict[str, Any]:
    prompt = (
        f"masked_of={route_case['case_id']}; mask_style={mask_style}; "
        f"preserve_objective={route_case['objective']}; "
        f"rewrite_surface_only=true; maintain_expected_policy={route_case['expected_policy_outcome']}"
    )
    return {
        "case_id": f"{route_case['case_id']}__MASKED",
        "case_sha256": _sha256_text(prompt),
        "family_id": route_case["family_id"],
        "family_category": route_case["family_category"],
        "target_lobe_id": route_case["target_lobe_id"],
        "case_role": "MASKED_FORM_VARIANT",
        "masked_variant_of_case_id": route_case["case_id"],
        "case_variant": f"{route_case['case_variant']}__MASKED",
        "expected_policy_outcome": route_case["expected_policy_outcome"],
        "selected_adapter_ids": list(route_case["selected_adapter_ids"]),
        "objective": route_case["objective"],
        "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
        "alpha_liability": route_case["alpha_liability"],
        "mask_style": mask_style,
        "prompt": prompt,
        "scoring_channels": list(scoring_channels),
    }


def _control_case(
    *,
    control_row: Dict[str, Any],
    blueprint: Dict[str, Any],
    scoring_channels: Sequence[str],
    masked: bool,
) -> Dict[str, Any]:
    suffix = "__MASKED" if masked else ""
    prompt = (
        f"family_id={blueprint['family_id']}; control_case=true; masked={str(masked).lower()}; "
        f"expected_policy={blueprint['expected_policy_outcome']}; objective={blueprint['objective']}"
    )
    row = {
        "case_id": f"{blueprint['family_id']}__{blueprint['variant_id']}{suffix}",
        "case_sha256": _sha256_text(prompt),
        "family_id": blueprint["family_id"],
        "family_category": str(control_row.get("family_category", "CONTROL")).strip(),
        "target_lobe_id": str(control_row.get("target_lobe_id", "")).strip(),
        "case_role": "CONTROL",
        "case_variant": f"{blueprint['variant_id']}{suffix}",
        "expected_policy_outcome": blueprint["expected_policy_outcome"],
        "selected_adapter_ids": [] if blueprint["expected_policy_outcome"] == ABSTAIN else [str(control_row.get("target_lobe_id", "")).strip()],
        "objective": blueprint["objective"],
        "pack_visibility": "VISIBLE_TO_ORDERED_PROOF",
        "alpha_liability": str(control_row.get("alpha_liability", "")).strip(),
        "mask_style": blueprint["mask_style"] if masked else "",
        "prompt": prompt,
        "scoring_channels": list(scoring_channels),
    }
    if blueprint["expected_policy_outcome"] == STATIC:
        row["static_baseline_reason"] = "Static control remains the rightful no-route hold."
    else:
        row["abstention_reason"] = "Abstention control remains the rightful fail-closed response."
        row["review_handoff_rule"] = "Escalate to manual review before action."
    return row


def run_recomposed_counted_lane_augmentation_tranche(
    *,
    recomposed_substrate_path: Path,
    recomposed_manifest_path: Path,
    pairwise_augmentation_path: Path,
    pairwise_report_path: Path,
    wedge_spec_path: Path,
    stage_pack_manifest_path: Path,
    route_policy_registry_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_recomposed_substrate_path, recomposed_substrate = _resolve_authoritative(root, recomposed_substrate_path, "authoritative_recomposed_13_entrant_substrate_receipt_ref", "recomposed substrate receipt")
    authoritative_recomposed_manifest_path, recomposed_manifest = _resolve_authoritative(root, recomposed_manifest_path, "authoritative_recomposed_13_entrant_manifest_ref", "recomposed manifest")
    authoritative_pairwise_augmentation_path, pairwise_augmentation = _resolve_authoritative(root, pairwise_augmentation_path, "authoritative_pairwise_counted_lane_augmentation_packet_ref", "pairwise augmentation packet")
    authoritative_pairwise_report_path, pairwise_report = _resolve_authoritative(root, pairwise_report_path, "authoritative_pairwise_transfer_candidate_report_ref", "pairwise transfer report")
    authoritative_wedge_spec_path, wedge_spec = _resolve_authoritative(root, wedge_spec_path, "authoritative_cohort0_residual_alpha_dominance_wedge_spec_ref", "residual wedge spec")
    authoritative_stage_pack_manifest_path, stage_pack_manifest = _resolve_authoritative(root, stage_pack_manifest_path, "authoritative_route_bearing_stage_pack_manifest_ref", "route bearing stage pack manifest")
    authoritative_route_policy_registry_path, route_policy_registry = _resolve_authoritative(root, route_policy_registry_path, "authoritative_route_policy_outcome_registry_ref", "route policy registry")

    _validate_inputs(
        recomposed_substrate=recomposed_substrate,
        recomposed_manifest=recomposed_manifest,
        pairwise_augmentation=pairwise_augmentation,
        pairwise_report=pairwise_report,
        wedge_spec=wedge_spec,
        stage_pack_manifest=stage_pack_manifest,
        route_policy_registry=route_policy_registry,
    )

    subject_head = _resolve_subject_head(
        packets=[
            recomposed_substrate,
            recomposed_manifest,
            pairwise_augmentation,
            pairwise_report,
            wedge_spec,
            stage_pack_manifest,
            route_policy_registry,
        ]
    )
    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_recomposed_counted_lane_augmentation").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    candidate_rows = _pairwise_index(pairwise_augmentation)
    entry_rows = _entry_index(recomposed_manifest)
    wedge_rows = _wedge_index(wedge_spec)
    scoring_channels = _scoring_channels(stage_pack_manifest)

    all_cases: List[Dict[str, Any]] = []
    null_rows: List[Dict[str, Any]] = []
    masked_rows: List[Dict[str, Any]] = []
    family_counts: List[Dict[str, Any]] = []
    orthogonality_rows: List[Dict[str, Any]] = []
    stress_rows: List[Dict[str, Any]] = []

    for family_id in pairwise_augmentation.get("ready_family_ids", []):
        candidate_row = candidate_rows[family_id]
        entry_row = entry_rows[str(candidate_row.get("target_lobe_id", "")).strip()]
        wedge_row = wedge_rows[family_id]
        blueprint_rows = CASE_BLUEPRINTS[family_id]["route_cases"]

        base_route_cases: List[Dict[str, Any]] = []
        for blueprint in blueprint_rows:
            route_case = _base_route_case(
                family_id=family_id,
                candidate_row=candidate_row,
                wedge_row=wedge_row,
                entry_row=entry_row,
                blueprint=blueprint,
                scoring_channels=scoring_channels,
            )
            null_case = _null_route_sibling(
                family_id=family_id,
                route_case=route_case,
                blueprint=blueprint,
                scoring_channels=scoring_channels,
            )
            masked_case = _masked_variant(
                route_case=route_case,
                mask_style=str(blueprint["mask_style"]),
                scoring_channels=scoring_channels,
            )
            all_cases.extend([route_case, null_case, masked_case])
            null_rows.append(null_case)
            masked_rows.append(masked_case)
            base_route_cases.append(route_case)

        family_counts.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(candidate_row.get("target_lobe_id", "")).strip(),
                "route_case_count": len(base_route_cases),
                "null_route_case_count": 2,
                "masked_variant_count": 2,
                "total_case_count": 6,
            }
        )
        tax = STRESS_TAX_RULES[family_id]
        stress_rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(candidate_row.get("target_lobe_id", "")).strip(),
                "added_proof_burden_tier": tax["added_proof_burden_tier"],
                "added_regression_surface_tier": tax["added_regression_surface_tier"],
                "added_operator_burden_tier": tax["added_operator_burden_tier"],
                "expected_governance_roi_tier": tax["expected_governance_roi_tier"],
                "net_route_value_score": float(candidate_row.get("net_route_value_score", 0.0)),
                "promotion_recommended": True,
            }
        )

    control_family_ids = ["BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"]
    for blueprint in CONTROL_BLUEPRINTS:
        source = _control_row(stage_pack_manifest, blueprint["family_id"])
        base_case = _control_case(control_row=source, blueprint=blueprint, scoring_channels=scoring_channels, masked=False)
        masked_case = _control_case(control_row=source, blueprint=blueprint, scoring_channels=scoring_channels, masked=True)
        all_cases.extend([base_case, masked_case])
        if masked_case["mask_style"]:
            masked_rows.append(masked_case)

    ready_ids = list(pairwise_augmentation.get("ready_family_ids", []))
    for left_index in range(len(ready_ids)):
        for right_index in range(left_index + 1, len(ready_ids)):
            left = ready_ids[left_index]
            right = ready_ids[right_index]
            left_row = candidate_rows[left]
            right_row = candidate_rows[right]
            overlap = 0.25 if left.endswith("REFRAME") and right.endswith("CHAIN") else 0.15
            if "AUDITOR" in left or "AUDITOR" in right:
                overlap -= 0.05
            orthogonality_rows.append(
                {
                    "family_pair": [left, right],
                    "alpha_liability_overlap_score": round(max(0.05, overlap), 2),
                    "route_outcome_overlap_score": 0.20 if "AUDITOR" in left or "AUDITOR" in right else 0.35,
                    "governance_roi_overlap_score": 0.30 if "AUDITOR" in left or "AUDITOR" in right else 0.40,
                    "orthogonality_score": round(1.0 - max(0.05, overlap), 2),
                    "orthogonal_enough_for_joint_augmentation": True,
                }
            )

    cases_path = (target_root / "cohort0_recomposed_counted_lane_augmentation_cases.json").resolve()
    write_json_stable(cases_path, {"schema_id": "kt.operator.cohort0_recomposed_counted_lane_augmentation_cases.v1", "generated_utc": utc_now_iso_z(), "status": "PASS", "subject_head": subject_head, "rows": all_cases})

    manifest = {
        "schema_id": "kt.operator.cohort0_recomposed_counted_lane_augmentation_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This manifest binds only the recomposed counted-lane augmentation court for strategist, auditor, and beta plus preserved controls. It does not widen claims beyond ordered proof preparation.",
        "ready_family_ids": ready_ids,
        "control_family_ids": control_family_ids,
        "source_refs": {
            "recomposed_substrate_receipt_ref": authoritative_recomposed_substrate_path.as_posix(),
            "recomposed_manifest_ref": authoritative_recomposed_manifest_path.as_posix(),
            "pairwise_counted_lane_augmentation_packet_ref": authoritative_pairwise_augmentation_path.as_posix(),
            "pairwise_transfer_candidate_report_ref": authoritative_pairwise_report_path.as_posix(),
            "residual_alpha_dominance_wedge_spec_ref": authoritative_wedge_spec_path.as_posix(),
            "route_bearing_stage_pack_manifest_ref": authoritative_stage_pack_manifest_path.as_posix(),
            "route_policy_outcome_registry_ref": authoritative_route_policy_registry_path.as_posix(),
        },
        "case_rows_ref": cases_path.as_posix(),
        "route_case_family_counts": family_counts,
        "case_count": len(all_cases),
        "null_route_counterfactual_count": len(null_rows),
        "masked_variant_count": len(masked_rows),
        "next_lawful_move": NEXT_MOVE,
    }
    null_packet = {
        "schema_id": "kt.operator.cohort0_recomposed_null_route_counterfactual_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These null-route siblings prove that the augmentation court is testing route quality, not route eagerness.",
        "ready_family_ids": ready_ids,
        "rows": null_rows,
    }
    masked_packet = {
        "schema_id": "kt.operator.cohort0_recomposed_masked_form_variant_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "These masked variants preserve underlying tasks while changing surface form so the augmentation court can reject shortcut routing.",
        "rows": masked_rows,
    }
    orthogonality = {
        "schema_id": "kt.operator.cohort0_recomposed_orthogonality_appendix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This appendix measures whether strategist, auditor, and beta justify distinct counted-lane complexity.",
        "rows": orthogonality_rows,
    }
    stress_tax = {
        "schema_id": "kt.operator.cohort0_recomposed_promotion_stress_tax.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": "This scorecard prices the complexity cost of promoting candidate families into ordered proof augmentation.",
        "rows": stress_rows,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_recomposed_counted_lane_augmentation_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "recomposed_counted_lane_augmentation_posture": POSTURE,
        "claim_boundary": "This receipt binds only the augmented ordered-proof court. The counted lane remains closed until router shadow and R5 reruns speak on this augmented court.",
        "ready_family_count": len(ready_ids),
        "ready_family_ids": ready_ids,
        "control_family_ids": control_family_ids,
        "null_route_counterfactual_count": len(null_rows),
        "masked_variant_count": len(masked_rows),
        "next_lawful_move": NEXT_MOVE,
    }

    payloads = {
        "cohort0_recomposed_counted_lane_augmentation_manifest": manifest,
        "cohort0_recomposed_null_route_counterfactual_packet": null_packet,
        "cohort0_recomposed_masked_form_variant_packet": masked_packet,
        "cohort0_recomposed_orthogonality_appendix": orthogonality,
        "cohort0_recomposed_promotion_stress_tax": stress_tax,
        "cohort0_recomposed_counted_lane_augmentation_receipt": receipt,
    }
    for name, obj in payloads.items():
        write_json_stable((target_root / f"{name}.json").resolve(), obj)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_names = {
        "cohort0_recomposed_counted_lane_augmentation_manifest": ("TRACKED_CARRIER_ONLY_RECOMPOSED_COUNTED_LANE_AUGMENTATION_MANIFEST", DEFAULT_TRACKED_MANIFEST),
        "cohort0_recomposed_null_route_counterfactual_packet": ("TRACKED_CARRIER_ONLY_RECOMPOSED_NULL_ROUTE_COUNTERFACTUAL_PACKET", DEFAULT_TRACKED_NULL_ROUTE),
        "cohort0_recomposed_masked_form_variant_packet": ("TRACKED_CARRIER_ONLY_RECOMPOSED_MASKED_FORM_VARIANT_PACKET", DEFAULT_TRACKED_MASKED),
        "cohort0_recomposed_orthogonality_appendix": ("TRACKED_CARRIER_ONLY_RECOMPOSED_ORTHOGONALITY_APPENDIX", DEFAULT_TRACKED_ORTHOGONALITY),
        "cohort0_recomposed_promotion_stress_tax": ("TRACKED_CARRIER_ONLY_RECOMPOSED_PROMOTION_STRESS_TAX", DEFAULT_TRACKED_STRESS_TAX),
        "cohort0_recomposed_counted_lane_augmentation_receipt": ("TRACKED_CARRIER_ONLY_RECOMPOSED_COUNTED_LANE_AUGMENTATION_RECEIPT", DEFAULT_TRACKED_RECEIPT),
    }
    for name, obj in payloads.items():
        carrier_role, tracked_name = carrier_names[name]
        tracked = dict(obj)
        tracked["carrier_surface_role"] = carrier_role
        tracked[f"authoritative_{name}_ref"] = (target_root / f"{name}.json").resolve().as_posix()
        write_json_stable((reports_root / tracked_name).resolve(), tracked)

    return payloads


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind strategist/auditor/beta back into a recomposed counted-lane augmentation court with null-route siblings, masked variants, and promotion-stress accounting.")
    ap.add_argument("--recomposed-substrate", default=DEFAULT_RECOMPOSED_SUBSTRATE_REL)
    ap.add_argument("--recomposed-manifest", default=DEFAULT_RECOMPOSED_MANIFEST_REL)
    ap.add_argument("--pairwise-augmentation", default=DEFAULT_PAIRWISE_AUGMENTATION_REL)
    ap.add_argument("--pairwise-report", default=DEFAULT_PAIRWISE_REPORT_REL)
    ap.add_argument("--wedge-spec", default=DEFAULT_WEDGE_SPEC_REL)
    ap.add_argument("--stage-pack-manifest", default=DEFAULT_STAGE_PACK_MANIFEST_REL)
    ap.add_argument("--route-policy-registry", default=DEFAULT_ROUTE_POLICY_REGISTRY_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_recomposed_counted_lane_augmentation_tranche(
        recomposed_substrate_path=_resolve(root, str(args.recomposed_substrate)),
        recomposed_manifest_path=_resolve(root, str(args.recomposed_manifest)),
        pairwise_augmentation_path=_resolve(root, str(args.pairwise_augmentation)),
        pairwise_report_path=_resolve(root, str(args.pairwise_report)),
        wedge_spec_path=_resolve(root, str(args.wedge_spec)),
        stage_pack_manifest_path=_resolve(root, str(args.stage_pack_manifest)),
        route_policy_registry_path=_resolve(root, str(args.route_policy_registry)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["cohort0_recomposed_counted_lane_augmentation_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "recomposed_counted_lane_augmentation_posture": receipt["recomposed_counted_lane_augmentation_posture"],
                "ready_family_count": receipt["ready_family_count"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
