from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
PRODUCT_ROOT_REL = "KT_PROD_CLEANROOM/product"

TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
DEFERRAL_HEARTBEAT_REL = f"{REPORT_ROOT_REL}/c006_deferral_heartbeat.json"
PRODUCT_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_product_truth_surface.json"
COMMERCIAL_TRUTH_PACKET_REL = f"{REPORT_ROOT_REL}/commercial_truth_packet.json"
PUBLIC_VERIFIER_KIT_REL = f"{REPORT_ROOT_REL}/public_verifier_kit.json"
C006_SECOND_HOST_KIT_REL = f"{REPORT_ROOT_REL}/c006_second_host_kit.json"
EXTERNAL_AUDIT_PACKET_REL = f"{REPORT_ROOT_REL}/external_audit_packet_manifest.json"

PRODUCT_DEPLOYMENT_PROFILES_REL = f"{PRODUCT_ROOT_REL}/deployment_profiles.json"
CLIENT_WRAPPER_SPEC_REL = f"{PRODUCT_ROOT_REL}/client_wrapper_spec.json"
OPERATOR_RUNBOOK_REL = f"{PRODUCT_ROOT_REL}/operator_runbook_v2.md"
SUPPORT_BOUNDARY_REL = f"{PRODUCT_ROOT_REL}/support_boundary.json"
ONE_PAGE_PRODUCT_TRUTH_REL = f"{PRODUCT_ROOT_REL}/one_page_product_truth_surface.md"
NIST_MATRIX_REL = f"{PRODUCT_ROOT_REL}/nist_mapping_matrix.json"
ISO_MATRIX_REL = f"{PRODUCT_ROOT_REL}/iso_42001_mapping_matrix.json"
EU_AI_MATRIX_REL = f"{PRODUCT_ROOT_REL}/eu_ai_act_alignment_matrix.json"
OPERATOR_QUICKSTART_REL = "KT_PROD_CLEANROOM/docs/operator/RUN_KT_IN_30_MINUTES.md"

DEPLOYMENT_PROFILES_OUTPUT_REL = f"{REPORT_ROOT_REL}/deployment_profiles.json"
PRODUCT_INSTALL_RECEIPT_REL = f"{REPORT_ROOT_REL}/product_install_15m_receipt.json"
OPERATOR_HANDOFF_RECEIPT_REL = f"{REPORT_ROOT_REL}/operator_handoff_receipt.json"
STANDARDS_MAPPING_RECEIPT_REL = f"{REPORT_ROOT_REL}/standards_mapping_receipt.json"

REQUIRED_PROFILE_IDS = {
    "local_verifier_mode",
    "team_pilot_mode",
    "regulated_workflow_mode",
}

LEGACY_OPERATOR_PROFILES = [
    {
        "implementation_path": "KT_PROD_CLEANROOM/tools/operator/kt_cli.py",
        "profile_id": "canonical_operator_safe_run",
        "program_id": "program.safe_run",
    },
    {
        "implementation_path": "KT_PROD_CLEANROOM/tools/operator/truth_surface_sync.py",
        "profile_id": "truth_publication_operator",
        "program_id": "program.truth.surface_sync",
    },
    {
        "implementation_path": "KT_PROD_CLEANROOM/tools/delivery/delivery_contract_validator.py",
        "profile_id": "delivery_pack_generation",
        "program_id": "program.delivery.contract.validate",
    },
]


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _read_text(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def _contains_all(text: str, needles: Sequence[str]) -> bool:
    lowered = str(text).lower()
    return all(str(needle).lower() in lowered for needle in needles)


def _load_required_object(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required W7 surface: {rel}")
    return load_json(path)


def _profile_rows(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = source.get("profiles", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: product deployment profiles missing profiles list")
    normalized: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: product deployment profile row must be an object")
        normalized.append(dict(row))
    return normalized


def build_deployment_profiles_report(*, root: Path) -> Dict[str, Any]:
    truth_lock = _load_required_object(root, TRUTH_LOCK_REL)
    heartbeat = _load_required_object(root, DEFERRAL_HEARTBEAT_REL)
    source = _load_required_object(root, PRODUCT_DEPLOYMENT_PROFILES_REL)
    rows = _profile_rows(source)
    profile_ids = {str(row.get("profile_id", "")).strip() for row in rows}
    all_e1 = all(str(row.get("max_externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY" for row in rows)
    status = (
        "ACTIVE"
        if str(source.get("status", "")).strip() == "ACTIVE"
        and str(truth_lock.get("status", "")).strip() == "PASS"
        and str(heartbeat.get("status", "")).strip() == "PASS"
        and profile_ids == REQUIRED_PROFILE_IDS
        and all_e1
        else "FAIL"
    )
    return {
        "claim_boundary": "These deployment profiles describe the bounded E1 product wedge only. They do not widen runtime, externality, or enterprise claims.",
        "current_git_head": _git_head(root),
        "generated_utc": utc_now_iso_z(),
        "legacy_operator_profiles": LEGACY_OPERATOR_PROFILES,
        "product_profile_count": len(rows),
        "product_profiles": rows,
        "profile_order": list(source.get("profile_order", [])),
        "profiles": rows,
        "schema_id": "kt.deployment_profiles.v2",
        "source_ref": PRODUCT_DEPLOYMENT_PROFILES_REL,
        "status": status,
    }


def build_product_install_receipt(*, root: Path, deployment_profiles: Dict[str, Any]) -> Dict[str, Any]:
    truth_lock = _load_required_object(root, TRUTH_LOCK_REL)
    heartbeat = _load_required_object(root, DEFERRAL_HEARTBEAT_REL)
    product_truth = _load_required_object(root, PRODUCT_TRUTH_REL)
    commercial_truth = _load_required_object(root, COMMERCIAL_TRUTH_PACKET_REL)
    verifier_kit = _load_required_object(root, PUBLIC_VERIFIER_KIT_REL)
    c006_second_host_kit = _load_required_object(root, C006_SECOND_HOST_KIT_REL)
    wrapper_spec = _load_required_object(root, CLIENT_WRAPPER_SPEC_REL)
    support_boundary = _load_required_object(root, SUPPORT_BOUNDARY_REL)

    profiles = list(deployment_profiles.get("profiles", []))
    local_profile = next((row for row in profiles if str(row.get("profile_id", "")).strip() == "local_verifier_mode"), {})
    wrapper_commands = [str(row.get("command", "")).strip() for row in wrapper_spec.get("entrypoints", []) if isinstance(row, dict)]
    verifier_commands = [str(item).strip() for item in verifier_kit.get("entrypoints", []) if str(item).strip()]
    truth_text = _read_text(root, ONE_PAGE_PRODUCT_TRUTH_REL)
    runbook_text = _read_text(root, OPERATOR_RUNBOOK_REL)

    checks = [
        {
            "check_id": "current_head_ceiling_preserved",
            "pass": (
                str(truth_lock.get("claim_ceiling_enforcements", {}).get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
                and str(heartbeat.get("machine_effective_state", {}).get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
            ),
            "ref": TRUTH_LOCK_REL,
        },
        {
            "check_id": "three_buyer_profiles_declared",
            "pass": {str(row.get("profile_id", "")).strip() for row in profiles} == REQUIRED_PROFILE_IDS,
            "ref": PRODUCT_DEPLOYMENT_PROFILES_REL,
        },
        {
            "check_id": "local_profile_install_budget_under_15_minutes",
            "pass": int(local_profile.get("install_to_pass_fail_minutes", 0) or 0) <= 15,
            "ref": PRODUCT_DEPLOYMENT_PROFILES_REL,
        },
        {
            "check_id": "wrapper_entrypoints_match_verifier_kit",
            "pass": wrapper_commands == verifier_commands,
            "ref": CLIENT_WRAPPER_SPEC_REL,
        },
        {
            "check_id": "runbook_and_truth_surface_restate_bounded_e1_only",
            "pass": _contains_all(
                truth_text + "\n" + runbook_text,
                [
                    "E1",
                    "Do not claim `E2`",
                    "Do not claim enterprise readiness",
                ],
            ),
            "ref": ONE_PAGE_PRODUCT_TRUTH_REL,
        },
        {
            "check_id": "support_boundary_stays_no_training_and_no_cutover",
            "pass": (
                support_boundary.get("no_training_default") is True
                and support_boundary.get("runtime_cutover_allowed") is False
                and "enterprise_readiness_claims" in support_boundary.get("unsupported_surfaces", [])
            ),
            "ref": SUPPORT_BOUNDARY_REL,
        },
        {
            "check_id": "bounded_pack_stays_green",
            "pass": (
                str(product_truth.get("status", "")).strip() == "PASS"
                and str(commercial_truth.get("status", "")).strip() == "PASS"
                and str(verifier_kit.get("status", "")).strip() == "PASS"
                and str(c006_second_host_kit.get("status", "")).strip() == "PASS"
            ),
            "ref": COMMERCIAL_TRUTH_PACKET_REL,
        },
    ]
    status = "PASS" if all(bool(item["pass"]) for item in checks) else "FAIL"
    return {
        "checks": checks,
        "claim_boundary": "This receipt proves only that the bounded E1 wedge is packaged into a buyer-simple install-to-pass/fail flow. It does not widen externality or commercial claims.",
        "current_git_head": _git_head(root),
        "generated_utc": utc_now_iso_z(),
        "installation_entrypoints": wrapper_commands,
        "local_profile_id": "local_verifier_mode",
        "local_profile_install_to_pass_fail_minutes": int(local_profile.get("install_to_pass_fail_minutes", 0) or 0),
        "pass_fail_surface_refs": list(wrapper_spec.get("pass_fail_surface_refs", [])),
        "schema_id": "kt.product.install_15m_receipt.v1",
        "source_refs": [
            PRODUCT_DEPLOYMENT_PROFILES_REL,
            CLIENT_WRAPPER_SPEC_REL,
            SUPPORT_BOUNDARY_REL,
            ONE_PAGE_PRODUCT_TRUTH_REL,
            OPERATOR_RUNBOOK_REL,
            COMMERCIAL_TRUTH_PACKET_REL,
            PUBLIC_VERIFIER_KIT_REL,
            C006_SECOND_HOST_KIT_REL,
        ],
        "status": status,
    }


def build_operator_handoff_receipt(*, root: Path, product_install_receipt: Dict[str, Any]) -> Dict[str, Any]:
    verifier_kit = _load_required_object(root, PUBLIC_VERIFIER_KIT_REL)
    audit_packet = _load_required_object(root, EXTERNAL_AUDIT_PACKET_REL)
    commercial_truth = _load_required_object(root, COMMERCIAL_TRUTH_PACKET_REL)
    c006_second_host_kit = _load_required_object(root, C006_SECOND_HOST_KIT_REL)

    handoff_bundle_refs = [
        ONE_PAGE_PRODUCT_TRUTH_REL,
        CLIENT_WRAPPER_SPEC_REL,
        SUPPORT_BOUNDARY_REL,
        OPERATOR_RUNBOOK_REL,
        COMMERCIAL_TRUTH_PACKET_REL,
        PUBLIC_VERIFIER_KIT_REL,
        EXTERNAL_AUDIT_PACKET_REL,
        C006_SECOND_HOST_KIT_REL,
        OPERATOR_QUICKSTART_REL,
    ]
    checks = [
        {
            "check_id": "product_install_receipt_passes",
            "pass": str(product_install_receipt.get("status", "")).strip() == "PASS",
            "ref": PRODUCT_INSTALL_RECEIPT_REL,
        },
        {
            "check_id": "handoff_bundle_refs_exist",
            "pass": all((root / ref).exists() for ref in handoff_bundle_refs),
            "ref": OPERATOR_RUNBOOK_REL,
        },
        {
            "check_id": "bounded_packet_surfaces_remain_pass",
            "pass": (
                str(verifier_kit.get("status", "")).strip() == "PASS"
                and str(audit_packet.get("status", "")).strip() == "PASS"
                and str(commercial_truth.get("status", "")).strip() == "PASS"
                and str(c006_second_host_kit.get("status", "")).strip() == "PASS"
            ),
            "ref": EXTERNAL_AUDIT_PACKET_REL,
        },
    ]
    status = "PASS" if all(bool(item["pass"]) for item in checks) else "FAIL"
    return {
        "checks": checks,
        "claim_boundary": "This receipt proves that an operator can be handed one bounded product bundle without repo archaeology. It does not prove cross-host or enterprise operation.",
        "current_git_head": _git_head(root),
        "generated_utc": utc_now_iso_z(),
        "handoff_bundle_refs": handoff_bundle_refs,
        "independent_operator_target_minutes": int(product_install_receipt.get("local_profile_install_to_pass_fail_minutes", 0) or 0),
        "schema_id": "kt.product.operator_handoff_receipt.v1",
        "status": status,
    }


def build_standards_mapping_receipt(*, root: Path) -> Dict[str, Any]:
    matrices = [
        _load_required_object(root, NIST_MATRIX_REL),
        _load_required_object(root, ISO_MATRIX_REL),
        _load_required_object(root, EU_AI_MATRIX_REL),
    ]
    refs = [NIST_MATRIX_REL, ISO_MATRIX_REL, EU_AI_MATRIX_REL]
    checks = []
    for ref, payload in zip(refs, matrices):
        checks.append(
            {
                "check_id": f"{Path(ref).stem}_informative_only",
                "pass": (
                    str(payload.get("status", "")).strip() == "ACTIVE"
                    and payload.get("informative_only") is True
                    and payload.get("not_certification_or_legal_determination") is True
                    and str(payload.get("current_claim_ceiling", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
                ),
                "ref": ref,
            }
        )
    status = "PASS" if all(bool(item["pass"]) for item in checks) else "FAIL"
    return {
        "checks": checks,
        "claim_boundary": "These mappings are informative-only legibility surfaces for the bounded E1 wedge. They do not claim certification, compliance, or legal clearance.",
        "current_git_head": _git_head(root),
        "generated_utc": utc_now_iso_z(),
        "matrix_count": len(matrices),
        "matrix_refs": refs,
        "schema_id": "kt.product.standards_mapping_receipt.v1",
        "status": status,
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile the bounded W7 product plane and validate 15-minute operator install surfaces.")
    parser.add_argument("--deployment-profiles-output", default=DEPLOYMENT_PROFILES_OUTPUT_REL)
    parser.add_argument("--product-install-output", default=PRODUCT_INSTALL_RECEIPT_REL)
    parser.add_argument("--operator-handoff-output", default=OPERATOR_HANDOFF_RECEIPT_REL)
    parser.add_argument("--standards-mapping-output", default=STANDARDS_MAPPING_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    deployment_profiles = build_deployment_profiles_report(root=root)
    product_install_receipt = build_product_install_receipt(root=root, deployment_profiles=deployment_profiles)
    operator_handoff_receipt = build_operator_handoff_receipt(root=root, product_install_receipt=product_install_receipt)
    standards_mapping_receipt = build_standards_mapping_receipt(root=root)

    write_json_stable(_resolve(root, str(args.deployment_profiles_output)), deployment_profiles)
    write_json_stable(_resolve(root, str(args.product_install_output)), product_install_receipt)
    write_json_stable(_resolve(root, str(args.operator_handoff_output)), operator_handoff_receipt)
    write_json_stable(_resolve(root, str(args.standards_mapping_output)), standards_mapping_receipt)

    summary = {
        "deployment_profile_count": deployment_profiles["product_profile_count"],
        "local_install_to_pass_fail_minutes": product_install_receipt["local_profile_install_to_pass_fail_minutes"],
        "standards_mapping_status": standards_mapping_receipt["status"],
        "status": (
            "PASS"
            if all(
                item.get("status") == "PASS"
                for item in (product_install_receipt, operator_handoff_receipt, standards_mapping_receipt)
            )
            and deployment_profiles.get("status") == "ACTIVE"
            else "FAIL"
        ),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
