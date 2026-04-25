from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOV_ROOT_REL = "KT_PROD_CLEANROOM/governance"

KEYLESS_STATUS_REL = f"{REPORT_ROOT_REL}/kt_sigstore_keyless_status.json"
WS11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sigstore_integration_receipt.json"
SIGSTORE_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_sigstore_publication_bundle.json"
REKOR_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_rekor_inclusion_receipt.json"
SUPPLY_CHAIN_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_supply_chain_policy_receipt.json"
DETERMINISM_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"
TUF_POLICY_REL = f"{GOV_ROOT_REL}/kt_tuf_distribution_policy.json"


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _head_binding_state(*, actual_head: str, bound_head: str) -> str:
    if not bound_head:
        return "HEAD_AGNOSTIC"
    return "CURRENT_HEAD_MATCH" if str(actual_head).strip() == str(bound_head).strip() else "STALE_HEAD_BINDING_VISIBLE"


def _row(
    *,
    mechanism_id: str,
    status: str,
    execution_state: str,
    target_scope: str,
    head_binding_state: str,
    exact_refs: Sequence[str],
    target_surfaces: Sequence[str],
    stronger_claims_forbidden: Sequence[str],
    notes: Sequence[str],
) -> Dict[str, Any]:
    return {
        "mechanism_id": mechanism_id,
        "status": status,
        "execution_state": execution_state,
        "target_scope": target_scope,
        "head_binding_state": head_binding_state,
        "exact_refs": list(exact_refs),
        "target_surfaces": list(target_surfaces),
        "stronger_claims_forbidden": list(stronger_claims_forbidden),
        "notes": list(notes),
    }


def build_wave1_trust_surface_matrix(*, root: Path) -> Dict[str, Any]:
    actual_head = _git_head(root)

    keyless_status = load_json(root / KEYLESS_STATUS_REL)
    ws11_receipt = load_json(root / WS11_RECEIPT_REL)
    supply_chain = load_json(root / SUPPLY_CHAIN_RECEIPT_REL)
    determinism = load_json(root / DETERMINISM_RECEIPT_REL)
    tuf_policy = load_json(root / TUF_POLICY_REL)

    rows: List[Dict[str, Any]] = []

    rows.append(
        _row(
            mechanism_id="sigstore_rekor_keyless",
            status="PASS" if str(keyless_status.get("status", "")).strip() == "PASS" and str(ws11_receipt.get("status", "")).strip() == "PASS" else "HOLD",
            execution_state="EXECUTED_BOUNDED_DECLARED_SURFACES_ONLY",
            target_scope=str(keyless_status.get("declared_public_trust_path_for_pass", "")).strip() or "DECLARED_WS11_SURFACES_ONLY",
            head_binding_state=_head_binding_state(actual_head=actual_head, bound_head=str(keyless_status.get("current_repo_head", "")).strip()),
            exact_refs=[KEYLESS_STATUS_REL, WS11_RECEIPT_REL, SIGSTORE_BUNDLE_REL, REKOR_RECEIPT_REL],
            target_surfaces=[str(item).strip() for item in keyless_status.get("declared_ws11_keyless_surfaces", []) if str(item).strip()],
            stronger_claims_forbidden=[str(item).strip() for item in keyless_status.get("stronger_claim_not_made", []) if str(item).strip()],
            notes=[
                "Wave 1 treats the bounded keyless path as real only on its declared surfaces.",
                "Same-host and broader externality ceilings remain unchanged by this matrix.",
            ],
        )
    )

    supply_chain_refs = []
    lineage = supply_chain.get("supply_chain_lineage", {})
    if isinstance(lineage, dict):
        for key in (
            "source_in_toto_ref",
            "publication_in_toto_ref",
            "build_provenance_ref",
            "verification_summary_ref",
            "build_verification_receipt_ref",
            "supply_chain_layout_ref",
        ):
            value = str(lineage.get(key, "")).strip()
            if value:
                supply_chain_refs.append(value)
    rows.append(
        _row(
            mechanism_id="in_toto_slsa_lineage",
            status="PASS" if str(supply_chain.get("status", "")).strip() == "PASS" else "HOLD",
            execution_state="EXECUTED_BOUNDED_VERIFIER_PUBLICATION_CHAIN_ONLY",
            target_scope=str(supply_chain.get("bounded_current_surface", "")).strip() or "DECLARED_PUBLIC_VERIFIER_MANIFEST_ONLY",
            head_binding_state=_head_binding_state(actual_head=actual_head, bound_head=str(supply_chain.get("current_repo_head", "")).strip()),
            exact_refs=[SUPPLY_CHAIN_RECEIPT_REL, *supply_chain_refs],
            target_surfaces=[str(supply_chain.get("bounded_current_surface", "")).strip()],
            stronger_claims_forbidden=[str(item).strip() for item in supply_chain.get("stronger_claim_not_made", []) if str(item).strip()],
            notes=[
                "The bounded in-toto/SLSA surface is executed for the declared verifier/publication chain.",
                "Wave 1 does not widen this into product or runtime capability proof.",
            ],
        )
    )

    tuf_targets = []
    for row in tuf_policy.get("distribution_targets", []):
        if isinstance(row, dict):
            ref = str(row.get("primary_manifest_ref", "")).strip()
            if ref:
                tuf_targets.append(ref)
    rows.append(
        _row(
            mechanism_id="tuf_distribution",
            status="PASS" if str(tuf_policy.get("status", "")).strip() == "ACTIVE" else "HOLD",
            execution_state="ACTIVE_BOUNDED_CHILD_VERIFIER_DISTRIBUTION_ONLY",
            target_scope=str(tuf_policy.get("scope", "")).strip() or "CHILD_VERIFIER_DISTRIBUTION_ONLY",
            head_binding_state=_head_binding_state(actual_head=actual_head, bound_head=str(tuf_policy.get("current_repo_head", "")).strip()),
            exact_refs=[TUF_POLICY_REL],
            target_surfaces=tuf_targets,
            stronger_claims_forbidden=[str(item).strip() for item in tuf_policy.get("stronger_claim_not_made", []) if str(item).strip()],
            notes=[
                "The active TUF surface remains distribution-only for verifier bundles.",
                "Wave 1 does not narrate this as a deployed updater fleet.",
            ],
        )
    )

    rows.append(
        _row(
            mechanism_id="determinism_envelope",
            status="PASS" if str(determinism.get("status", "")).strip() == "PASS" else "HOLD",
            execution_state="EXECUTED_BOUNDED_CLASS_A_B_C_WITH_CLASS_C_CARRY_FORWARD",
            target_scope="DECLARED_CLASS_A_CLASS_B_AND_BOUNDED_CLASS_C_SURFACES_ONLY",
            head_binding_state=_head_binding_state(actual_head=actual_head, bound_head=str(determinism.get("current_repo_head", "")).strip()),
            exact_refs=[
                DETERMINISM_RECEIPT_REL,
                "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json",
                "KT_PROD_CLEANROOM/governance/kt_artifact_class_policy.json",
            ],
            target_surfaces=[
                "KT_PROD_CLEANROOM/governance/kt_artifact_class_policy.json",
                "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json",
                "KT_PROD_CLEANROOM/reports/ws13_determinism/local/live_validation_index.local.json",
                "KT_PROD_CLEANROOM/reports/ws13_determinism/ci/live_validation_index.ci.json",
            ],
            stronger_claims_forbidden=[
                "repo_root_import_fragility_closed",
                "global_cross_environment_runtime_reproducibility_proven",
                "runtime_capability_upgraded_by_determinism_envelope",
            ],
            notes=[
                "The determinism envelope is real for its declared classes.",
                "Repo-root import fragility remains explicitly visible and unresolved.",
            ],
        )
    )

    executed = all(str(row.get("status", "")).strip() == "PASS" for row in rows)
    stale_rows = [str(row.get("mechanism_id", "")).strip() for row in rows if row.get("head_binding_state") == "STALE_HEAD_BINDING_VISIBLE"]

    return {
        "schema_id": "kt.wave1.trust_stack_surface_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": actual_head,
        "status": "PASS" if executed else "FAIL",
        "scope_boundary": "Wave 1 binds existing trust mechanisms to exact KT surfaces without widening runtime capability or externality claims.",
        "rows": rows,
        "stale_head_binding_visible_for": stale_rows,
        "open_holds_preserved": [
            "C003_ADAPTER_CIVILIZATION_WITH_ZERO_ADAPTERS",
            "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
            "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
            "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
        ],
        "stronger_claim_not_made": [
            "current_head_external_runtime_capability_confirmed",
            "product_or_release_readiness_upgraded",
            "broad_externality_widened",
            "router_or_adapter_scope_opened",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Wave 1 trust surface matrix from exact current-head KT surfaces.")
    parser.add_argument("--output", default=f"{REPORT_ROOT_REL}/kt_wave1_trust_stack_surface_matrix.json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report = build_wave1_trust_surface_matrix(root=root)
    out_path = Path(str(args.output)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    write_json_stable(out_path, report)
    print(json.dumps({"status": report["status"], "stale_head_binding_visible_for": report["stale_head_binding_visible_for"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
