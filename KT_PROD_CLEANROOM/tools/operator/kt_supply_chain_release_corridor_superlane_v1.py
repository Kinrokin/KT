from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator import validate_kt_detached_verifier_clean_room_replay_evidence_review_packet as predecessor
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-supply-chain-release-corridor-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-supply-chain-release-corridor-superlane-v1-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = predecessor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = predecessor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PACKET_BOUND__"
    "SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"
PREFERRED_VALIDATION_OUTCOME = (
    "KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATED__"
    "CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_NEXT"
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PREDECESSOR_MISSING",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT_MOVE_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MISSING",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TUF_METADATA_INVALID",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_BREACH",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TRUST_ZONE_FAILED",
        )
    )
)

PREDECESSOR_INPUTS = {
    "h01_validation_contract": predecessor.OUTPUTS["validation_contract"],
    "h01_validation_receipt": predecessor.OUTPUTS["validation_receipt"],
    "h01_validation_scorecard": predecessor.OUTPUTS["validation_scorecard"],
    "h01_supply_chain_gate_decision": predecessor.OUTPUTS["supply_chain_gate_decision"],
    "h01_next_lawful_move": predecessor.OUTPUTS["next_lawful_move"],
}

SUPPLY_CHAIN_INPUTS = {
    "ws12_supply_chain_policy_receipt": "KT_PROD_CLEANROOM/reports/kt_supply_chain_policy_receipt.json",
    "slsa_provenance_receipt": "KT_PROD_CLEANROOM/reports/kt_slsa_provenance_receipt.json",
    "build_provenance_dsse": "KT_PROD_CLEANROOM/reports/kt_build_provenance.dsse",
    "in_toto_layout": "KT_PROD_CLEANROOM/reports/kt_in_toto_layout.json",
    "in_toto_provenance_dsse": "KT_PROD_CLEANROOM/reports/kt_in_toto_provenance.dsse",
    "source_in_toto_statement": "KT_PROD_CLEANROOM/reports/source_build_attestation/in_toto_statement.json",
    "cryptographic_in_toto_statement": "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
    "sigstore_publication_bundle": "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json",
    "rekor_inclusion_receipt": "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json",
    "tuf_root_initialization": "KT_PROD_CLEANROOM/reports/kt_tuf_root_initialization.json",
    "tuf_distribution_policy": "KT_PROD_CLEANROOM/governance/kt_tuf_distribution_policy.json",
    "supply_chain_layout_policy": "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
    "cyclonedx_sbom": "KT_PROD_CLEANROOM/reports/sbom_cyclonedx.json",
    "public_verifier_sbom": "KT_PROD_CLEANROOM/reports/kt_public_verifier_sbom.json",
    "detached_verifier_sbom": "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_sbom.json",
}

INPUTS = {**PREDECESSOR_INPUTS, **SUPPLY_CHAIN_INPUTS}

OUTPUTS = {
    "corridor_contract": "governance/kt_supply_chain_release_corridor_superlane_v1.json",
    "packet_contract": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_packet_report.md",
    "artifact_manifest": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_artifact_manifest.json",
    "slsa_provenance_review": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_slsa_provenance_review.json",
    "in_toto_layout_links_review": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_in_toto_layout_links_review.json",
    "sigstore_rekor_bundle_review": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_sigstore_rekor_bundle_review.json",
    "sbom_review": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_sbom_review.json",
    "spdx_sbom": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_spdx_sbom.json",
    "tuf_metadata_set": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_tuf_metadata_set.json",
    "release_integrity_receipt": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_release_integrity_receipt.json",
    "attack_test_matrix": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_attack_test_matrix.json",
    "claim_boundary_receipt": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_claim_boundary_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_supply_chain_release_corridor_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_supply_chain_release_corridor_superlane_v1.py",
    }
)

AUTHORITY_DRIFT_KEYS = evidence_packet.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "release_execution_authorized",
        "release_executed",
        "supply_chain_release_corridor_validated",
        "claim_compiler_authorized",
        "external_audit_completed",
        "external_audit_claimed_complete",
    }
)

FORBIDDEN_CLAIM_PATTERNS = evidence_packet.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bsupply[- ]chain release (?:is )?(?:executed|complete|completed|validated)\b", re.IGNORECASE),
    re.compile(r"\brelease corridor (?:is )?(?:executed|complete|completed|validated)\b", re.IGNORECASE),
    re.compile(r"\bclaim compiler (?:is )?authorized\b", re.IGNORECASE),
)


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> NoReturn:
    raise LaneFailure(code, detail)


def _status_relpaths(status: str) -> list[str]:
    rows: list[str] = []
    for line in status.splitlines():
        if not line.strip():
            continue
        rel = line[3:].strip().replace("\\", "/")
        if rel:
            rows.append(rel)
    return rows


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if (branch == "main" or branch.startswith(REPLAY_BRANCH_PREFIX)) and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT", "main/replay authoring requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT", "dirty worktree outside supply-chain corridor scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MISSING", f"missing input {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _validate_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("supply_chain_release_corridor_next") is not True:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PREDECESSOR_MISSING", f"{role} did not select supply-chain corridor next")
        if payload.get("supply_chain_release_corridor_authorized") is not False:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_BREACH", f"{role} prematurely authorizes supply-chain release corridor")


def _status_is_pass(payload: Dict[str, Any]) -> bool:
    status = str(payload.get("status", "")).strip().upper()
    return status == "PASS"


def _validate_supply_chain_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in (
        "ws12_supply_chain_policy_receipt",
        "slsa_provenance_receipt",
        "sigstore_publication_bundle",
        "rekor_inclusion_receipt",
        "tuf_root_initialization",
    ):
        if not _status_is_pass(payloads[role]):
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED", f"{role} must have status PASS")

    cyclonedx = payloads["cyclonedx_sbom"]
    if cyclonedx.get("bomFormat") != "CycloneDX":
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID", "CycloneDX SBOM must declare bomFormat CycloneDX")
    if not isinstance(cyclonedx.get("components", []), list):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID", "CycloneDX SBOM must include components list")

    layout = payloads["supply_chain_layout_policy"]
    if layout.get("status") != "ACTIVE":
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED", "supply-chain layout policy must be ACTIVE")
    if "in-toto" not in str(layout.get("statement_predicate", {}).get("statement_type", layout.get("statement_type", ""))).lower() and "in-toto" not in str(layout).lower():
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED", "supply-chain layout must be in-toto aligned")

    tuf_root = payloads["tuf_root_initialization"]
    if not str(tuf_root.get("trust_root_id", "")).strip():
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TUF_METADATA_INVALID", "TUF root initialization must declare trust_root_id")


def _validate_claim_boundary(predecessor_payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in predecessor_payloads.items():
        for key, value in evidence_packet._walk(payload):  # noqa: SLF001 - reuse hardened lane scanner.
            leaf_key = evidence_packet._leaf_key(key)  # noqa: SLF001
            if leaf_key in AUTHORITY_DRIFT_KEYS and value is not False and leaf_key not in {"supply_chain_release_corridor_next"}:
                _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not evidence_packet._is_negative_field(key) and not evidence_packet._is_machine_routing_field(key):  # noqa: SLF001
                clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", value, flags=re.IGNORECASE)
                for clause in clauses:
                    if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not evidence_packet._is_negative_text(clause):  # noqa: SLF001
                        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")


def _spdx_sbom(*, generated_utc: str, head: str, inputs: list[Dict[str, str]]) -> Dict[str, Any]:
    packages = [
        {
            "SPDXID": f"SPDXRef-{row['role'].replace('_', '-')}",
            "name": row["path"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": row["sha256"]}],
        }
        for row in inputs
        if row["role"] in {"public_verifier_sbom", "detached_verifier_sbom", "cyclonedx_sbom"}
    ]
    return {
        "schema_id": "kt.supply_chain_release_corridor.spdx_sbom.v1",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "KT supply-chain release corridor bounded SBOM bridge",
        "documentNamespace": f"https://kt.local/spdx/supply-chain-release-corridor/{head}",
        "creationInfo": {
            "created": generated_utc,
            "creators": ["Tool: kt_supply_chain_release_corridor_superlane_v1"],
        },
        "packages": packages,
        "external_audit_completed": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_claimed_proven": False,
    }


def _tuf_metadata_set(payloads: Dict[str, Dict[str, Any]], *, generated_utc: str, input_bindings: list[Dict[str, str]]) -> Dict[str, Any]:
    trust_root_id = str(payloads["tuf_root_initialization"].get("trust_root_id", "")).strip()
    target_rows = [
        {"path": row["path"], "sha256": row["sha256"], "length": None}
        for row in input_bindings
        if row["role"] in {"public_verifier_sbom", "detached_verifier_sbom", "sigstore_publication_bundle", "rekor_inclusion_receipt"}
    ]
    return {
        "schema_id": "kt.supply_chain_release_corridor.tuf_metadata_set.v1",
        "artifact_id": "KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TUF_METADATA_SET",
        "artifact_role": "tuf_metadata_set",
        "metadata_mode": "PRE_RELEASE_CORRIDOR_AUTHORING_ONLY",
        "generated_utc": generated_utc,
        "root": {"role": "root", "trust_root_id": trust_root_id, "status": "BOUND_FROM_EXISTING_TUF_ROOT_INITIALIZATION"},
        "targets": {"role": "targets", "targets": target_rows},
        "snapshot": {"role": "snapshot", "targets_bound": len(target_rows), "freeze_attack_must_fail_closed": True},
        "timestamp": {"role": "timestamp", "expires_required": True, "expired_metadata_must_fail_closed": True},
        "release_execution_authorized": False,
        "external_audit_completed": False,
    }


def _attack_matrix() -> Dict[str, Any]:
    scenarios = [
        ("artifact_swap_test", "Artifact digest swap must fail closed against bound SHA-256 inputs."),
        ("tuf_rollback_test", "Older TUF metadata must fail closed before any release execution lane."),
        ("tuf_freeze_test", "Expired or frozen timestamp/snapshot metadata must fail closed."),
        ("expired_metadata_test", "Expired metadata is a blocker, not a warning-only release condition."),
        ("missing_sbom_test", "Missing CycloneDX or SPDX SBOM evidence blocks validation."),
        ("forged_rekor_bundle_test", "Forged Rekor/Sigstore bundle evidence blocks validation."),
        ("in_toto_layout_drift_test", "in-toto layout or link drift blocks validation."),
    ]
    return {
        "schema_id": "kt.supply_chain_release_corridor.attack_test_matrix.v1",
        "artifact_id": "KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ATTACK_TEST_MATRIX",
        "artifact_role": "attack_test_matrix",
        "attack_scenarios": [
            {"scenario_id": scenario_id, "expected_validation_behavior": "FAIL_CLOSED", "detail": detail}
            for scenario_id, detail in scenarios
        ],
        "release_execution_authorized": False,
    }


def _base(
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.supply_chain_release_corridor.authoring.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "AUTHORING_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "preferred_validation_outcome": PREFERRED_VALIDATION_OUTCOME,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "predecessor_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "current_branch": branch,
        "current_git_head": head,
        "current_branch_head": head,
        "current_main": current_main_head,
        "current_main_head": current_main_head,
        "generated_utc": generated_utc,
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "trust_zone_validation": trust_zone_validation,
        "detached_verifier_h01_exit_validated": True,
        "supply_chain_release_corridor_packet_authored": True,
        "supply_chain_release_corridor_validated": False,
        "release_execution_authorized": False,
        "release_executed": False,
        "claim_compiler_authorized": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
        "commercial_activation_claimed": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_claimed": False,
        "seven_b_amplification_claimed_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "fp0_or_highway_promoted_to_authority": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "claim_boundary_passed": True,
    }


def _artifact(base: Dict[str, Any], *, role: str, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id, "artifact_role": role})
    payload.update(extra)
    return payload


def _outputs(base: Dict[str, Any], supply_payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    input_bindings = list(base["input_bindings"])
    common_extra = {
        "slsa_provenance_bound": True,
        "in_toto_layout_bound": True,
        "sigstore_rekor_bound": True,
        "cyclonedx_sbom_bound": True,
        "spdx_sbom_authored": True,
        "tuf_metadata_roles_authored": ["root", "targets", "snapshot", "timestamp"],
    }
    manifest_rows = [
        {"role": row["role"], "path": row["path"], "sha256": row["sha256"], "required_for_validation": True}
        for row in input_bindings
    ]
    validation_checks = [
        "recompute_all_bound_hashes",
        "validate_slsa_provenance_receipt",
        "validate_in_toto_layout_and_links",
        "validate_sigstore_rekor_bundle",
        "validate_spdx_and_cyclonedx_sboms",
        "validate_tuf_root_targets_snapshot_timestamp",
        "run_artifact_swap_negative_test",
        "run_tuf_rollback_freeze_expired_metadata_negative_tests",
        "run_missing_sbom_negative_test",
        "enforce_claim_boundary",
    ]
    return {
        "corridor_contract": _artifact(
            base,
            role="corridor_contract",
            schema_id="kt.supply_chain_release_corridor.superlane_contract.v1",
            artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_CONTRACT",
            corridor_scope="author validation-ready supply-chain release law; do not execute release",
            required_evidence_classes=["SLSA", "in-toto", "Sigstore/Rekor", "SPDX", "CycloneDX", "TUF"],
            validation_checks=validation_checks,
            **common_extra,
        ),
        "packet_contract": _artifact(base, role="packet_contract", schema_id="kt.supply_chain_release_corridor.packet_contract.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PACKET_CONTRACT", **common_extra),
        "packet_receipt": _artifact(base, role="packet_receipt", schema_id="kt.supply_chain_release_corridor.packet_receipt.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PACKET_RECEIPT", verdict="SUPPLY_CHAIN_RELEASE_CORRIDOR_PACKET_BOUND_VALIDATION_NEXT", **common_extra),
        "artifact_manifest": _artifact(base, role="artifact_manifest", schema_id="kt.supply_chain_release_corridor.artifact_manifest.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MANIFEST", artifacts=manifest_rows),
        "slsa_provenance_review": _artifact(base, role="slsa_provenance_review", schema_id="kt.supply_chain_release_corridor.slsa_provenance_review.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SLSA_PROVENANCE_REVIEW", status="READY_FOR_VALIDATION", source_ref=SUPPLY_CHAIN_INPUTS["slsa_provenance_receipt"]),
        "in_toto_layout_links_review": _artifact(base, role="in_toto_layout_links_review", schema_id="kt.supply_chain_release_corridor.in_toto_layout_links_review.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_IN_TOTO_LAYOUT_LINKS_REVIEW", status="READY_FOR_VALIDATION", source_refs=[SUPPLY_CHAIN_INPUTS["supply_chain_layout_policy"], SUPPLY_CHAIN_INPUTS["in_toto_layout"], SUPPLY_CHAIN_INPUTS["in_toto_provenance_dsse"]]),
        "sigstore_rekor_bundle_review": _artifact(base, role="sigstore_rekor_bundle_review", schema_id="kt.supply_chain_release_corridor.sigstore_rekor_bundle_review.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SIGSTORE_REKOR_BUNDLE_REVIEW", status="READY_FOR_VALIDATION", source_refs=[SUPPLY_CHAIN_INPUTS["sigstore_publication_bundle"], SUPPLY_CHAIN_INPUTS["rekor_inclusion_receipt"]]),
        "sbom_review": _artifact(base, role="sbom_review", schema_id="kt.supply_chain_release_corridor.sbom_review.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_REVIEW", status="READY_FOR_VALIDATION", cyclonedx_ref=SUPPLY_CHAIN_INPUTS["cyclonedx_sbom"], spdx_ref=OUTPUTS["spdx_sbom"], public_verifier_sbom_ref=SUPPLY_CHAIN_INPUTS["public_verifier_sbom"], detached_verifier_sbom_ref=SUPPLY_CHAIN_INPUTS["detached_verifier_sbom"]),
        "spdx_sbom": _spdx_sbom(generated_utc=str(base["generated_utc"]), head=str(base["current_git_head"]), inputs=input_bindings),
        "tuf_metadata_set": _tuf_metadata_set(supply_payloads, generated_utc=str(base["generated_utc"]), input_bindings=input_bindings),
        "release_integrity_receipt": _artifact(base, role="release_integrity_receipt", schema_id="kt.supply_chain_release_corridor.release_integrity_receipt.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_RELEASE_INTEGRITY_RECEIPT", release_integrity_bound=True, artifact_swap_must_fail_closed=True, release_execution_authorized=False),
        "attack_test_matrix": _attack_matrix(),
        "claim_boundary_receipt": _artifact(base, role="claim_boundary_receipt", schema_id="kt.supply_chain_release_corridor.claim_boundary_receipt.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_RECEIPT", allowed_current_claim="Supply-chain release corridor packet is authored for validation next.", forbidden_claims=["external audit completed", "commercial activation authorized", "7B amplification proven", "release executed", "claim compiler authorized"], **common_extra),
        "validation_plan": _artifact(base, role="validation_plan", schema_id="kt.supply_chain_release_corridor.validation_plan.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_PLAN", validation_checks=validation_checks, expected_validation_outcome=PREFERRED_VALIDATION_OUTCOME),
        "validation_reason_codes": _artifact(base, role="validation_reason_codes", schema_id="kt.supply_chain_release_corridor.validation_reason_codes.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_REASON_CODES", reason_codes=list(REASON_CODES)),
        "next_lawful_move": _artifact(base, role="next_lawful_move", schema_id="kt.supply_chain_release_corridor.next_lawful_move.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT_LAWFUL_MOVE_RECEIPT", current_execution_lane=AUTHORITATIVE_LANE, current_execution_outcome=SELECTED_OUTCOME, next_lawful_move=NEXT_LAWFUL_MOVE),
        "packet_report": _report(base),
    }


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Supply-Chain Release Corridor Packet",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "Supply-chain release corridor validated: false",
            "Release execution authorized: false",
            "External audit completed: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    predecessor_payloads = {role: _load_json(root, raw, label=role) for role, raw in PREDECESSOR_INPUTS.items()}
    supply_payloads = {role: _load_json(root, raw, label=role) for role, raw in SUPPLY_CHAIN_INPUTS.items()}
    _validate_predecessor(predecessor_payloads)
    _validate_supply_chain_inputs(supply_payloads)
    _validate_claim_boundary(predecessor_payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    input_bindings = _input_bindings(root)
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base, supply_payloads)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if role == "packet_report":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(outputs[role]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Author the KT supply-chain release corridor packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
