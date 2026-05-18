from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_supply_chain_release_corridor_superlane_v1 as packet
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-supply-chain-release-corridor-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-supply-chain-release-corridor-validation-on-main"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "VALIDATE_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATED__CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_NEXT"
NEXT_LAWFUL_MOVE = "AUTHOR_KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_SUPERLANE_V1"

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PACKET_MISSING",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_OUTCOME_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_MISSING",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_STATUS_FAILED",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ATTACK_MATRIX_INCOMPLETE",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_REASON_CODE_DUPLICATE",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_CLAIM_BOUNDARY_BREACH",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TRUST_ZONE_FAILED",
        )
    )
)

JSON_PACKET_OUTPUTS = {
    role: raw for role, raw in packet.OUTPUTS.items() if raw.endswith(".json")
}

BASE_PACKET_ROLES = frozenset(
    role
    for role in JSON_PACKET_OUTPUTS
    if role not in {"spdx_sbom", "tuf_metadata_set", "attack_test_matrix"}
)

OUTPUTS = {
    "validation_contract": "governance/kt_supply_chain_release_corridor_validation_v1.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_report.md",
    "validation_scorecard": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_scorecard.json",
    "claim_compiler_gate_decision": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_decision.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_validation_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/validate_kt_supply_chain_release_corridor_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_validate_kt_supply_chain_release_corridor_superlane_v1.py",
    }
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
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT", "main/replay validation requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT", "dirty worktree outside validation scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _load_packet_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in JSON_PACKET_OUTPUTS.items()}


def _load_supply_chain_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in packet.SUPPLY_CHAIN_INPUTS.items()}


def _validate_packet_shape(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in BASE_PACKET_ROLES:
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("supply_chain_release_corridor_packet_authored") is not True:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PACKET_MISSING", f"{role} is not an authored packet artifact")
        if payload.get("supply_chain_release_corridor_validated") is not False:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", f"{role} validates the corridor before validation lane")
        if payload.get("release_execution_authorized") is not False or payload.get("release_executed") is not False:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", f"{role} authorizes or executes release")
        if payload.get("external_audit_completed") is not False or payload.get("external_audit_claimed_complete") is not False:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", f"{role} claims external audit completion")
        if payload.get("commercial_activation_claim_authorized") is not False:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", f"{role} authorizes commercial activation claims")

    receipt = payloads["packet_receipt"]
    if receipt.get("release_execution_authorized") is not False or receipt.get("release_executed") is not False:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", "packet receipt authorizes or executes release")
    if payloads["claim_boundary_receipt"].get("claim_compiler_authorized") is not False:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", "claim compiler authorized before validation")


def _validate_reason_codes(payloads: Dict[str, Dict[str, Any]]) -> None:
    reason_codes = payloads["validation_reason_codes"].get("reason_codes", [])
    if not isinstance(reason_codes, list) or not reason_codes:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_MISSING", "validation reason codes missing")
    if len(reason_codes) != len(set(reason_codes)):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_REASON_CODE_DUPLICATE", "validation reason codes must be unique")


def _validate_bound_source_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    contract = payloads["packet_contract"]
    rows = contract.get("input_bindings", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", "packet contract input bindings missing")

    expected_by_role = contract.get("binding_hashes", {})
    if not isinstance(expected_by_role, dict):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", "packet contract binding_hashes missing")

    validated_rows: list[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", "input binding row must be object")
        role = str(row.get("role", "")).strip()
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not role or not raw or not expected:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", "input binding row incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_MISSING", f"missing bound input {role}: {raw}")
        actual = file_sha256(path)
        if actual != expected:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", f"{role} source hash mismatch")
        if expected_by_role.get(f"{role}_hash") != actual:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes mismatch")
        validated_rows.append({"role": role, "path": raw, "sha256": actual})

    for role in BASE_PACKET_ROLES:
        payload = payloads[role]
        if payload.get("input_bindings") != rows:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", f"{role} input_bindings drifted from packet contract")
        if payload.get("binding_hashes") != expected_by_role:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes drifted from packet contract")
    return validated_rows


def _validate_generated_timestamp_coherence(payloads: Dict[str, Dict[str, Any]]) -> None:
    expected = payloads["packet_contract"].get("generated_utc")
    if not expected:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PACKET_MISSING", "packet contract generated_utc missing")
    for role, payload in payloads.items():
        if role == "tuf_metadata_set" and payload.get("generated_utc") != expected:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF metadata set generated_utc drifted from packet")
        if "generated_utc" in payload and payload.get("generated_utc") != expected:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PACKET_MISSING", f"{role} generated_utc drifted from packet")


def _validate_supply_chain_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    try:
        packet._validate_supply_chain_inputs(payloads)  # noqa: SLF001 - validation must reuse authoring evidence checks.
    except packet.LaneFailure as exc:
        code = {
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED": "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_STATUS_FAILED",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID": "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID",
            "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_TUF_METADATA_INVALID": "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID",
        }.get(exc.code, "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_STATUS_FAILED")
        _fail(code, exc.detail)


def _validate_sboms(payloads: Dict[str, Dict[str, Any]], input_bindings: list[Dict[str, str]]) -> None:
    by_path = {row["path"]: row["sha256"] for row in input_bindings}
    spdx = payloads["spdx_sbom"]
    if spdx.get("spdxVersion") != "SPDX-2.3" or not isinstance(spdx.get("packages"), list):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID", "SPDX SBOM shape invalid")
    package_paths = set()
    for package_row in spdx["packages"]:
        name = str(package_row.get("name", ""))
        checksums = package_row.get("checksums", [])
        if not isinstance(checksums, list) or not checksums:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID", "SPDX package checksum missing")
        digest = checksums[0].get("checksumValue")
        if name not in by_path or digest != by_path[name]:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID", f"SPDX package {name} does not bind input digest")
        package_paths.add(name)
    required = {
        packet.SUPPLY_CHAIN_INPUTS["public_verifier_sbom"],
        packet.SUPPLY_CHAIN_INPUTS["detached_verifier_sbom"],
        packet.SUPPLY_CHAIN_INPUTS["cyclonedx_sbom"],
    }
    if not required <= package_paths:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID", "SPDX SBOM missing required package rows")
    if spdx.get("external_audit_completed") is not False or spdx.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_CLAIM_BOUNDARY_BREACH", "SPDX SBOM claim boundary drifted")


def _validate_tuf_metadata(payloads: Dict[str, Dict[str, Any]], input_bindings: list[Dict[str, str]]) -> None:
    tuf = payloads["tuf_metadata_set"]
    if tuf.get("metadata_mode") != "PRE_RELEASE_CORRIDOR_AUTHORING_ONLY":
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF metadata mode drifted")
    if not str(tuf.get("root", {}).get("trust_root_id", "")).strip():
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF root trust_root_id missing")
    targets = tuf.get("targets", {}).get("targets", [])
    if not isinstance(targets, list) or not targets:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF targets missing")
    by_path = {row["path"]: row["sha256"] for row in input_bindings}
    for target in targets:
        raw = str(target.get("path", ""))
        if raw not in by_path or target.get("sha256") != by_path[raw]:
            _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", f"TUF target {raw} does not bind input digest")
    if tuf.get("snapshot", {}).get("targets_bound") != len(targets):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF snapshot target count drifted")
    if tuf.get("timestamp", {}).get("expired_metadata_must_fail_closed") is not True:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID", "TUF expired metadata policy missing")
    if tuf.get("release_execution_authorized") is not False or tuf.get("external_audit_completed") is not False:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", "TUF metadata authorizes release or audit")


def _validate_attack_matrix(payloads: Dict[str, Dict[str, Any]]) -> None:
    matrix = payloads["attack_test_matrix"]
    scenarios = {
        row.get("scenario_id")
        for row in matrix.get("attack_scenarios", [])
        if isinstance(row, dict)
    }
    required = {
        "artifact_swap_test",
        "tuf_rollback_test",
        "tuf_freeze_test",
        "expired_metadata_test",
        "missing_sbom_test",
        "forged_rekor_bundle_test",
        "in_toto_layout_drift_test",
    }
    if not required <= scenarios:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ATTACK_MATRIX_INCOMPLETE", "attack matrix missing required scenarios")
    if matrix.get("release_execution_authorized") is not False:
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY", "attack matrix authorizes release")


def _validate_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        for key, value in packet.evidence_packet._walk(payload):  # noqa: SLF001 - reuse hardened recursive scanner.
            leaf_key = packet.evidence_packet._leaf_key(key)  # noqa: SLF001
            if leaf_key in packet.AUTHORITY_DRIFT_KEYS and value is not False and leaf_key not in {"supply_chain_release_corridor_next"}:
                _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not packet.evidence_packet._is_negative_field(key) and not packet.evidence_packet._is_machine_routing_field(key):  # noqa: SLF001
                clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", value, flags=re.IGNORECASE)
                for clause in clauses:
                    if any(pattern.search(clause) for pattern in packet.FORBIDDEN_CLAIM_PATTERNS) and not packet.evidence_packet._is_negative_text(clause):  # noqa: SLF001
                        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")


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
        "schema_id": "kt.supply_chain_release_corridor.validation.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "VALIDATION_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
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
        "source_hashes_recomputed": True,
        "supply_chain_release_corridor_packet_validated": True,
        "claim_compiler_commercial_language_gate_next": True,
        "claim_compiler_authorized": False,
        "release_execution_authorized": False,
        "release_executed": False,
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


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    scorecard = {
        "overall_grade": "PASS",
        "packet_shape_validated": True,
        "source_hashes_recomputed": True,
        "slsa_provenance_passed": True,
        "in_toto_layout_passed": True,
        "sigstore_rekor_passed": True,
        "spdx_cyclonedx_sbom_passed": True,
        "tuf_metadata_passed": True,
        "attack_matrix_passed": True,
        "claim_boundary_preserved": True,
        "claim_compiler_commercial_language_gate_next_supported": True,
    }
    return {
        "validation_contract": _artifact(base, role="validation_contract", schema_id="kt.supply_chain_release_corridor.validation_contract.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_CONTRACT"),
        "validation_receipt": _artifact(base, role="validation_receipt", schema_id="kt.supply_chain_release_corridor.validation_receipt.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_RECEIPT", verdict="SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATED_CLAIM_COMPILER_NEXT"),
        "validation_scorecard": _artifact(base, role="validation_scorecard", schema_id="kt.supply_chain_release_corridor.validation_scorecard.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_SCORECARD", scorecard=scorecard),
        "claim_compiler_gate_decision": _artifact(base, role="claim_compiler_gate_decision", schema_id="kt.claim_compiler.commercial_language_gate.decision.v1", artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_DECISION", decision="CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_NEXT", next_lawful_move=NEXT_LAWFUL_MOVE),
        "next_lawful_move": _artifact(base, role="next_lawful_move", schema_id="kt.supply_chain_release_corridor.validation_next_lawful_move.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT", current_execution_lane=AUTHORITATIVE_LANE, current_execution_outcome=SELECTED_OUTCOME, next_lawful_move=NEXT_LAWFUL_MOVE),
        "validation_report": _report(base),
    }


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Supply-Chain Release Corridor Validation",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Validation verdict: {SELECTED_OUTCOME}",
            "Supply-chain release corridor packet validated: true",
            "Release execution authorized: false",
            "External audit completed: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Claim compiler authorized now: false",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_packet_outputs(root)
    _validate_packet_shape(payloads)
    _validate_reason_codes(payloads)
    input_bindings = _validate_bound_source_hashes(root, payloads)
    _validate_generated_timestamp_coherence(payloads)
    supply_payloads = _load_supply_chain_inputs(root)
    _validate_supply_chain_inputs(supply_payloads)
    _validate_sboms(payloads, input_bindings)
    _validate_tuf_metadata(payloads, input_bindings)
    _validate_attack_matrix(payloads)
    _validate_claim_boundary({**payloads, **supply_payloads})
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if role == "validation_report":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(outputs[role]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Validate the KT supply-chain release corridor packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
