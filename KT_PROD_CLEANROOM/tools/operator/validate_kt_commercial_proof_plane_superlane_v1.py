from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_commercial_proof_plane_superlane_v1 as plane
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-commercial-proof-plane-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-commercial-proof-plane-validation-on-main"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "VALIDATE_KT_COMMERCIAL_PROOF_PLANE_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = plane.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = plane.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "KT_COMMERCIAL_PROOF_PLANE_VALIDATED__ADVERSARIAL_PROOF_CORRIDOR_NEXT"
NEXT_LAWFUL_MOVE = "AUTHOR_KT_ADVERSARIAL_PROOF_CORRIDOR_SUPERLANE_V1"

PACKET_JSON_OUTPUTS = {
    role: raw for role, raw in plane.OUTPUTS.items() if raw.endswith(".json")
}
PACKET_MARKDOWN_OUTPUTS = {
    role: raw for role, raw in plane.OUTPUTS.items() if raw.endswith(".md")
}

OUTPUTS = {
    "validation_contract": "governance/kt_commercial_proof_plane_validation_v1.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_report.md",
    "validation_scorecard": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_scorecard.json",
    "adversarial_proof_corridor_gate_decision": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_gate_decision.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/validate_kt_commercial_proof_plane_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_validate_kt_commercial_proof_plane_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PACKET_MISSING",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_OUTCOME_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_REASON_CODE_DUPLICATE",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_CLAIM_BOUNDARY_BREACH",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_BRANCH_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_VAL_TRUST_ZONE_FAILED",
        )
    )
)

AUTHORITY_DRIFT_KEYS = plane.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "commercial_proof_plane_packet_validated",
        "commercial_proof_plane_validated",
        "commercial_proof_plane_active",
        "commercial_proof_plane_authorized",
        "commercial_activation_claim_authorized",
        "commercial_activation_claims_authorized",
        "allowed_claims_authorize_commercial_activation_claims",
        "benchmark_prep_authorizes_commercial_activation",
        "external_audit_completed",
        "external_audit_claimed_complete",
        "adversarial_proof_corridor_next",
        "adversarial_proof_corridor_authorized",
        "adversarial_proof_corridor_validated",
        "adversarial_proof_corridor_active",
    }
)

ALLOWED_AUTHORITY_TRUE_KEYS = plane.ALLOWED_AUTHORITY_TRUE_KEYS | frozenset(
    {
        "commercial_proof_plane_packet_validated",
        "commercial_proof_plane_validated",
        "adversarial_proof_corridor_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = plane.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bcommercial activation claims (?:are )?authorized\b", re.IGNORECASE),
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed)\b", re.IGNORECASE),
    re.compile(r"\b7b amplification (?:is )?(?:proven|validated)\b", re.IGNORECASE),
    re.compile(r"\bbeyond-sota (?:is )?(?:proven|validated|claimed)\b", re.IGNORECASE),
    re.compile(r"\bs-tier (?:claim )?(?:is )?(?:allowed|proven|validated)\b", re.IGNORECASE),
    re.compile(r"\bfp0 or highway (?:shadow )?(?:is )?(?:authority|canonical authority|promoted)\b", re.IGNORECASE),
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
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_BRANCH_DRIFT", "main/replay validation requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_BRANCH_DRIFT", "dirty worktree outside validation scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _load_packet_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in PACKET_JSON_OUTPUTS.items()}


def _validate_packet_shape(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("commercial_proof_plane_packet_authored") is not True:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PACKET_MISSING", f"{role} is not an authored commercial proof plane artifact")
        if payload.get("commercial_proof_plane_validated") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} validates commercial proof plane before validation lane")
        if payload.get("commercial_proof_plane_active") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} activates commercial proof plane before validation")
        if payload.get("adversarial_proof_corridor_next") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} selects adversarial proof before validation")
        if payload.get("commercial_activation_claim_authorized") is not False or payload.get("commercial_claims_authorized") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} authorizes commercial claims")
        if payload.get("external_audit_completed") is not False or payload.get("external_audit_claimed_complete") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} claims external audit completion")
        if payload.get("seven_b_amplification_claimed_proven") is not False or payload.get("beyond_sota_claimed") is not False or payload.get("s_tier_claimed") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} claims 7B/beyond-SOTA/S-tier proof")
        if payload.get("fp0_or_highway_promoted_to_authority") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", f"{role} promotes FP0/highway authority")


def _validate_reason_codes(payloads: Dict[str, Dict[str, Any]]) -> None:
    reason_codes = payloads["validation_reason_codes"].get("reason_codes", [])
    if not isinstance(reason_codes, list) or not reason_codes:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING", "validation reason codes missing")
    if len(reason_codes) != len(set(reason_codes)):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_REASON_CODE_DUPLICATE", "validation reason codes must be unique")


def _validate_bound_source_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    contract = payloads["packet_contract"]
    rows = contract.get("input_bindings", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", "packet contract input bindings missing")
    expected_by_role = contract.get("binding_hashes", {})
    if not isinstance(expected_by_role, dict):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", "packet contract binding_hashes missing")

    validated_rows: list[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", "input binding row must be object")
        role = str(row.get("role", "")).strip()
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not role or not raw or not expected:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", "input binding row incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING", f"missing bound input {role}: {raw}")
        actual = file_sha256(path)
        if actual != expected:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", f"{role} source hash mismatch")
        if expected_by_role.get(f"{role}_hash") != actual:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes mismatch")
        validated_rows.append({"role": role, "path": raw, "sha256": actual})

    for role, payload in payloads.items():
        if payload.get("input_bindings") != rows:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", f"{role} input_bindings drifted from packet contract")
        if payload.get("binding_hashes") != expected_by_role:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes drifted from packet contract")
    return validated_rows


def _validate_generated_timestamp_coherence(payloads: Dict[str, Dict[str, Any]]) -> None:
    expected = payloads["packet_contract"].get("generated_utc")
    if not expected:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PACKET_MISSING", "packet contract generated_utc missing")
    for role, payload in payloads.items():
        if "generated_utc" in payload and payload.get("generated_utc") != expected:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PACKET_MISSING", f"{role} generated_utc drifted from packet")


def _leaf_key(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1].replace("[]", "")
    return re.sub(r"\[\d+\]$", "", leaf)


def _is_machine_routing_field(key: str) -> bool:
    return plane._is_machine_routing_field(key) or evidence_packet._is_machine_routing_field(key)  # noqa: SLF001


def _is_negative_field(key: str) -> bool:
    return plane._is_negative_field(key) or evidence_packet._is_negative_field(key)  # noqa: SLF001


def _is_negative_text(text: str) -> bool:
    return plane._is_negative_text(text) or evidence_packet._is_negative_text(text)  # noqa: SLF001


def _explicit_false_clause(text: str) -> bool:
    return bool(re.search(r":\s*false\s*$", text.strip(), flags=re.IGNORECASE))


def _scan_claim_text(label: str, text: str) -> None:
    clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", text, flags=re.IGNORECASE)
    for clause in clauses:
        if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not (_is_negative_text(clause) or _explicit_false_clause(clause)):
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_CLAIM_BOUNDARY_BREACH", f"{label} contains forbidden affirmative claim: {clause.strip()!r}")


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001 - reuse hardened recursive walker.
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            _scan_claim_text(f"{label}.{key}", value)


def _validate_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _scan_claim_boundary(label, payload)


def _validate_generated_markdown_reports(root: Path) -> None:
    for role, raw in PACKET_MARKDOWN_OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_ARTIFACT_MISSING", f"missing packet Markdown report {role}: {raw}")
        _scan_claim_text(f"{role}:{raw}", path.read_text(encoding="utf-8"))


def _validate_deliverables(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    expected = set(plane._common_deliverables())  # noqa: SLF001 - validation must enforce authored deliverable list.
    contract_deliverables = payloads["packet_contract"].get("deliverables", [])
    if set(contract_deliverables) != expected:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", "packet contract deliverables drifted")
    for raw in expected:
        if not common.resolve_path(root, raw).is_file():
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", f"missing deliverable {raw}")

    manifest = payloads["evidence_pack_manifest"]
    if manifest.get("evidence_pack_authorizes_commercial_activation_claims") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", "evidence pack authorizes commercial activation claims")
    items = manifest.get("evidence_pack_items", [])
    if not isinstance(items, list):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", "evidence pack items must be a list")
    if plane.SOURCE_INPUTS["public_verifier_manifest"] not in items:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", "public verifier manifest missing from evidence pack manifest")

    source_manifest = payloads["source_manifest"]
    sources = source_manifest.get("sources", [])
    if not isinstance(sources, list) or not sources:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", "source manifest sources missing")
    bound_paths = {row.get("path") for row in sources if isinstance(row, dict)}
    if plane.SOURCE_INPUTS["public_verifier_manifest"] not in bound_paths:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_DELIVERABLE_MISSING", "public verifier manifest not bound as source input")


def _validate_claim_state(payloads: Dict[str, Dict[str, Any]]) -> None:
    boundary = payloads["claim_boundary_receipt"]
    if boundary.get("no_claim_expansion") is not True:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_CLAIM_BOUNDARY_BREACH", "claim boundary receipt must preserve no_claim_expansion")
    if boundary.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", "claim boundary authorizes commercial activation claims")
    if boundary.get("external_audit_completed") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", "claim boundary claims external audit completion")
    if boundary.get("seven_b_amplification_claimed_proven") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_PREMATURE_AUTHORITY", "claim boundary claims 7B amplification proof")


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
        "schema_id": "kt.commercial_proof_plane.validation.v1",
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
        "commercial_proof_plane_packet_validated": True,
        "commercial_proof_plane_validated": True,
        "commercial_proof_plane_active": False,
        "commercial_proof_plane_authorized": False,
        "adversarial_proof_corridor_next": True,
        "adversarial_proof_corridor_authorized": False,
        "adversarial_proof_corridor_validated": False,
        "adversarial_proof_corridor_active": False,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_claimed": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
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


def _outputs(base: Dict[str, Any], packet_payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    score_rows = [
        {"check_id": "h04_packet_shape", "status": "PASS"},
        {"check_id": "source_hash_recompute", "status": "PASS"},
        {"check_id": "deliverables_present", "status": "PASS"},
        {"check_id": "public_verifier_manifest_bound", "status": "PASS"},
        {"check_id": "generated_markdown_claim_scan", "status": "PASS"},
        {"check_id": "commercial_claim_boundary", "status": "PASS"},
        {"check_id": "trust_zone", "status": "PASS"},
    ]
    return {
        "validation_contract": _artifact(
            base,
            role="validation_contract",
            schema_id="kt.commercial_proof_plane.validation_contract.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_CONTRACT",
            validation_checks=[row["check_id"] for row in score_rows],
            packet_contract_ref=plane.OUTPUTS["packet_contract"],
        ),
        "validation_receipt": _artifact(
            base,
            role="validation_receipt",
            schema_id="kt.commercial_proof_plane.validation_receipt.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_RECEIPT",
            verdict="COMMERCIAL_PROOF_PLANE_VALIDATED_ADVERSARIAL_PROOF_CORRIDOR_NEXT",
        ),
        "validation_scorecard": _artifact(
            base,
            role="validation_scorecard",
            schema_id="kt.commercial_proof_plane.validation_scorecard.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_SCORECARD",
            score_rows=score_rows,
            pass_count=len(score_rows),
            fail_count=0,
        ),
        "adversarial_proof_corridor_gate_decision": _artifact(
            base,
            role="adversarial_proof_corridor_gate_decision",
            schema_id="kt.adversarial_proof_corridor.gate_decision.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_GATE_DECISION",
            decision="ADVERSARIAL_PROOF_CORRIDOR_NEXT",
            adversarial_proof_corridor_next=True,
            adversarial_proof_corridor_authorized=False,
            commercial_activation_claim_authorized=False,
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.commercial_proof_plane.validation_next_lawful_move.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "validation_report": _report(base, packet_payloads),
    }


def _report(base: Dict[str, Any], packet_payloads: Dict[str, Dict[str, Any]]) -> str:
    deliverable_count = len(packet_payloads["packet_contract"].get("deliverables", []))
    return "\n".join(
        [
            "# KT Commercial Proof Plane Validation",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "Commercial proof plane validated: true",
            "Adversarial proof corridor next: true",
            "Adversarial proof corridor authorized: false",
            "Commercial activation claims authorized: false",
            "External audit completed: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
            f"Commercial proof deliverables validated: {deliverable_count}",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    packet_payloads = _load_packet_outputs(root)
    _validate_packet_shape(packet_payloads)
    _validate_reason_codes(packet_payloads)
    input_bindings = _validate_bound_source_hashes(root, packet_payloads)
    _validate_generated_timestamp_coherence(packet_payloads)
    _validate_deliverables(root, packet_payloads)
    _validate_claim_state(packet_payloads)
    _validate_claim_boundary(packet_payloads)
    _validate_generated_markdown_reports(root)

    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
    outputs = _outputs(base, packet_payloads)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if role == "validation_report":
            path.parent.mkdir(parents=True, exist_ok=True)
            text = str(outputs[role])
            path.write_text(text, encoding="utf-8", newline="\n")
        else:
            _scan_claim_boundary(role, outputs[role])
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Validate the KT commercial proof plane packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
