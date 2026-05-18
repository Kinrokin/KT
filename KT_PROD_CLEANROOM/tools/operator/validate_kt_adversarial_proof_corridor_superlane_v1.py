from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_adversarial_proof_corridor_superlane_v1 as corridor
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-adversarial-proof-corridor-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-adversarial-proof-corridor-validation-on-main"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "VALIDATE_KT_ADVERSARIAL_PROOF_CORRIDOR_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = corridor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = corridor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATED__EXTERNAL_AUDIT_RATIFICATION_PACKET_NEXT"
NEXT_LAWFUL_MOVE = "AUTHOR_KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_SUPERLANE_V1"

PACKET_JSON_OUTPUTS = {
    role: raw for role, raw in corridor.OUTPUTS.items() if raw.endswith(".json")
}
PACKET_MARKDOWN_OUTPUTS = {
    role: raw for role, raw in corridor.OUTPUTS.items() if raw.endswith(".md")
}

OUTPUTS = {
    "validation_contract": "governance/kt_adversarial_proof_corridor_validation_v1.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_report.md",
    "validation_scorecard": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_scorecard.json",
    "external_audit_ratification_gate_decision": "KT_PROD_CLEANROOM/reports/kt_external_audit_ratification_gate_decision.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/validate_kt_adversarial_proof_corridor_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_validate_kt_adversarial_proof_corridor_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_ADVERSARIAL_PROOF_VAL_PACKET_MISSING",
            "RC_KT_ADVERSARIAL_PROOF_VAL_OUTCOME_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH",
            "RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING",
            "RC_KT_ADVERSARIAL_PROOF_VAL_ATTACK_MATRIX_INCOMPLETE",
            "RC_KT_ADVERSARIAL_PROOF_VAL_REASON_CODE_DUPLICATE",
            "RC_KT_ADVERSARIAL_PROOF_VAL_CLAIM_BOUNDARY_BREACH",
            "RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY",
            "RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_VAL_TRUST_ZONE_FAILED",
        )
    )
)

AUTHORITY_DRIFT_KEYS = corridor.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "adversarial_proof_corridor_packet_validated",
        "external_audit_ratification_packet_next",
        "external_audit_ratification_packet_authorized",
        "external_reaudit_accepted",
    }
)

ALLOWED_AUTHORITY_TRUE_KEYS = corridor.ALLOWED_AUTHORITY_TRUE_KEYS | frozenset(
    {
        "adversarial_proof_corridor_packet_validated",
        "adversarial_proof_corridor_validated",
        "external_audit_ratification_packet_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = corridor.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed|accepted)\b", re.IGNORECASE),
    re.compile(r"\bexternal reaudit (?:is )?accepted\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation claims (?:are )?authorized\b", re.IGNORECASE),
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
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT", "main/replay validation requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT", "dirty worktree outside validation scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _load_packet_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in PACKET_JSON_OUTPUTS.items()}


def _validate_packet_shape(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("adversarial_proof_corridor_packet_authored") is not True:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PACKET_MISSING", f"{role} is not an authored adversarial proof artifact")
        if payload.get("adversarial_proof_corridor_validated") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", f"{role} validates adversarial proof before validation lane")
        if payload.get("adversarial_proof_corridor_active") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", f"{role} activates adversarial proof before validation")
        if payload.get("adversarial_attacks_executed") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", f"{role} executed attacks in authoring packet")
        if payload.get("external_audit_completed") is not False or payload.get("external_audit_claimed_complete") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", f"{role} claims external audit completion")
        if payload.get("commercial_activation_claim_authorized") is not False or payload.get("commercial_claims_authorized") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", f"{role} authorizes commercial claims")


def _validate_reason_codes(payloads: Dict[str, Dict[str, Any]]) -> None:
    reason_codes = payloads["validation_reason_codes"].get("reason_codes", [])
    if not isinstance(reason_codes, list) or not reason_codes:
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING", "validation reason codes missing")
    if len(reason_codes) != len(set(reason_codes)):
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_REASON_CODE_DUPLICATE", "validation reason codes must be unique")


def _validate_bound_source_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    contract = payloads["packet_contract"]
    rows = contract.get("input_bindings", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", "packet contract input bindings missing")
    expected_by_role = contract.get("binding_hashes", {})
    if not isinstance(expected_by_role, dict):
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", "packet contract binding_hashes missing")

    validated_rows: list[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", "input binding row must be object")
        role = str(row.get("role", "")).strip()
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not role or not raw or not expected:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", "input binding row incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING", f"missing bound input {role}: {raw}")
        actual = file_sha256(path)
        if actual != expected:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", f"{role} source hash mismatch")
        if expected_by_role.get(f"{role}_hash") != actual:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes mismatch")
        validated_rows.append({"role": role, "path": raw, "sha256": actual})

    for role, payload in payloads.items():
        if payload.get("input_bindings") != rows:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", f"{role} input_bindings drifted from packet contract")
        if payload.get("binding_hashes") != expected_by_role:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes drifted from packet contract")
    return validated_rows


def _leaf_key(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1].replace("[]", "")
    return re.sub(r"\[\d+\]$", "", leaf)


def _is_machine_routing_field(key: str) -> bool:
    return corridor._is_machine_routing_field(key) or evidence_packet._is_machine_routing_field(key)  # noqa: SLF001


def _is_negative_field(key: str) -> bool:
    return corridor._is_negative_field(key) or evidence_packet._is_negative_field(key)  # noqa: SLF001


def _is_negative_text(text: str) -> bool:
    return corridor._is_negative_text(text) or evidence_packet._is_negative_text(text)  # noqa: SLF001


def _explicit_false_clause(text: str) -> bool:
    return bool(re.search(r":\s*false\s*$", text.strip(), flags=re.IGNORECASE))


def _scan_claim_text(label: str, text: str) -> None:
    clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", text, flags=re.IGNORECASE)
    for clause in clauses:
        if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not (_is_negative_text(clause) or _explicit_false_clause(clause)):
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_CLAIM_BOUNDARY_BREACH", f"{label} contains forbidden affirmative claim: {clause.strip()!r}")


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001 - reuse hardened recursive walker.
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            _scan_claim_text(f"{label}.{key}", value)


def _validate_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        _scan_claim_boundary(label, payload)


def _validate_attack_matrix(payloads: Dict[str, Dict[str, Any]]) -> None:
    matrix = payloads["attack_matrix"]
    rows = matrix.get("attack_rows", [])
    if not isinstance(rows, list) or len(rows) != len(corridor.ATTACK_CLASSES):
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ATTACK_MATRIX_INCOMPLETE", "attack matrix row count mismatch")
    classes = {row.get("attack_class") for row in rows if isinstance(row, dict)}
    missing = set(corridor.ATTACK_CLASSES) - classes
    if missing:
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ATTACK_MATRIX_INCOMPLETE", "attack matrix missing classes: " + ", ".join(sorted(missing)))
    for row in rows:
        if row.get("status") != "PLANNED_NOT_EXECUTED" or row.get("must_fail_closed") is not True:
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ATTACK_MATRIX_INCOMPLETE", "attack matrix rows must be planned fail-closed rows")
    if matrix.get("attack_execution_performed") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY", "attack execution happened before validation")


def _validate_generated_markdown_reports(root: Path) -> None:
    for role, raw in PACKET_MARKDOWN_OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_ADVERSARIAL_PROOF_VAL_ARTIFACT_MISSING", f"missing packet Markdown report {role}: {raw}")
        _scan_claim_text(f"{role}:{raw}", path.read_text(encoding="utf-8"))


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
        "schema_id": "kt.adversarial_proof_corridor.validation.v1",
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
        "adversarial_proof_corridor_packet_validated": True,
        "adversarial_proof_corridor_validated": True,
        "adversarial_proof_corridor_active": False,
        "adversarial_attacks_executed": False,
        "external_audit_ratification_packet_next": True,
        "external_audit_ratification_packet_authorized": False,
        "external_reaudit_accepted": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_claimed": False,
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
    score_rows = [
        {"check_id": "h05_packet_shape", "status": "PASS"},
        {"check_id": "source_hash_recompute", "status": "PASS"},
        {"check_id": "attack_matrix_complete", "status": "PASS"},
        {"check_id": "attack_execution_not_performed", "status": "PASS"},
        {"check_id": "generated_markdown_claim_scan", "status": "PASS"},
        {"check_id": "claim_boundary", "status": "PASS"},
        {"check_id": "trust_zone", "status": "PASS"},
    ]
    return {
        "validation_contract": _artifact(
            base,
            role="validation_contract",
            schema_id="kt.adversarial_proof_corridor.validation_contract.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_CONTRACT",
            validation_checks=[row["check_id"] for row in score_rows],
            packet_contract_ref=corridor.OUTPUTS["packet_contract"],
        ),
        "validation_receipt": _artifact(
            base,
            role="validation_receipt",
            schema_id="kt.adversarial_proof_corridor.validation_receipt.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_RECEIPT",
            verdict="ADVERSARIAL_PROOF_CORRIDOR_VALIDATED_EXTERNAL_AUDIT_RATIFICATION_PACKET_NEXT",
        ),
        "validation_scorecard": _artifact(
            base,
            role="validation_scorecard",
            schema_id="kt.adversarial_proof_corridor.validation_scorecard.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_SCORECARD",
            score_rows=score_rows,
            pass_count=len(score_rows),
            fail_count=0,
        ),
        "external_audit_ratification_gate_decision": _artifact(
            base,
            role="external_audit_ratification_gate_decision",
            schema_id="kt.external_audit_ratification.gate_decision.v1",
            artifact_id="KT_EXTERNAL_AUDIT_RATIFICATION_GATE_DECISION",
            decision="EXTERNAL_AUDIT_RATIFICATION_PACKET_NEXT",
            external_audit_ratification_packet_next=True,
            external_audit_ratification_packet_authorized=False,
            external_reaudit_accepted=False,
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.adversarial_proof_corridor.validation_next_lawful_move.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "validation_report": _report(base),
    }


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Adversarial Proof Corridor Validation",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "Adversarial proof corridor validated: true",
            "Adversarial attacks executed: false",
            "External audit ratification packet next: true",
            "External audit ratification packet authorized: false",
            "External audit completed: false",
            "External reaudit accepted: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
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
    _validate_attack_matrix(packet_payloads)
    _validate_claim_boundary(packet_payloads)
    _validate_generated_markdown_reports(root)

    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_ADVERSARIAL_PROOF_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
            _scan_claim_boundary(role, outputs[role])
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Validate the KT adversarial proof corridor packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
