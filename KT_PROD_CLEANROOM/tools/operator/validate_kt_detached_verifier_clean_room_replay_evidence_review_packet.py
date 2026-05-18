from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as packet
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-detached-verifier-clean-room-replay-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/kt-detached-verifier-clean-room-replay-evidence-review-validation-on-main"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"
EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATED__"
    "SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT"
)
NEXT_LAWFUL_MOVE = "AUTHOR_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_PREDECESSOR_MISSING",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_OUTCOME_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_ARTIFACT_MISSING",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SCORECARD_FAILED",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_REASON_CODE_DUPLICATE",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SUPPLY_CHAIN_PREMATURE_AUTHORITY",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_TRUST_ZONE_FAILED",
        )
    )
)

JSON_PACKET_OUTPUTS = {
    role: raw for role, raw in packet.OUTPUTS.items() if raw.endswith(".json")
}

OUTPUTS = {
    "validation_contract": "governance/kt_detached_verifier_clean_room_replay_evidence_review_validation_v1.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_report.md",
    "validation_scorecard": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_scorecard.json",
    "supply_chain_gate_decision": "KT_PROD_CLEANROOM/reports/kt_supply_chain_release_corridor_gate_decision.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/validate_kt_detached_verifier_clean_room_replay_evidence_review_packet.py",
        "KT_PROD_CLEANROOM/tests/operator/test_validate_kt_detached_verifier_clean_room_replay_evidence_review_packet.py",
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
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT", "main/replay validation requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT", "dirty worktree outside validation scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _load_packet_outputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in JSON_PACKET_OUTPUTS.items()}


def _validate_reason_codes(payloads: Dict[str, Dict[str, Any]]) -> None:
    reason_codes = payloads["validation_reason_codes"].get("reason_codes", [])
    if not isinstance(reason_codes, list) or not reason_codes:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_ARTIFACT_MISSING", "reason codes missing")
    if len(reason_codes) != len(set(reason_codes)):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_REASON_CODE_DUPLICATE", "reason codes must be unique")


def _validate_packet_shape(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("evidence_review_packet_authored") is not True or payload.get("evidence_review_validated") is not False:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_PREDECESSOR_MISSING", f"{role} is not an authored, unvalidated evidence-review packet")
        if payload.get("supply_chain_release_corridor_authorized") is not False:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SUPPLY_CHAIN_PREMATURE_AUTHORITY", f"{role} authorizes supply chain prematurely")

    scorecard = payloads["evidence_scorecard"].get("scorecard", {})
    if scorecard.get("overall_grade") != "PASS" or scorecard.get("claim_boundary_preserved") is not True:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SCORECARD_FAILED", "evidence scorecard does not pass")
    if payloads["supply_chain_readiness_matrix"].get("authorized_now") is not False:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SUPPLY_CHAIN_PREMATURE_AUTHORITY", "supply-chain readiness matrix authorizes now")
    if payloads["external_audit_readiness_matrix"].get("external_audit_completed") is not False:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH", "external audit completion drifted")


def _validate_bound_source_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> list[Dict[str, str]]:
    contract = payloads["packet_contract"]
    rows = contract.get("input_bindings", [])
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", "packet contract input bindings missing")

    expected_by_role = contract.get("binding_hashes", {})
    if not isinstance(expected_by_role, dict):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", "packet contract binding_hashes missing")

    validated_rows: list[Dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", "input binding row must be object")
        role = str(row.get("role", "")).strip()
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not role or not raw or not expected:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", "input binding row incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_ARTIFACT_MISSING", f"missing bound input {role}: {raw}")
        actual = file_sha256(path)
        if actual != expected:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", f"{role} source hash mismatch")
        if expected_by_role.get(f"{role}_hash") != actual:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes mismatch")
        validated_rows.append({"role": role, "path": raw, "sha256": actual})

    for role, payload in payloads.items():
        if payload.get("input_bindings") != rows:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", f"{role} input_bindings drifted from packet contract")
        if payload.get("binding_hashes") != expected_by_role:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH", f"{role} binding_hashes drifted from packet contract")
    return validated_rows


def _validate_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
    for label, payload in payloads.items():
        for key, value in packet._walk(payload):  # noqa: SLF001 - reuse hardened lane scanner.
            leaf_key = packet._leaf_key(key)  # noqa: SLF001
            if leaf_key in packet.AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not packet._is_negative_field(key) and not packet._is_machine_routing_field(key):  # noqa: SLF001
                if packet._has_forbidden_claim(value):  # noqa: SLF001
                    _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")


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
        "schema_id": "kt.detached_verifier.clean_room_replay.evidence_review.validation.v1",
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
        "clean_room_replay_executed": True,
        "clean_room_replay_evidence_review_packet_validated": True,
        "supply_chain_release_corridor_next": True,
        "supply_chain_release_corridor_authorized": False,
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
        "source_hashes_recomputed": True,
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
        "claim_boundary_preserved": True,
        "supply_chain_release_corridor_next_supported": True,
        "external_audit_completed": False,
    }
    return {
        "validation_contract": _artifact(base, role="validation_contract", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.validation_contract.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATION_CONTRACT"),
        "validation_receipt": _artifact(base, role="validation_receipt", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.validation_receipt.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATION_RECEIPT", verdict="EVIDENCE_REVIEW_VALIDATED_SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT"),
        "validation_scorecard": _artifact(base, role="validation_scorecard", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.validation_scorecard.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATION_SCORECARD", scorecard=scorecard),
        "supply_chain_gate_decision": _artifact(base, role="supply_chain_gate_decision", schema_id="kt.supply_chain_release_corridor.gate_decision.v1", artifact_id="KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_GATE_DECISION", decision="SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT", next_lawful_move=NEXT_LAWFUL_MOVE),
        "next_lawful_move": _artifact(base, role="next_lawful_move", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.validation_next_lawful_move.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT", current_execution_lane=AUTHORITATIVE_LANE, current_execution_outcome=SELECTED_OUTCOME, next_lawful_move=NEXT_LAWFUL_MOVE),
        "validation_report": _report(base),
    }


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Detached Verifier Clean-Room Replay Evidence Review Validation",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Validation verdict: {SELECTED_OUTCOME}",
            "Clean-room replay evidence review packet validated: true",
            "Supply-chain release corridor authorized now: false",
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
    payloads = _load_packet_outputs(root)
    _validate_packet_shape(payloads)
    _validate_reason_codes(payloads)
    input_bindings = _validate_bound_source_hashes(root, payloads)
    _validate_claim_boundary(payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
    return argparse.ArgumentParser(description="Validate the KT detached verifier clean-room replay evidence-review packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
