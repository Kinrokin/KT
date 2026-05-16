from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_external_launch_readiness_truth_lock as packet
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-external-launch-readiness-truth-lock"
REPLAY_BRANCH_PREFIX = "replay/kt-external-launch-readiness-truth-lock-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION"
PREVIOUS_LANE = packet.AUTHORITATIVE_LANE
EXPECTED_PREVIOUS_OUTCOME = packet.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = packet.NEXT_LAWFUL_MOVE

SELECTED_OUTCOME = packet.VALIDATED_SUCCESS_OUTCOME
NEXT_LAWFUL_MOVE = packet.VALIDATED_NEXT_LAWFUL_MOVE

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_TRUTH_LOCK_VAL_PACKET_MISSING",
            "RC_KT_TRUTH_LOCK_VAL_PACKET_OUTCOME_DRIFT",
            "RC_KT_TRUTH_LOCK_VAL_NEXT_MOVE_DRIFT",
            "RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH",
            "RC_KT_TRUTH_LOCK_VAL_CLAIM_TOKEN_DRIFT",
            "RC_KT_TRUTH_LOCK_VAL_BOUNDARY_DRIFT",
            "RC_KT_TRUTH_LOCK_VAL_TRUST_ZONE_FAILED",
        )
    )
)

JSON_INPUTS = {role: raw for role, raw in packet.JSON_OUTPUTS.items()}
TEXT_INPUTS = {role: raw for role, raw in packet.TEXT_OUTPUTS.items()}

OUTPUTS = {
    "validation_contract": "governance/truth_lock_validation_contract.json",
    "validation_receipt": "governance/truth_lock_validation_receipt.json",
    "validation_report": "governance/truth_lock_validation_report.md",
    "validation_next_lawful_move": "governance/truth_lock_validation_next_lawful_move_receipt.json",
    "detached_verifier_kit_next_prep_only": "governance/detached_verifier_kit_next_prep_only.json",
}


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise LaneFailure(code, detail)


def _walk(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item, str(key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk(item, parent_key)
            else:
                yield parent_key, item


def _is_negative_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed", "refusal"))


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in packet.CLAIM_DRIFT_PHRASES)


def _is_negative_text_context(value: str) -> bool:
    normalized = value.lower()
    return any(
        marker in normalized
        for marker in (
            "not authorized",
            "not proven",
            "not complete",
            "not completed",
            "forbidden",
            "blocked",
            "prohibited",
            "out of scope",
            "cannot claim",
            "requires a separate",
            "requires separate",
        )
    )


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_TRUTH_LOCK_VAL_NEXT_MOVE_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_TRUTH_LOCK_VAL_NEXT_MOVE_DRIFT", f"branch {branch!r} is not allowed")


def _load(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    payload = common.load_json_required(root, raw, label=label)
    if not isinstance(payload, dict):
        _fail("RC_KT_TRUTH_LOCK_VAL_PACKET_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_TRUTH_LOCK_VAL_PACKET_MISSING", str(exc))


def _payloads(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load(root, raw, label=role) for role, raw in JSON_INPUTS.items()}
    texts = {role: _read_text(root, raw, label=role) for role, raw in TEXT_INPUTS.items()}
    return payloads, texts


def _ensure_claim_boundary(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in packet.AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_TRUTH_LOCK_VAL_BOUNDARY_DRIFT", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and _contains_forbidden_claim(value):
                _fail("RC_KT_TRUTH_LOCK_VAL_CLAIM_TOKEN_DRIFT", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        if label == "hard_refusal_tokens":
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _contains_forbidden_claim(line) and not _is_negative_text_context(line):
                _fail(
                    "RC_KT_TRUTH_LOCK_VAL_CLAIM_TOKEN_DRIFT",
                    f"{label} line {line_number} contains forbidden claim",
                )


def _ensure_handoff(payloads: Dict[str, Dict[str, Any]]) -> None:
    head = payloads["current_truth_head"]
    receipt = payloads["current_truth_head_receipt"]
    next_move = payloads["truth_lock_next_lawful_move_receipt"]
    if head.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_TRUTH_LOCK_VAL_PACKET_OUTCOME_DRIFT", "Truth Lock current truth outcome drift")
    if receipt.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
        _fail("RC_KT_TRUTH_LOCK_VAL_PACKET_OUTCOME_DRIFT", "Truth Lock receipt outcome drift")
    if head.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_TRUTH_LOCK_VAL_NEXT_MOVE_DRIFT", "Truth Lock current truth next move drift")
    if next_move.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
        _fail("RC_KT_TRUTH_LOCK_VAL_NEXT_MOVE_DRIFT", "Truth Lock next move receipt drift")
    required = {
        "ready_for_reaudit_or_external_review": True,
        "follow_up_audit_readiness_validated": True,
        "commercial_activation_claim_authorized": False,
        "external_audit_completed": False,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }
    for key, expected in required.items():
        if head.get(key) is not expected:
            _fail("RC_KT_TRUTH_LOCK_VAL_BOUNDARY_DRIFT", f"Truth Lock {key} drifted")


def _ensure_source_hashes(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    head = payloads["current_truth_head"]
    rows = head.get("input_bindings")
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH", "Truth Lock input_bindings missing or empty")
    seen_roles = {str(row.get("role", "")) for row in rows if isinstance(row, dict)}
    expected_roles = set(packet.INPUTS)
    if seen_roles != expected_roles:
        _fail(
            "RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH",
            f"Truth Lock input binding roles drifted: expected {sorted(expected_roles)}, got {sorted(seen_roles)}",
        )
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH", "Truth Lock input binding row malformed")
        raw = str(row.get("path", ""))
        expected = row.get("sha256")
        path = common.resolve_path(root, raw)
        if not path.is_file() or file_sha256(path) != expected:
            _fail("RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH", f"source hash mismatch for {raw}")


def _output_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in {**JSON_INPUTS, **TEXT_INPUTS}.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_TRUTH_LOCK_VAL_PACKET_MISSING", f"{role} missing at {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _base(
    *,
    generated_utc: str,
    head: str,
    current_main_head: str,
    branch: str,
    output_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS",
            "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_INVALID__FORENSIC_TRUTH_LOCK_REVIEW_NEXT",
        ],
        "artifact_bindings": output_bindings,
        "authoritative_lane": AUTHORITATIVE_LANE,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in output_bindings},
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_claim_7b_amplification_proven": True,
        "cannot_claim_beyond_sota": True,
        "cannot_claim_external_audit_complete": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
        "commercial_activation_claim_authorized": False,
        "current_branch": branch,
        "current_branch_head": head,
        "current_git_head": head,
        "current_main_head": current_main_head,
        "external_audit_completed": False,
        "follow_up_audit_readiness_validated": True,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "previous_authoritative_lane": PREVIOUS_LANE,
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "previous_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "ready_for_reaudit_or_external_review": True,
        "selected_outcome": SELECTED_OUTCOME,
        "seven_b_amplification_claimed_proven": False,
        "truth_engine_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_changed": False,
        "trust_zone_law_unchanged": True,
        "trust_zone_validation_status": trust_zone_validation.get("status"),
        "trust_zone_failures": list(trust_zone_validation.get("failures", [])),
        "truth_lock_validated": True,
    }


def _artifact(base: Dict[str, Any], *, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    return {"schema_id": schema_id, "artifact_id": artifact_id, **base, **extra}


def _outputs(base: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        "validation_contract": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.validation_contract.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION_CONTRACT",
            validation_status="PASS",
        ),
        "validation_receipt": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.validation_receipt.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION_RECEIPT",
            verdict="TRUTH_LOCK_VALIDATED_DETACHED_VERIFIER_NEXT",
        ),
        "validation_next_lawful_move": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.validation_next_lawful_move_receipt.v1",
            artifact_id="KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            receipt_type="NEXT_LAWFUL_MOVE",
        ),
        "detached_verifier_kit_next_prep_only": _artifact(
            base,
            schema_id="kt.external_launch_readiness.truth_lock.detached_verifier_kit_next_prep_only.v1",
            artifact_id="KT_DETACHED_VERIFIER_KIT_NEXT_PREP_ONLY",
            authority="PREP_ONLY",
            cannot_authorize_commercial_activation_claims=True,
            cannot_claim_7b_amplification_proven=True,
            purpose="Prepare detached verifier kit lane after Truth Lock validation replay.",
        ),
    }


def _report_text(contract: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT External Launch Readiness Truth Lock Validation",
            "",
            f"Outcome: {contract['selected_outcome']}",
            f"Next lawful move: {contract['next_lawful_move']}",
            "",
            "Truth Lock is validated and routes to the detached verifier kit lane.",
            "Commercial activation claims remain unauthorized. External audit is not complete.",
            "7B amplification remains unproven. Truth-engine and trust-zone law remain unchanged.",
            "",
        ]
    )


def run(*, output_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    output_root = output_root or root
    if output_root.resolve() != root.resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical repository root only")
    branch = _ensure_branch_context(root)
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before KT external launch readiness Truth Lock validation")
    payloads, texts = _payloads(root)
    _ensure_handoff(payloads)
    _ensure_claim_boundary(payloads, texts)
    _ensure_source_hashes(root, payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_TRUTH_LOCK_VAL_TRUST_ZONE_FAILED", "trust-zone validation failed")
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        generated_utc=utc_now_iso_z(),
        head=head,
        current_main_head=current_main_head,
        branch=branch,
        output_bindings=_output_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base)
    for role, raw in OUTPUTS.items():
        path = output_root / raw
        if role == "validation_report":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_report_text(outputs["validation_contract"]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    return outputs["validation_contract"]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--output-root", default=".")
    args = parser.parse_args(argv)
    result = run(output_root=(repo_root() / args.output_root).resolve())
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
