from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, NoReturn, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


TARGET_ATTESTATION = "KT_PROD_CLEANROOM/reports/kt_external_reaudit_independent_attestation.json"
OUTPUT_RECEIPT = "KT_PROD_CLEANROOM/reports/kt_external_reaudit_independent_attestation_validation_receipt.json"
OUTPUT_BLOCKER_DASHBOARD = "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attestation_intake_blocker_dashboard.json"

LANE = "VALIDATE_EXTERNAL_REAUDIT_INDEPENDENT_ATTESTATION"
CURRENT_BLOCKED_OUTCOME = "H06_EXTERNAL_REAUDIT_DEFERRED__INDEPENDENT_ATTESTATION_REQUIRED"
PARKED_CONTINUATION_LABEL = (
    "H06_EXTERNAL_REAUDIT_DEFERRED__INDEPENDENT_ATTESTATION_REQUIRED__"
    "CONTINUE_PREP_SHADOW_AND_INTERNAL_CAPABILITY_COMPLETION_UNDER_CLAIM_CEILING"
)

ACCEPTED_NEXT = "RUN_KT_EXTERNAL_REAUDIT_ATTEMPT_WITH_INDEPENDENT_ATTESTATION"
BLOCKED_NEXT = "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION"
REJECTED_NEXT = "AUTHOR_KT_FORENSIC_EXTERNAL_REAUDIT_REVIEW_PACKET"

ALLOWED_VERDICTS = frozenset({"ACCEPTED", "DEFERRED", "REJECTED"})
ALLOWED_RELATIONSHIPS = frozenset({"independent", "paid_independent_reviewer", "external_auditor", "design_partner_reviewer"})
FORBIDDEN_REVIEWER_TOKENS = ("kings theorem", "kinrokin", "kt internal", "kt-authored", "self-authored")
REQUIRED_ACCEPTED_SCOPES = (
    "external_audit_packet_reviewed",
    "public_verifier_reviewed",
    "supply_chain_reviewed",
    "claim_boundary_reviewed",
    "commands_executed",
    "evidence_bundle_reviewed",
)


class AttestationFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> NoReturn:
    raise AttestationFailure(code, detail)


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        _fail("RC_EXTERNAL_ATTESTATION_JSON_INVALID", f"{path.as_posix()}: {exc}")
    if not isinstance(payload, dict):
        _fail("RC_EXTERNAL_ATTESTATION_JSON_INVALID", f"{path.as_posix()} must contain a JSON object")
    return payload


def _reviewer_text(payload: Dict[str, Any]) -> str:
    reviewer = payload.get("reviewer")
    if isinstance(reviewer, dict):
        return " ".join(str(reviewer.get(key, "")) for key in ("name", "organization", "email", "relationship_to_kt"))
    return str(reviewer or "")


def _claim_flags(payload: Dict[str, Any]) -> Dict[str, bool]:
    return {
        "commercial_claims_authorized": bool(payload.get("commercial_claims_authorized")),
        "commercial_activation_claim_authorized": bool(payload.get("commercial_activation_claim_authorized")),
        "seven_b_amplification_proven": bool(payload.get("seven_b_amplification_proven")),
        "beyond_sota_claimed": bool(payload.get("beyond_sota_claimed")),
        "s_tier_claimed": bool(payload.get("s_tier_claimed")),
        "truth_engine_law_changed": bool(payload.get("truth_engine_law_changed")),
        "trust_zone_law_changed": bool(payload.get("trust_zone_law_changed")),
    }


def _base(root: Path, *, attestation_path: Path, payload: Dict[str, Any] | None, blockers: list[Dict[str, Any]]) -> Dict[str, Any]:
    verdict = str(payload.get("verdict", "") if payload else "").upper()
    accepted = verdict == "ACCEPTED" and not blockers
    rejected = verdict == "REJECTED"
    deferred = verdict == "DEFERRED" or not payload or (not accepted and not rejected)
    next_lawful_move = ACCEPTED_NEXT if accepted else REJECTED_NEXT if rejected else BLOCKED_NEXT
    decision = "ATTESTATION_ACCEPTED_NEXT_REAUDIT_ATTEMPT" if accepted else "ATTESTATION_REJECTED_FORENSIC_NEXT" if rejected else "BLOCKED_MISSING_OR_INCOMPLETE_INDEPENDENT_ATTESTATION"
    claim_flags = _claim_flags(payload or {})
    return {
        "schema_id": "kt.external_reaudit.independent_attestation_validation_receipt.v1",
        "artifact_id": "KT_EXTERNAL_REAUDIT_INDEPENDENT_ATTESTATION_VALIDATION_RECEIPT",
        "lane": LANE,
        "authority": "VALIDATION_ONLY",
        "current_blocked_outcome": CURRENT_BLOCKED_OUTCOME,
        "continuation_label": PARKED_CONTINUATION_LABEL,
        "attestation_path": attestation_path.relative_to(root).as_posix() if attestation_path.is_absolute() and root in attestation_path.parents else attestation_path.as_posix(),
        "generated_utc": utc_now_iso_z(),
        "attestation_present": payload is not None,
        "attestation_verdict": verdict or "MISSING",
        "attestation_accepted": accepted,
        "attestation_deferred": deferred,
        "attestation_rejected": rejected,
        "independent_attestation_accepted": accepted,
        "external_audit_accepted": False,
        "external_audit_completed": False,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "claim_flags_found": claim_flags,
        "claim_boundary_passed": not any(claim_flags.values()),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "decision": decision,
        "next_lawful_move": next_lawful_move,
    }


def evaluate_attestation(*, root: Path | None = None, attestation_path: Path | None = None) -> Dict[str, Any]:
    base_root = root or repo_root()
    raw_path = attestation_path or (base_root / TARGET_ATTESTATION)
    path = raw_path if raw_path.is_absolute() else base_root / raw_path
    blockers: list[Dict[str, Any]] = []
    payload: Dict[str, Any] | None = None

    if not path.is_file():
        blockers.append(
            {
                "blocker_id": "independent_external_reaudit_attestation_missing",
                "status": "BLOCKING",
                "required_artifact": TARGET_ATTESTATION,
                "repair": "Collect an attestation from an independent external reviewer; do not self-author it.",
            }
        )
        return _base(base_root, attestation_path=path, payload=None, blockers=blockers)

    payload = _load_json(path)
    verdict = str(payload.get("verdict", "")).upper()
    if verdict not in ALLOWED_VERDICTS:
        blockers.append({"blocker_id": "attestation_verdict_invalid", "status": "BLOCKING", "allowed": sorted(ALLOWED_VERDICTS)})

    reviewer = payload.get("reviewer") if isinstance(payload.get("reviewer"), dict) else {}
    relationship = str(reviewer.get("relationship_to_kt", "") if isinstance(reviewer, dict) else "").strip().lower()
    reviewer_text = _reviewer_text(payload).lower()
    if payload.get("prepared_by_kt") is True or payload.get("authoring_entity_is_kt") is True:
        blockers.append({"blocker_id": "kt_authored_attestation_rejected", "status": "BLOCKING"})
    if relationship not in ALLOWED_RELATIONSHIPS:
        blockers.append({"blocker_id": "reviewer_relationship_not_independent", "status": "BLOCKING", "actual": relationship})
    if any(token in reviewer_text for token in FORBIDDEN_REVIEWER_TOKENS):
        blockers.append({"blocker_id": "reviewer_identity_not_independent", "status": "BLOCKING"})

    if verdict == "ACCEPTED":
        scope = payload.get("scope")
        if not isinstance(scope, dict):
            blockers.append({"blocker_id": "accepted_attestation_scope_missing", "status": "BLOCKING"})
        else:
            missing_scopes = [key for key in REQUIRED_ACCEPTED_SCOPES if scope.get(key) is not True]
            if missing_scopes:
                blockers.append({"blocker_id": "accepted_attestation_scope_incomplete", "status": "BLOCKING", "missing": missing_scopes})
        evidence = payload.get("evidence_review")
        if not isinstance(evidence, dict) or not evidence.get("evidence_bundle_hash") or not evidence.get("commands_run"):
            blockers.append({"blocker_id": "accepted_attestation_evidence_review_incomplete", "status": "BLOCKING"})
        if payload.get("paid_reviewer") is True and not payload.get("paid_reviewer_disclosure"):
            blockers.append({"blocker_id": "paid_reviewer_disclosure_missing", "status": "BLOCKING"})

    claim_flags = _claim_flags(payload)
    if any(claim_flags.values()):
        blockers.append({"blocker_id": "attestation_claim_boundary_breach", "status": "BLOCKING", "claim_flags_found": claim_flags})

    return _base(base_root, attestation_path=path, payload=payload, blockers=blockers)


def validate_for_acceptance(*, root: Path | None = None, attestation_path: Path | None = None) -> Dict[str, Any]:
    receipt = evaluate_attestation(root=root, attestation_path=attestation_path)
    if receipt["decision"] != "ATTESTATION_ACCEPTED_NEXT_REAUDIT_ATTEMPT":
        _fail("RC_EXTERNAL_ATTESTATION_NOT_ACCEPTED", receipt["decision"])
    return receipt


def write_outputs(root: Path, receipt: Dict[str, Any]) -> None:
    write_json_stable(root / OUTPUT_RECEIPT, receipt)
    dashboard = {
        "schema_id": "kt.external_reaudit.attestation_intake_blocker_dashboard.v1",
        "artifact_id": "KT_EXTERNAL_REAUDIT_ATTESTATION_INTAKE_BLOCKER_DASHBOARD",
        "lane": LANE,
        "continuation_label": PARKED_CONTINUATION_LABEL,
        "blockers": receipt["blockers"],
        "blocker_count": receipt["blocker_count"],
        "next_lawful_move": receipt["next_lawful_move"],
        "claim_ceiling_preserved": True,
    }
    write_json_stable(root / OUTPUT_BLOCKER_DASHBOARD, dashboard)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate independent external re-audit attestation intake.")
    parser.add_argument("--attestation-path", default=TARGET_ATTESTATION)
    parser.add_argument("--require-accepted", action="store_true")
    parser.add_argument("--write-receipt", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    path = Path(args.attestation_path)
    try:
        receipt = validate_for_acceptance(root=root, attestation_path=path) if args.require_accepted else evaluate_attestation(root=root, attestation_path=path)
        if args.write_receipt:
            write_outputs(root, receipt)
        print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
        return 0
    except AttestationFailure as exc:
        if args.write_receipt:
            receipt = evaluate_attestation(root=root, attestation_path=path)
            write_outputs(root, receipt)
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
