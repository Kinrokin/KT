from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_GATE_D_DECISION_LAW_REL = "KT_PROD_CLEANROOM/governance/gate_d_decision_law.json"
DEFAULT_GATE_D_DECISION_TERMINAL_STATE_REL = "KT_PROD_CLEANROOM/governance/gate_d_decision_terminal_state.json"
DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_reanchor_packet.json"
DEFAULT_GATE_D_DECISION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/gate_d_decision_law_receipt.json"

EXPECTED_DEFAULTS = {
    "D1_EXTERNALITY_WIDENING": "EXTERNALITY_BOUNDED",
    "D2_NEW_COUNTED_DOMAINS": "COUNTED_DOMAINS_FROZEN",
    "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION": "STATIC_SYSTEM",
    "D4_COMPARATIVE_COMPETITIVE_CLAIMS": "NO_EXTERNAL_COMPARATIVE_CLAIMS",
    "D5_COMMERCIAL_ACTIVATION": "LAB_ONLY",
}

EXPECTED_ENUMS = {
    "D1_EXTERNALITY_WIDENING": [
        "EXTERNALITY_BOUNDED",
        "EXTERNALITY_CONTROLLED_EXPANSION",
        "EXTERNALITY_OPEN",
    ],
    "D2_NEW_COUNTED_DOMAINS": [
        "COUNTED_DOMAINS_FROZEN",
        "COUNTED_DOMAINS_CONTROLLED_EXPANSION",
        "COUNTED_DOMAINS_OPEN",
    ],
    "D3_ADAPTIVE_EVOLUTION_AUTHORIZATION": [
        "STATIC_SYSTEM",
        "ADAPTER_EVOLUTION_AUTHORIZED",
        "FULL_TOURNAMENT_EVOLUTION_AUTHORIZED",
    ],
    "D4_COMPARATIVE_COMPETITIVE_CLAIMS": [
        "NO_EXTERNAL_COMPARATIVE_CLAIMS",
        "BOUNDED_COMPARATIVE_CLAIMS",
        "OPEN_COMPARATIVE_CLAIMS",
    ],
    "D5_COMMERCIAL_ACTIVATION": [
        "LAB_ONLY",
        "OPERATOR_SERVICE",
        "CONTROLLED_COMMERCIAL_DEPLOYMENT",
        "PLATFORM_LICENSING",
    ],
}


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _write_receipt(
    *,
    root: Path,
    target: Path,
    payload: Dict[str, Any],
    allow_default_repo_write: bool,
) -> None:
    default_target = (root / DEFAULT_GATE_D_DECISION_RECEIPT_REL).resolve()
    resolved_target = target.resolve()
    if resolved_target == default_target and not allow_default_repo_write:
        raise RuntimeError("FAIL_CLOSED: tracked Gate D decision-law receipt refresh requires --allow-tracked-output-refresh")
    write_json_stable(resolved_target, payload)


def build_gate_d_decision_law_receipt(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    law = load_json(root / DEFAULT_GATE_D_DECISION_LAW_REL)
    terminal = load_json(root / DEFAULT_GATE_D_DECISION_TERMINAL_STATE_REL)
    reanchor = load_json(root / DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL)

    domains = law["decision_domains"]
    domain_rows: List[Dict[str, Any]] = []
    for domain in domains:
        domain_id = str(domain.get("domain_id", "")).strip()
        allowed_postures = [str(item).strip() for item in domain.get("allowed_postures", [])]
        default_posture = str(domain.get("default_posture", "")).strip()
        selected_posture = domain.get("selected_posture")
        domain_rows.append(
            {
                "domain_id": domain_id,
                "allowed_postures_exact": allowed_postures == EXPECTED_ENUMS.get(domain_id, []),
                "default_posture": default_posture,
                "default_is_restrictive": default_posture == EXPECTED_DEFAULTS.get(domain_id, ""),
                "selected_posture": selected_posture,
                "selected_posture_is_unset": selected_posture is None,
            }
        )

    checks = [
        {
            "check_id": "law_type_is_gate_d_decision_ballot",
            "pass": str(law.get("law_type", "")).strip() == "GATE_D_DECISION_BALLOT",
        },
        {
            "check_id": "mode_is_definition_only_no_posture_selected",
            "pass": str(law.get("mode", "")).strip() == "DEFINITION_ONLY_NO_POSTURE_SELECTED",
        },
        {
            "check_id": "gate_c_exit_head_matches_reanchor_packet",
            "pass": str(law.get("gate_c_exit_head", "")).strip()
            == str(reanchor["authoritative_gate_c_exit"]["authoritative_head"]).strip(),
        },
        {
            "check_id": "reanchor_head_matches_reanchor_packet",
            "pass": str(law.get("reanchor_head", "")).strip() == str(reanchor.get("reanchor_head", "")).strip(),
        },
        {
            "check_id": "b04_activation_disabled_in_law",
            "pass": law.get("b04_activation_allowed") is False,
        },
        {
            "check_id": "postures_unselected_in_law",
            "pass": law.get("postures_selected") is False,
        },
        {
            "check_id": "all_required_domains_present",
            "pass": [row["domain_id"] for row in domain_rows] == list(EXPECTED_DEFAULTS.keys())
            and law.get("required_domain_ids") == list(EXPECTED_DEFAULTS.keys()),
        },
        {
            "check_id": "all_domains_have_exact_enums_restrictive_defaults_and_no_selected_posture",
            "pass": all(
                row["allowed_postures_exact"]
                and row["default_is_restrictive"]
                and row["selected_posture_is_unset"]
                for row in domain_rows
            ),
        },
        {
            "check_id": "activation_rules_fail_closed_before_decision",
            "pass": law["activation_rules"]["b04_requires_gate_d_decision"] is True
            and law["activation_rules"]["b04_requires_all_required_domains_resolved"] is True
            and law["activation_rules"]["b04_requires_same_head_decision_receipt"] is True
            and str(law["activation_rules"]["b04_activation_without_gate_d_decision"]).strip() == "FAIL_CLOSED"
            and law["activation_rules"]["gate_d_decision_does_not_activate_b04_by_itself"] is True,
        },
        {
            "check_id": "decision_receipt_requirement_is_same_head_and_nonactivating",
            "pass": str(law["decision_receipt_requirement"]["required_receipt_ref"]).strip()
            == "KT_PROD_CLEANROOM/reports/gate_d_decision_receipt.json"
            and law["decision_receipt_requirement"]["same_head_required"] is True
            and law["decision_receipt_requirement"]["must_select_all_required_domains"] is True
            and law["decision_receipt_requirement"]["may_not_activate_b04"] is True
            and str(law["decision_receipt_requirement"]["must_reference_gate_d_decision_law_ref"]).strip()
            == DEFAULT_GATE_D_DECISION_LAW_REL
            and str(law["decision_receipt_requirement"]["must_reference_gate_d_decision_reanchor_packet_ref"]).strip()
            == DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL,
        },
        {
            "check_id": "terminal_state_is_unselected_and_nonactivating",
            "pass": str(terminal.get("current_state", "")).strip() == "DECISION_LAW_BOUND_POSTURES_UNSELECTED"
            and terminal.get("postures_selected") is False
            and terminal.get("b04_activation_allowed") is False
            and terminal.get("gate_d_decision_receipt_required") is True,
        },
        {
            "check_id": "terminal_next_move_is_posture_selection_only",
            "pass": str(terminal.get("next_lawful_move", "")).strip() == "B04_GATE_D_POSTURE_SELECTION_ONLY"
            and str(law.get("next_lawful_move_after_law", "")).strip() == "B04_GATE_D_POSTURE_SELECTION_ONLY",
        },
        {
            "check_id": "claim_boundary_does_not_activate_b04",
            "pass": "does not select any posture" in str(law.get("claim_boundary", "")).strip().lower()
            and "does not activate b04" in str(terminal.get("terminal_rule", "")).strip().lower(),
        },
    ]

    status = "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_d.decision_law_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": status,
        "receipt_role": "COUNTED_GATE_D_DECISION_LAW_ARTIFACT_ONLY",
        "law_type": str(law.get("law_type", "")).strip(),
        "mode": str(law.get("mode", "")).strip(),
        "gate_c_exit_head": str(law.get("gate_c_exit_head", "")).strip(),
        "reanchor_head": str(law.get("reanchor_head", "")).strip(),
        "postures_selected": law.get("postures_selected") is True,
        "b04_activation_allowed": law.get("b04_activation_allowed") is True,
        "canonical_receipt_binding": {
            "gate_d_decision_law_ref": DEFAULT_GATE_D_DECISION_LAW_REL,
            "gate_d_decision_terminal_state_ref": DEFAULT_GATE_D_DECISION_TERMINAL_STATE_REL,
            "gate_d_decision_reanchor_packet_ref": DEFAULT_GATE_D_DECISION_REANCHOR_PACKET_REL,
        },
        "domain_rows": domain_rows,
        "checks": checks,
        "next_lawful_move": "B04_GATE_D_POSTURE_SELECTION_ONLY" if status == "PASS" else "FIX_GATE_D_DECISION_LAW_DEFINITION_DEFECT",
        "claim_boundary": "This receipt proves only that the Gate D ballot is definition-only, posture values remain unselected, and B04 activation stays fail-closed until a future same-head decision receipt exists.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the Gate D decision-law ballot without selecting any posture.")
    parser.add_argument("--output", default=DEFAULT_GATE_D_DECISION_RECEIPT_REL)
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    receipt = build_gate_d_decision_law_receipt(root=root)
    output = _resolve(root, str(args.output))
    _write_receipt(
        root=root,
        target=output,
        payload=receipt,
        allow_default_repo_write=args.allow_tracked_output_refresh,
    )
    result = {
        "status": receipt["status"],
        "gate_d_decision_law_status": receipt["status"],
        "next_lawful_move": receipt["next_lawful_move"],
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
