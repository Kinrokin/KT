from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_e2e_closure_adaptive_ratification_order as order
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


AUTHORITY_BRANCH = "authoritative/kt-e2e-closure-adaptive-ratification-order-validation"
REPLAY_BRANCH_PREFIX = "replay/kt-e2e-closure-adaptive-ratification-order-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

SELECTED_OUTCOME = (
    "KT_E2E_CLOSURE_ADAPTIVE_RATIFICATION_AND_7B_AMPLIFICATION_BENCHMARK_ORDER_VALIDATED__"
    "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT"
)
NEXT_LAWFUL_MOVE = "AUTHOR_B04_R6_EXPANDED_CANARY_AUTHORIZATION_PACKET"

OUTPUTS = {
    "validation_contract": "kt_e2e_closure_campaign_order_validation_contract.json",
    "validation_receipt": "kt_e2e_closure_campaign_order_validation_receipt.json",
    "validation_report": "kt_e2e_closure_campaign_order_validation_report.md",
    "validation_reason_codes": "kt_e2e_closure_campaign_order_validation_reason_codes.json",
    "next_lawful_move": "kt_next_lawful_move_receipt.json",
}

REASON_CODES = (
    "RC_KT_CAMPAIGN_ORDER_MISSING",
    "RC_KT_CAMPAIGN_ORDER_OUTCOME_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_PREP_ONLY_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_BOUNDARY_AUTHORITY_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_CLAIM_CEILING_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_ABLATION_LADDER_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_LOBE_FACTORY_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_GPU_GATE_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_BOARD_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_PATH_BINDING_DRIFT",
    "RC_KT_CAMPAIGN_ORDER_NEXT_MOVE_DRIFT",
)

AUTHORITY_KEYS = (
    "runtime_cutover_authorized",
    "r6_open",
    "lobe_activation_authorized",
    "adapter_promotion_authorized",
    "package_promotion_authorized",
    "commercial_activation_claim_authorized",
    "gpu_training_authorized",
    "seven_b_amplification_proven",
    "truth_engine_law_mutated",
    "trust_zone_law_mutated",
)

NEGATIVE_GUARDS = (
    "cannot_authorize_runtime_cutover",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
)


def _ensure_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch not in ALLOWED_BRANCHES and not branch.startswith(REPLAY_BRANCH_PREFIX):
        allowed = ", ".join(sorted([*ALLOWED_BRANCHES, f"{REPLAY_BRANCH_PREFIX}*"]))
        raise RuntimeError(f"FAIL_CLOSED: must run on one of: {allowed}; got: {branch}")
    if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
        raise RuntimeError("FAIL_CLOSED: main validation requires HEAD to equal origin/main")
    if common.git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: dirty worktree before campaign order validation")
    return branch


def _fail(reason: str, message: str) -> None:
    raise RuntimeError(f"FAIL_CLOSED[{reason}]: {message}")


def _load_campaign_outputs(reports_root: Path) -> Dict[str, Dict[str, Any]]:
    payloads: Dict[str, Dict[str, Any]] = {}
    for role, filename in order.OUTPUTS.items():
        path = reports_root / filename
        if not path.exists():
            _fail("RC_KT_CAMPAIGN_ORDER_MISSING", f"missing campaign output {filename}")
        payload = load_json(path)
        if not isinstance(payload, dict):
            _fail("RC_KT_CAMPAIGN_ORDER_MISSING", f"campaign output must be JSON object {filename}")
        payloads[role] = payload
    return payloads


def _walk_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _validate_prep_only(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role, payload in payloads.items():
        replayed_next_move = (
            role == "next_lawful_move"
            and payload.get("authority") == "VALIDATION"
            and payload.get("selected_outcome") == SELECTED_OUTCOME
            and payload.get("campaign_validation_complete") is True
        )
        if payload.get("authority") != order.AUTHORITY and not replayed_next_move:
            _fail("RC_KT_CAMPAIGN_ORDER_PREP_ONLY_DRIFT", f"{role} authority drifted")
        for guard in NEGATIVE_GUARDS:
            if payload.get(guard) is not True:
                _fail("RC_KT_CAMPAIGN_ORDER_PREP_ONLY_DRIFT", f"{role} missing guard {guard}")
        for nested in _walk_dicts(payload):
            for key in AUTHORITY_KEYS:
                if nested.get(key) is True:
                    _fail("RC_KT_CAMPAIGN_ORDER_BOUNDARY_AUTHORITY_DRIFT", f"{role} grants {key}")


def _validate_campaign_shape(payloads: Dict[str, Dict[str, Any]]) -> None:
    campaign = payloads["campaign_order"]
    if campaign.get("selected_outcome") != order.SELECTED_OUTCOME:
        _fail("RC_KT_CAMPAIGN_ORDER_OUTCOME_DRIFT", "campaign order selected outcome drifted")
    if campaign.get("next_lawful_move") != order.NEXT_LAWFUL_MOVE:
        _fail("RC_KT_CAMPAIGN_ORDER_NEXT_MOVE_DRIFT", "campaign order next lawful move drifted")
    if "does not claim small models are secretly giant models" not in str(campaign.get("required_statement", "")):
        _fail("RC_KT_CAMPAIGN_ORDER_CLAIM_CEILING_DRIFT", "required 7B caveat missing")

    bindings = campaign.get("prior_bindings", {})
    for key in ("canary_evidence_validation_receipt", "canary_post_run_decision_matrix_validation_receipt"):
        raw = str(bindings.get(key, ""))
        if not raw.startswith("KT_PROD_CLEANROOM/reports/") or ":" in raw or raw.startswith("/"):
            _fail("RC_KT_CAMPAIGN_ORDER_PATH_BINDING_DRIFT", f"{key} must be repo-relative")

    claim_ceiling = payloads["claim_ceiling"]
    if "7B amplification is proven." not in claim_ceiling.get("forbidden_claims", []):
        _fail("RC_KT_CAMPAIGN_ORDER_CLAIM_CEILING_DRIFT", "7B overclaim is not forbidden")
    if "KT beats larger models generally." not in claim_ceiling.get("forbidden_claims", []):
        _fail("RC_KT_CAMPAIGN_ORDER_CLAIM_CEILING_DRIFT", "general superiority overclaim is not forbidden")

    ablation = payloads["amplification_ablation_plan"]
    if ablation.get("ablation_ladder") != list(order.ABLATION_LADDER):
        _fail("RC_KT_CAMPAIGN_ORDER_ABLATION_LADDER_DRIFT", "7B ablation ladder drifted")
    if ablation.get("theorem_status") != "NOT_PROVEN":
        _fail("RC_KT_CAMPAIGN_ORDER_ABLATION_LADDER_DRIFT", "7B theorem must remain unproven")

    lobe = payloads["lobe_ratification_factory"]
    if lobe.get("lobe_ratification_order") != list(order.LOBE_RATIFICATION_ORDER):
        _fail("RC_KT_CAMPAIGN_ORDER_LOBE_FACTORY_DRIFT", "lobe ratification order drifted")
    if lobe.get("lobe_activation") != "BLOCKED_UNTIL_FUTURE_AUTHORITY":
        _fail("RC_KT_CAMPAIGN_ORDER_LOBE_FACTORY_DRIFT", "lobe activation boundary drifted")

    gpu = payloads["gpu_training_gate"]
    if gpu.get("gpu_training_readiness") != "BLOCKED_PENDING_TRAINING_LAW":
        _fail("RC_KT_CAMPAIGN_ORDER_GPU_GATE_DRIFT", "GPU gate drifted")

    corridors = {row.get("corridor"): row for row in payloads["campaign_board"].get("corridors", []) if isinstance(row, dict)}
    for corridor in order.REQUIRED_CORRIDORS:
        if corridor not in corridors:
            _fail("RC_KT_CAMPAIGN_ORDER_BOARD_DRIFT", f"missing campaign corridor {corridor}")
    if corridors["R6_CORRIDOR"].get("authoritative_next") != order.PREVIOUS_NEXT_LAWFUL_MOVE:
        _fail("RC_KT_CAMPAIGN_ORDER_BOARD_DRIFT", "R6 corridor no longer routes to expanded canary authorship")


def _hash_bindings(reports_root: Path) -> Dict[str, str]:
    bindings = {}
    for role, filename in order.OUTPUTS.items():
        path = reports_root / filename
        bindings[f"{role}_path"] = f"KT_PROD_CLEANROOM/reports/{filename}"
        bindings[f"{role}_hash"] = file_sha256(path)
    return bindings


def _validation_base(*, role: str, branch: str, head: str, current_main_head: str, generated_utc: str) -> Dict[str, Any]:
    return {
        **order._prep_guard(),
        "schema_id": "kt.e2e_closure.adaptive_ratification_order.validation.v1",
        "artifact_id": role.upper(),
        "authority": "VALIDATION",
        "created_utc": generated_utc,
        "current_branch": branch,
        "head": head,
        "current_main_head": current_main_head,
        "validated_campaign_id": order.CAMPAIGN_ID,
        "predecessor_outcome": order.SELECTED_OUTCOME,
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_proven": False,
        "lobe_activation_authorized": False,
        "gpu_training_authorized": False,
    }


def _write_report(path: Path, *, current_main_head: str) -> None:
    path.write_text(
        "\n".join(
            [
                "# KT E2E Campaign Order Validation",
                "",
                f"Outcome: {SELECTED_OUTCOME}",
                "",
                f"Current main: {current_main_head}",
                "",
                f"Next lawful move: {NEXT_LAWFUL_MOVE}",
                "",
                "The campaign constitution validated as PREP_ONLY. It does not authorize runtime cutover, R6 opening, lobe activation, adapter promotion, GPU training authority, package promotion, commercial activation claims, or 7B amplification claims.",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )


def run(*, reports_root: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    reports_root = reports_root or root / "KT_PROD_CLEANROOM" / "reports"
    if reports_root.resolve() != (root / "KT_PROD_CLEANROOM/reports").resolve():
        raise RuntimeError("FAIL_CLOSED: must write canonical reports root only")

    branch = _ensure_context(root)
    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    payloads = _load_campaign_outputs(reports_root)
    _validate_prep_only(payloads)
    _validate_campaign_shape(payloads)

    generated_utc = utc_now_iso_z()
    bindings = _hash_bindings(reports_root)
    contract = {
        **_validation_base(
            role="kt_e2e_closure_campaign_order_validation_contract",
            branch=branch,
            head=head,
            current_main_head=current_main_head,
            generated_utc=generated_utc,
        ),
        "binding_hashes": bindings,
        "validated_checks": list(REASON_CODES),
    }
    receipt = {
        **_validation_base(
            role="kt_e2e_closure_campaign_order_validation_receipt",
            branch=branch,
            head=head,
            current_main_head=current_main_head,
            generated_utc=generated_utc,
        ),
        "campaign_order_validated": True,
        "binding_hashes": bindings,
        "post_validation_parallel_prep_tracks": [
            "proof_factory_v1",
            "claim_compiler_v1",
            "promotion_engine_v1",
            "lobe_ratification_factory",
            "adapter_tournament_factory",
            "benchmark_constitution",
            "external_verifier",
            "commercial_truth_plane",
            "gpu_training_readiness",
            "competition_factory",
        ],
    }
    reason_codes = {
        **_validation_base(
            role="kt_e2e_closure_campaign_order_validation_reason_codes",
            branch=branch,
            head=head,
            current_main_head=current_main_head,
            generated_utc=generated_utc,
        ),
        "reason_codes": list(REASON_CODES),
    }
    next_move = {
        **_validation_base(
            role="kt_next_lawful_move_receipt",
            branch=branch,
            head=head,
            current_main_head=current_main_head,
            generated_utc=generated_utc,
        ),
        "receipt_type": "NEXT_LAWFUL_MOVE",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "expanded_canary_execution_authorized": False,
        "campaign_validation_complete": True,
    }

    write_json_stable(reports_root / OUTPUTS["validation_contract"], contract)
    write_json_stable(reports_root / OUTPUTS["validation_receipt"], receipt)
    write_json_stable(reports_root / OUTPUTS["validation_reason_codes"], reason_codes)
    write_json_stable(reports_root / OUTPUTS["next_lawful_move"], next_move)
    _write_report(reports_root / OUTPUTS["validation_report"], current_main_head=current_main_head)
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the prep-only KT E2E adaptive ratification campaign order.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    reports_root = (repo_root() / args.reports_root).resolve()
    result = run(reports_root=reports_root)
    print(result["selected_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
