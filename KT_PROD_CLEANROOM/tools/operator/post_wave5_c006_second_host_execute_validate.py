from __future__ import annotations

import argparse
import json
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
IMPORT_ROOT_REL = f"{REPORT_ROOT_REL}/imports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"

ANCHOR_REL = f"{GOVERNANCE_ROOT_REL}/kt_unified_convergence_max_power_campaign_v2_1_1_anchor.json"
HANDOFF_PACK_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_friendly_host_handoff_pack.json"
VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
OUTPUT_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_execution_receipt.json"
TEMPLATE_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_submission_template.json"
DEFAULT_RETURN_REL = f"{IMPORT_ROOT_REL}/post_wave5_c006_second_host_return.json"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _check(check_id: str, ok: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected object json at {rel}")
    return payload


def _machine_fingerprint() -> str:
    return json.dumps(
        {
            "machine": platform.machine(),
            "node": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "system": platform.system(),
        },
        sort_keys=True,
    )


def build_second_host_submission_template(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.post_wave5.c006_second_host_return.v1",
        "status": "PENDING_RETURN",
        "current_head_commit": current_head,
        "handoff_pack_ref": HANDOFF_PACK_REL,
        "required_environment_class": "E_CROSS_HOST_FRIENDLY",
        "required_fields": [
            "schema_id",
            "status",
            "current_head_commit",
            "handoff_pack_ref",
            "environment_class",
            "host_label",
            "machine_fingerprint",
            "detached_verifier_status",
            "deterministic_output_contract",
            "hidden_secret_dependency",
            "returned_receipt_ref",
            "returned_result_ref",
            "returned_utc",
        ],
        "claim_boundary": "A returned second-host verifier receipt may earn E2 for the bounded verifier surface only if it is fresh, bound to the current-head anchor, and executed on a different friendly host.",
        "forbidden_claims": [
            "broad_current_head_runtime_capability_confirmed",
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "router_or_product_widening_from_verifier_only_second_host_success",
        ],
    }


def build_post_wave5_c006_second_host_execution_receipt(
    *,
    root: Path,
    second_host_return_rel: str = DEFAULT_RETURN_REL,
) -> Dict[str, Any]:
    current_head = _git_head(root)
    anchor = _load_required(root, ANCHOR_REL)
    handoff = _load_required(root, HANDOFF_PACK_REL)
    verifier_truth = _load_required(root, VERIFIER_TRUTH_REL)

    second_host_return_path = (root / Path(second_host_return_rel)).resolve()
    second_host_return: Dict[str, Any] = {}
    second_host_return_present = second_host_return_path.exists()
    if second_host_return_present:
        second_host_return = load_json(second_host_return_path)
        if not isinstance(second_host_return, dict):
            raise RuntimeError(f"FAIL_CLOSED: expected object json at {second_host_return_rel}")

    local_machine_fingerprint = _machine_fingerprint()
    template = build_second_host_submission_template(current_head=current_head)

    checks = [
        _check(
            "anchor_limits_authoritative_scope_to_c006",
            str(anchor.get("current_authorized_scope", {}).get("authoritative_track", "")).strip() == "C006 only",
            "The active anchor must keep the canonical lane narrowed to C006 only.",
            [ANCHOR_REL],
        ),
        _check(
            "handoff_pack_is_pass_and_e1_only",
            str(handoff.get("status", "")).strip() == "PASS"
            and str(handoff.get("current_externality_ceiling", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "The handoff pack must remain PASS while keeping the current ceiling at E1.",
            [HANDOFF_PACK_REL],
        ),
        _check(
            "wave5_verifier_truth_remains_current_head_e1",
            str(verifier_truth.get("status", "")).strip() == "PASS"
            and str(verifier_truth.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "Current-head verifier truth must remain explicitly bounded at E1 before second-host promotion.",
            [VERIFIER_TRUTH_REL],
        ),
        _check(
            "second_host_return_present",
            second_host_return_present,
            "A fresh second-host return receipt must be imported before E2 can be earned.",
            [second_host_return_rel],
        ),
    ]

    exact_externality_class_earned = "NOT_EARNED"
    blocker_delta = "C006_EXECUTION_ATTEMPTED_AWAITING_SECOND_HOST_RETURN"
    c006_status = "OPEN_SECOND_HOST_EXECUTION_PENDING"

    if second_host_return_present:
        returned_head = str(second_host_return.get("current_head_commit", "")).strip()
        returned_handoff = str(second_host_return.get("handoff_pack_ref", "")).strip()
        returned_env = str(second_host_return.get("environment_class", "")).strip()
        returned_machine = str(second_host_return.get("machine_fingerprint", "")).strip()
        detached_status = str(second_host_return.get("detached_verifier_status", "")).strip()
        deterministic = str(second_host_return.get("deterministic_output_contract", "")).strip()
        hidden_secret = str(second_host_return.get("hidden_secret_dependency", "")).strip()

        checks.extend(
            [
                _check(
                    "second_host_return_matches_current_head",
                    returned_head == current_head,
                    "Returned second-host evidence must bind to the current repo head, not an older subject.",
                    [second_host_return_rel, ANCHOR_REL],
                ),
                _check(
                    "second_host_return_matches_handoff_pack",
                    returned_handoff == HANDOFF_PACK_REL,
                    "Returned second-host evidence must bind to the active post-Wave5 handoff pack.",
                    [second_host_return_rel, HANDOFF_PACK_REL],
                ),
                _check(
                    "second_host_environment_declared_as_friendly_cross_host",
                    returned_env == "E_CROSS_HOST_FRIENDLY",
                    "Returned second-host evidence must explicitly declare E_CROSS_HOST_FRIENDLY.",
                    [second_host_return_rel],
                ),
                _check(
                    "second_host_machine_differs_from_local_host",
                    bool(returned_machine) and returned_machine != local_machine_fingerprint,
                    "Friendly-host replay must declare a different machine fingerprint than the local execution host.",
                    [second_host_return_rel],
                ),
                _check(
                    "second_host_detached_verifier_passes_secret_free_and_deterministic",
                    detached_status == "PASS" and deterministic == "PASS" and hidden_secret == "ABSENT",
                    "The second-host verifier replay must pass, remain deterministic, and require no hidden secrets.",
                    [second_host_return_rel],
                ),
            ]
        )

        required_ok = all(row["status"] == "PASS" for row in checks)
        if required_ok:
            exact_externality_class_earned = "E2_CROSS_HOST_FRIENDLY_REPLAY"
            blocker_delta = "C006_CLOSED_FOR_BOUNDED_VERIFIER_E2_FRIENDLY_HOST_REPLAY"
            c006_status = "CLOSED_BOUNDED_VERIFIER_E2_ONLY"
        else:
            blocker_delta = "C006_SECOND_HOST_RETURN_IMPORTED_BUT_NOT_E2_ADMISSIBLE"
            c006_status = "OPEN_SECOND_HOST_RETURN_INVALID_OR_PARTIAL"

    status = "PASS"
    return {
        "schema_id": "kt.operator.post_wave5.c006_second_host_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_repo_head": current_head,
        "c006_status": c006_status,
        "blocker_delta": blocker_delta,
        "exact_externality_class_earned": exact_externality_class_earned,
        "environment_declaration": {
            "local_execution_host_fingerprint": local_machine_fingerprint,
            "required_second_host_environment_class": "E_CROSS_HOST_FRIENDLY",
            "second_host_return_rel": second_host_return_rel,
            "second_host_return_present": second_host_return_present,
        },
        "second_host_return_summary": second_host_return if second_host_return_present else {
            "status": "MISSING",
            "claim_effect": "NO_EXTERNALITY_PROMOTION",
        },
        "submission_template_ref": TEMPLATE_REL,
        "checks": checks,
        "exact_remaining_forbidden_claims": [
            "Do not claim E2 unless a fresh current-head second-host verifier return is imported and all typed checks pass.",
            "Do not narrate verifier-only second-host success as broad current-head runtime proof.",
            "Do not narrate friendly-host replay as independent hostile replay or public challenge survival.",
            "Do not widen router, product, procurement, or comparative-proof claims from this tranche.",
        ],
        "next_lawful_move": (
            "Import a fresh second-host return receipt that binds to the current-head handoff pack."
            if exact_externality_class_earned == "NOT_EARNED"
            else "Refresh current-head blocker and verifier truth surfaces with the bounded E2 verifier result only."
        ),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute the bounded post-Wave5 C006 second-host intake/typing tranche.")
    parser.add_argument("--output", default=OUTPUT_REL)
    parser.add_argument("--template-output", default=TEMPLATE_REL)
    parser.add_argument("--second-host-return", default=DEFAULT_RETURN_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()

    template_path = Path(str(args.template_output)).expanduser()
    if not template_path.is_absolute():
        template_path = (root / template_path).resolve()

    receipt = build_post_wave5_c006_second_host_execution_receipt(
        root=root,
        second_host_return_rel=str(args.second_host_return),
    )
    template = build_second_host_submission_template(current_head=receipt["current_repo_head"])

    write_json_stable(output_path, receipt)
    write_json_stable(template_path, template)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "blocker_delta": receipt["blocker_delta"],
                "exact_externality_class_earned": receipt["exact_externality_class_earned"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
