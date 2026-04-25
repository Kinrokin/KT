from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
OUTPUT_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_trust_prep_receipt.json"
WAVE3_DETACHED_REL = f"{REPORT_ROOT_REL}/kt_wave3_detached_verifier_receipt.json"
WS19_DETACHED_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
WS20_EXTERNAL_REPRO_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"
OUTSIDER_PATH_REL = f"{REPORT_ROOT_REL}/kt_outsider_path_receipt.json"
WAVE4_EXTERNALITY_REL = f"{REPORT_ROOT_REL}/kt_wave4_externality_class_matrix.json"
WAVE5_VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
POST_WAVE5_C016A_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
POST_WAVE5_C016B_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"


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


def build_post_wave5_c006_trust_prep_receipt(*, root: Path) -> Dict[str, Any]:
    wave3_detached = _load_required(root, WAVE3_DETACHED_REL)
    ws19_detached = _load_required(root, WS19_DETACHED_REL)
    ws20_external_repro = _load_required(root, WS20_EXTERNAL_REPRO_REL)
    outsider_path = _load_required(root, OUTSIDER_PATH_REL)
    wave4_externality = _load_required(root, WAVE4_EXTERNALITY_REL)
    wave5_verifier_truth = _load_required(root, WAVE5_VERIFIER_TRUTH_REL)
    c016a_success = _load_required(root, POST_WAVE5_C016A_REL)
    c016b_resilience = _load_required(root, POST_WAVE5_C016B_REL)
    trust_zone = validate_trust_zones(root=root)

    wave4_earned = [
        str(row.get("earned_class", "")).strip()
        for row in wave4_externality.get("earned_classes", [])
        if isinstance(row, dict)
    ]
    outsider_secret_free = str(outsider_path.get("hidden_secret_dependency", "")).strip() == "ABSENT"
    same_host_provider_success = str(c016a_success.get("c016a_delta", "")).strip() == "C016A_CLOSED_FOR_CANONICAL_LIVE_HASHED_LANE"
    same_host_provider_resilience = str(c016b_resilience.get("c016b_delta", "")).strip() == "C016B_CLOSED_FOR_CANONICAL_LIVE_HASHED_RESILIENCE_PATH"

    checks = [
        _check(
            "wave3_detached_verifier_boundary_still_e1",
            str(wave3_detached.get("status", "")).strip() == "PASS"
            and str(wave3_detached.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "Wave 3 detached verifier must remain a same-host packaged detached replay proof only.",
            [WAVE3_DETACHED_REL],
        ),
        _check(
            "ws19_detached_package_parity_still_pass",
            str(ws19_detached.get("status", "")).strip() == "PASS",
            "WS19 detached verifier packaging must remain PASS for the bounded trust substrate.",
            [WS19_DETACHED_REL],
        ),
        _check(
            "ws20_same_host_independent_replay_still_pass",
            str(ws20_external_repro.get("status", "")).strip() == "PASS",
            "WS20 same-host independent clean-environment replay must remain PASS.",
            [WS20_EXTERNAL_REPRO_REL],
        ),
        _check(
            "outsider_secret_free_path_still_pass",
            str(outsider_path.get("status", "")).strip() == "PASS"
            and str(outsider_path.get("deterministic_output_contract", "")).strip() == "PASS"
            and outsider_secret_free,
            "The bounded outsider verifier path must remain deterministic, detached, and secret-free.",
            [OUTSIDER_PATH_REL],
        ),
        _check(
            "wave4_externality_matrix_preserves_e1_ceiling",
            str(wave4_externality.get("status", "")).strip() == "PASS"
            and "E1_SAME_HOST_DETACHED_REPLAY" in wave4_earned
            and "E2_CROSS_HOST_FRIENDLY_REPLAY" in list(wave4_externality.get("not_earned_classes", [])),
            "Wave 4 externality matrix must still preserve E1 as the ceiling and leave E2+ unearned.",
            [WAVE4_EXTERNALITY_REL],
        ),
        _check(
            "wave5_verifier_truth_surface_binds_current_head_to_e1",
            str(wave5_verifier_truth.get("status", "")).strip() == "PASS"
            and str(wave5_verifier_truth.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "Wave 5 verifier truth surface must bind current-head verifier truth to E1 only.",
            [WAVE5_VERIFIER_TRUTH_REL],
        ),
        _check(
            "same_host_live_provider_success_does_not_raise_externality",
            same_host_provider_success and same_host_provider_resilience,
            "The post-Wave5 same-host LIVE_HASHED provider lane is proven, but it does not upgrade C006.",
            [POST_WAVE5_C016A_REL, POST_WAVE5_C016B_REL],
        ),
        _check(
            "trust_zone_boundaries_still_pass",
            str(trust_zone.get("status", "")).strip() == "PASS",
            "Trust-zone and canonical/generated/toolchain boundaries must remain intact while C006 stays open.",
            ["KT_PROD_CLEANROOM/governance/trust_zone_registry.json", "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"],
        ),
    ]

    failures = [str(row["check"]) for row in checks if str(row.get("status", "")).strip() != "PASS"]
    status = "PASS" if not failures else "FAIL"

    return {
        "schema_id": "kt.operator.post_wave5.c006_trust_prep_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "c006_status": "OPEN_PREPARED_NOT_PROMOTED" if status == "PASS" else "BLOCKED",
        "blocker_delta": "C006_PREPARED_FOR_FRIENDLY_CROSS_HOST_PROOF_PATH_BUT_NOT_PROMOTED" if status == "PASS" else "C006_PREP_PATH_BLOCKED",
        "current_externality_ceiling": "E1_SAME_HOST_DETACHED_REPLAY",
        "prepared_surface_refs": [
            WAVE3_DETACHED_REL,
            WS19_DETACHED_REL,
            WS20_EXTERNAL_REPRO_REL,
            OUTSIDER_PATH_REL,
            WAVE4_EXTERNALITY_REL,
            WAVE5_VERIFIER_TRUTH_REL,
        ],
        "same_host_live_provider_refs": [POST_WAVE5_C016A_REL, POST_WAVE5_C016B_REL],
        "same_host_live_provider_boundary": "Canonical same-host LIVE_HASHED OpenAI/OpenRouter success and resilience are proven, but they do not raise externality above E1.",
        "ready_inputs_for_future_c006_work": [
            "same_host_packaged_detached_verifier_parity",
            "same_host_independent_clean_environment_replay",
            "secret_free_outsider_verifier_path_for_bounded_verifier_surfaces",
            "current_head_verifier_truth_surface_bound_to_E1",
        ],
        "not_yet_earned": [
            "E2_CROSS_HOST_FRIENDLY_REPLAY",
            "E3_INDEPENDENT_HOSTILE_REPLAY",
            "E4_PUBLIC_CHALLENGE_SURVIVAL",
        ],
        "checks": checks,
        "exact_remaining_forbidden_claims": [
            "Do not claim C006 closed or upgraded above E1 from same-host trust or live-provider evidence.",
            "Do not claim cross-host friendly replay until a fresh current-head verifier or selected runtime surface is replayed on a different host.",
            "Do not claim outsider or public confirmation of runtime capability from bounded verifier-only outsider tooling.",
            "Do not widen into procurement, product, or router superiority claims from this prep receipt.",
        ],
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit a bounded post-Wave5 C006 trust-substrate preparation receipt without promoting externality.")
    parser.add_argument("--output", default=OUTPUT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()

    receipt = build_post_wave5_c006_trust_prep_receipt(root=root)
    write_json_stable(output_path, receipt)
    print(json.dumps({"status": receipt["status"], "blocker_delta": receipt["blocker_delta"]}, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
