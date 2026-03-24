from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFERRED_BLOCKERS_REL = f"{REPORT_ROOT_REL}/deferred_blockers.json"
BLOCKER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave5_blocker_matrix.json"
REMAINING_GAP_REL = f"{REPORT_ROOT_REL}/kt_wave5_remaining_gap_register.json"
FINAL_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave5_final_claim_class_matrix.json"
TRUTH_MAP_REL = f"{REPORT_ROOT_REL}/kt_unified_convergence_current_truth_map.json"
SECOND_HOST_EXECUTION_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_execution_receipt.json"
HEARTBEAT_REL = f"{REPORT_ROOT_REL}/c006_deferral_heartbeat.json"
DEFERRAL_STATUS_RECEIPT_REL = f"{REPORT_ROOT_REL}/c006_deferral_status_receipt.json"
TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _dedupe_strings(items: Sequence[str]) -> List[str]:
    deduped: List[str] = []
    for item in items:
        text = str(item).strip()
        if text and text not in deduped:
            deduped.append(text)
    return deduped


def _append_sentence(summary: str, note: str) -> str:
    left = str(summary).strip()
    right = str(note).strip()
    if not right:
        return left
    if right in left:
        return left
    if not left:
        return right
    return f"{left} {right}"


def _must_not_sentence(value: str) -> str:
    text = str(value).strip().rstrip(".")
    if not text:
        return ""
    if text.lower().startswith("do not "):
        return f"{text}."
    return f"Do not {text}."


def _load_c006_deferral(root: Path) -> Dict[str, Any]:
    payload = load_json(root / DEFERRED_BLOCKERS_REL)
    rows = payload.get("deferred", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: deferred blocker register missing deferred rows")
    for row in rows:
        if not isinstance(row, dict):
            continue
        blocker_id = str(row.get("blocker_id", "")).strip()
        status = str(row.get("status", "")).strip()
        if blocker_id == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED":
            if status != "DEFERRED_RESOURCE_CONSTRAINT":
                raise RuntimeError("FAIL_CLOSED: C006 deferral row exists but is not DEFERRED_RESOURCE_CONSTRAINT")
            machine_state = row.get("machine_effective_state", {})
            if not isinstance(machine_state, dict):
                raise RuntimeError("FAIL_CLOSED: C006 machine_effective_state missing")
            return {
                "payload": payload,
                "row": dict(row),
                "machine_state": dict(machine_state),
            }
    raise RuntimeError("FAIL_CLOSED: C006 deferred blocker row missing")


def build_blocker_matrix(*, root: Path, c006: Mapping[str, Any]) -> Dict[str, Any]:
    payload = load_json(root / BLOCKER_MATRIX_REL)
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    open_blockers = payload.get("open_blockers", [])
    if not isinstance(open_blockers, list):
        raise RuntimeError("FAIL_CLOSED: blocker matrix open_blockers missing")

    updated = False
    for blocker in open_blockers:
        if not isinstance(blocker, dict):
            continue
        if str(blocker.get("blocker_id", "")).strip() != "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED":
            continue
        blocker["state"] = str(machine_state.get("blocker_state", "")).strip() or "OPEN_DEFERRED_RESOURCE_CONSTRAINT"
        blocker["deferral_status"] = str(row.get("status", "")).strip()
        blocker["current_externality_ceiling"] = str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip()
        blocker["comparative_widening"] = str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN"
        blocker["commercial_widening"] = str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN"
        blocker["reentry_condition"] = {
            "description": str(row.get("reentry_condition", {}).get("description", "")).strip(),
            "return_import_path": str(row.get("reentry_condition", {}).get("return_import_path", "")).strip(),
            "validators": list(row.get("reentry_condition", {}).get("validators", [])),
        }
        blocker["summary"] = (
            "C006 is an active canonical blocker deferred under resource constraint. "
            "Externality remains bounded at E1 until a real second-host return is imported and validated. "
            "Engineering may continue under enforced E1 claim ceilings only."
        )
        blocker["missing_proof_to_close"] = str(row.get("reentry_condition", {}).get("description", "")).strip()
        updated = True
        break

    if not updated:
        raise RuntimeError("FAIL_CLOSED: blocker matrix missing active C006 row")

    payload["generated_utc"] = utc_now_iso_z()
    payload["matrix_status"] = "OPEN_DEFERRED_BLOCKERS_PRESENT"
    payload["blocked_promotions"] = _dedupe_strings(
        [
            *[str(item) for item in payload.get("blocked_promotions", [])],
            "externality_class_above_E1",
            "comparative_or_superiority_claims",
            "commercial_or_enterprise_readiness_claims",
        ]
    )
    payload["deferred_blocker_register_ref"] = DEFERRED_BLOCKERS_REL
    payload["deferral_heartbeat_ref"] = HEARTBEAT_REL
    return payload


def build_remaining_gap_register(*, root: Path, c006: Mapping[str, Any]) -> Dict[str, Any]:
    payload = load_json(root / REMAINING_GAP_REL)
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: remaining gap register rows missing")

    updated = False
    for gap in rows:
        if not isinstance(gap, dict):
            continue
        if str(gap.get("gap_id", "")).strip() != "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED":
            continue
        gap["status"] = str(row.get("status", "")).strip()
        gap["current_externality_ceiling"] = str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip()
        gap["comparative_widening"] = str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN"
        gap["commercial_widening"] = str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN"
        gap["reentry_condition"] = {
            "return_import_path": str(row.get("reentry_condition", {}).get("return_import_path", "")).strip(),
            "validators": list(row.get("reentry_condition", {}).get("validators", [])),
        }
        gap["summary"] = (
            "C006 remains open, deferred, and load-bearing under resource constraint. "
            "KT may continue bounded E1 work, but no E2+, comparative, or commercial widening is lawful."
        )
        gap["missing_proof"] = str(row.get("reentry_condition", {}).get("description", "")).strip()
        updated = True
        break

    if not updated:
        raise RuntimeError("FAIL_CLOSED: remaining gap register missing C006 row")

    payload["generated_utc"] = utc_now_iso_z()
    payload["deferred_gap_count"] = 1
    payload["deferred_blocker_register_ref"] = DEFERRED_BLOCKERS_REL
    return payload


def build_final_claim_class_matrix(*, root: Path, c006: Mapping[str, Any]) -> Dict[str, Any]:
    payload = load_json(root / FINAL_CLAIM_MATRIX_REL)
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    payload["generated_utc"] = utc_now_iso_z()
    payload["active_deferred_blockers"] = [
        {
            "blocker_id": str(row.get("blocker_id", "")).strip(),
            "status": str(row.get("status", "")).strip(),
            "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
            "comparative_widening": str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
            "commercial_widening": str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
            "reentry_condition": str(machine_state.get("reentry_condition", "")).strip() or str(row.get("reentry_condition", {}).get("description", "")).strip(),
            "register_ref": DEFERRED_BLOCKERS_REL,
        }
    ]
    payload["claim_ceiling_overrides"] = {
        "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
        "comparative_widening": str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
        "commercial_widening": str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
        "reentry_condition": str(machine_state.get("reentry_condition", "")).strip() or str(row.get("reentry_condition", {}).get("description", "")).strip(),
    }
    payload["forbidden_escalations"] = _dedupe_strings(
        [
            *[str(item) for item in payload.get("forbidden_escalations", [])],
            "Do not narrate deferred C006 as ignored, softened, or closed.",
            "Do not narrate any surface above E1 while C006 is deferred under resource constraint.",
            "Do not widen comparative or superiority language while C006 remains deferred and open.",
            "Do not widen commercial or enterprise language while C006 remains deferred and open.",
        ]
    )
    return payload


def build_truth_map(*, root: Path, c006: Mapping[str, Any]) -> Dict[str, Any]:
    payload = load_json(root / TRUTH_MAP_REL)
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    payload["generated_utc"] = utc_now_iso_z()
    payload["open_stop_gates"] = _dedupe_strings(
        [
            *[str(item) for item in payload.get("open_stop_gates", [])],
            "c006_deferred_resource_constraint_active",
        ]
    )
    source_surfaces = payload.get("source_surfaces", {})
    if not isinstance(source_surfaces, dict):
        raise RuntimeError("FAIL_CLOSED: truth map source_surfaces missing")
    source_surfaces["current_head_deferred_blocker_surface"] = DEFERRED_BLOCKERS_REL
    source_surfaces["current_head_c006_deferral_heartbeat_surface"] = HEARTBEAT_REL
    payload["source_surfaces"] = source_surfaces
    payload["claim_ceiling_overrides"] = {
        "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
        "comparative_widening": str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
        "commercial_widening": str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
        "reentry_condition": str(machine_state.get("reentry_condition", "")).strip() or str(row.get("reentry_condition", {}).get("description", "")).strip(),
    }
    payload["deferred_blockers"] = [
        {
            "blocker_id": str(row.get("blocker_id", "")).strip(),
            "status": str(row.get("status", "")).strip(),
            "reason": str(row.get("reason", "")).strip(),
            "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
        }
    ]
    partitions = payload.get("truth_partitions", {})
    if not isinstance(partitions, dict):
        raise RuntimeError("FAIL_CLOSED: truth map truth_partitions missing")
    note = "C006 remains open under resource-constrained deferral; no E2+, comparative, or commercial widening is lawful until second-host return plus validator pass."
    for key in (
        "current_head_runtime_truth",
        "current_head_trust_and_provenance_truth",
        "integrated_overall_truth",
        "product_and_commercial_truth",
    ):
        partition = partitions.get(key, {})
        if not isinstance(partition, dict):
            continue
        partition["summary"] = _append_sentence(str(partition.get("summary", "")).strip(), note)
    payload["truth_partitions"] = partitions
    return payload


def build_heartbeat(
    *,
    root: Path,
    c006: Mapping[str, Any],
    blocker_matrix: Mapping[str, Any],
    remaining_gap: Mapping[str, Any],
    final_claim_matrix: Mapping[str, Any],
    truth_map: Mapping[str, Any],
) -> Dict[str, Any]:
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    second_host_execution = load_json(root / SECOND_HOST_EXECUTION_REL)
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    open_blockers = [str(item).strip() for item in truth_lock.get("active_open_blocker_ids", []) if str(item).strip()]
    second_host_return_present = bool(second_host_execution.get("environment_declaration", {}).get("second_host_return_present"))

    blocker_rows = blocker_matrix.get("open_blockers", [])
    blocker_row = next(
        (
            item
            for item in blocker_rows
            if isinstance(item, dict) and str(item.get("blocker_id", "")).strip() == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
        ),
        {},
    )
    gap_rows = remaining_gap.get("rows", [])
    gap_row = next(
        (
            item
            for item in gap_rows
            if isinstance(item, dict) and str(item.get("gap_id", "")).strip() == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
        ),
        {},
    )
    claim_overrides = final_claim_matrix.get("claim_ceiling_overrides", {})
    truth_overrides = truth_map.get("claim_ceiling_overrides", {})
    open_stop_gates = [str(item).strip() for item in truth_map.get("open_stop_gates", []) if str(item).strip()]

    checks = [
        {
            "check_id": "active_truth_lock_still_carries_c006_only",
            "pass": open_blockers == ["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"],
            "ref": TRUTH_LOCK_REL,
        },
        {
            "check_id": "blocker_matrix_carries_open_deferred_c006",
            "pass": str(blocker_row.get("state", "")).strip() == "OPEN_DEFERRED_RESOURCE_CONSTRAINT",
            "ref": BLOCKER_MATRIX_REL,
        },
        {
            "check_id": "remaining_gap_register_carries_c006_deferral",
            "pass": str(gap_row.get("status", "")).strip() == "DEFERRED_RESOURCE_CONSTRAINT",
            "ref": REMAINING_GAP_REL,
        },
        {
            "check_id": "claim_matrix_keeps_e1_and_blocks_widening",
            "pass": (
                str(claim_overrides.get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
                and str(claim_overrides.get("comparative_widening", "")).strip() == "FORBIDDEN"
                and str(claim_overrides.get("commercial_widening", "")).strip() == "FORBIDDEN"
            ),
            "ref": FINAL_CLAIM_MATRIX_REL,
        },
        {
            "check_id": "truth_map_records_deferral_stop_gate",
            "pass": (
                "c006_deferred_resource_constraint_active" in open_stop_gates
                and str(truth_overrides.get("externality_class_max", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY"
            ),
            "ref": TRUTH_MAP_REL,
        },
        {
            "check_id": "second_host_return_still_missing_or_unconsumed",
            "pass": second_host_return_present is False,
            "ref": SECOND_HOST_EXECUTION_REL,
        },
    ]
    enforcement_checks = [item for item in checks if item["check_id"] != "second_host_return_still_missing_or_unconsumed"]
    blocked_claim_ceilings_still_enforced = all(bool(item["pass"]) for item in enforcement_checks)
    no_overclaim_leak_detected = blocked_claim_ceilings_still_enforced

    return {
        "schema_id": "kt.c006.deferral_heartbeat.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS" if blocked_claim_ceilings_still_enforced else "FAIL",
        "blocker_id": str(row.get("blocker_id", "")).strip(),
        "deferral_status": str(row.get("status", "")).strip(),
        "machine_effective_state": {
            "blocker_state": str(machine_state.get("blocker_state", "")).strip() or "OPEN_DEFERRED_RESOURCE_CONSTRAINT",
            "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
            "comparative_widening": str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
            "commercial_widening": str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
            "reentry_condition": str(machine_state.get("reentry_condition", "")).strip() or str(row.get("reentry_condition", {}).get("description", "")).strip(),
        },
        "second_host_return_present": second_host_return_present,
        "new_evidence_changes_eligibility": second_host_return_present,
        "blocked_claim_ceilings_still_enforced": blocked_claim_ceilings_still_enforced,
        "no_overclaim_leak_detected": no_overclaim_leak_detected,
        "reentry_condition_satisfied": False,
        "reentry_condition_ref": str(row.get("reentry_condition", {}).get("return_import_path", "")).strip(),
        "checks": checks,
        "claim_boundary": (
            "C006 remains open, deferred, and unforgettable. This heartbeat preserves E1 ceilings and blocks comparative/commercial widening until a real second-host return is imported and validated."
        ),
        "next_lawful_move": "Continue bounded E1 engineering, packaging, and buyer-safe preparation work while preparing the second-host kit for immediate execution when hardware appears.",
    }


def build_deferral_status_receipt(
    *,
    root: Path,
    c006: Mapping[str, Any],
    heartbeat: Mapping[str, Any],
) -> Dict[str, Any]:
    row = dict(c006["row"])
    machine_state = dict(c006["machine_state"])
    return {
        "schema_id": "kt.c006.deferral_status_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": str(heartbeat.get("status", "")).strip() or "FAIL",
        "blocker_id": str(row.get("blocker_id", "")).strip(),
        "deferral_status": str(row.get("status", "")).strip(),
        "machine_effective_state": {
            "blocker_state": str(machine_state.get("blocker_state", "")).strip() or "OPEN_DEFERRED_RESOURCE_CONSTRAINT",
            "externality_class_max": str(machine_state.get("externality_class_max", "")).strip() or str(row.get("current_externality_ceiling", "")).strip(),
            "comparative_widening": str(machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN",
            "commercial_widening": str(machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN",
            "reentry_condition": str(machine_state.get("reentry_condition", "")).strip() or str(row.get("reentry_condition", {}).get("description", "")).strip(),
        },
        "second_host_return_present": bool(heartbeat.get("second_host_return_present")),
        "blocked_claim_ceilings_still_enforced": bool(heartbeat.get("blocked_claim_ceilings_still_enforced")),
        "source_refs": [
            DEFERRED_BLOCKERS_REL,
            BLOCKER_MATRIX_REL,
            REMAINING_GAP_REL,
            FINAL_CLAIM_MATRIX_REL,
            TRUTH_MAP_REL,
            SECOND_HOST_EXECUTION_REL,
            HEARTBEAT_REL,
        ],
        "claim_boundary": "This receipt records that C006 remains open under resource-constrained deferral and that the E1 ceiling still governs all current-head widening.",
        "next_lawful_move": str(heartbeat.get("next_lawful_move", "")).strip(),
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bind C006 deferral law into live current-head surfaces and emit a recurring heartbeat.")
    parser.add_argument("--blocker-matrix-output", default=BLOCKER_MATRIX_REL)
    parser.add_argument("--remaining-gap-output", default=REMAINING_GAP_REL)
    parser.add_argument("--final-claim-matrix-output", default=FINAL_CLAIM_MATRIX_REL)
    parser.add_argument("--truth-map-output", default=TRUTH_MAP_REL)
    parser.add_argument("--heartbeat-output", default=HEARTBEAT_REL)
    parser.add_argument("--deferral-status-output", default=DEFERRAL_STATUS_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    c006 = _load_c006_deferral(root)
    blocker_matrix = build_blocker_matrix(root=root, c006=c006)
    remaining_gap = build_remaining_gap_register(root=root, c006=c006)
    final_claim_matrix = build_final_claim_class_matrix(root=root, c006=c006)
    truth_map = build_truth_map(root=root, c006=c006)
    heartbeat = build_heartbeat(
        root=root,
        c006=c006,
        blocker_matrix=blocker_matrix,
        remaining_gap=remaining_gap,
        final_claim_matrix=final_claim_matrix,
        truth_map=truth_map,
    )
    deferral_status_receipt = build_deferral_status_receipt(
        root=root,
        c006=c006,
        heartbeat=heartbeat,
    )

    write_json_stable(_resolve(root, str(args.blocker_matrix_output)), blocker_matrix)
    write_json_stable(_resolve(root, str(args.remaining_gap_output)), remaining_gap)
    write_json_stable(_resolve(root, str(args.final_claim_matrix_output)), final_claim_matrix)
    write_json_stable(_resolve(root, str(args.truth_map_output)), truth_map)
    write_json_stable(_resolve(root, str(args.heartbeat_output)), heartbeat)
    write_json_stable(_resolve(root, str(args.deferral_status_output)), deferral_status_receipt)

    summary = {
        "status": "PASS" if heartbeat["status"] == "PASS" else "FAIL",
        "active_deferred_blocker_ids": [str(c006["row"].get("blocker_id", "")).strip()],
        "externality_class_max": heartbeat["machine_effective_state"]["externality_class_max"],
        "comparative_widening": heartbeat["machine_effective_state"]["comparative_widening"],
        "commercial_widening": heartbeat["machine_effective_state"]["commercial_widening"],
        "reentry_condition_satisfied": heartbeat["reentry_condition_satisfied"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
