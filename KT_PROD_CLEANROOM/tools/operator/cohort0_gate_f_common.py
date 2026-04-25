from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORTS_ROOT_REL = "KT_PROD_CLEANROOM/reports"
PRODUCT_ROOT_REL = "KT_PROD_CLEANROOM/product"
DOCS_COMMERCIAL_ROOT_REL = "KT_PROD_CLEANROOM/docs/commercial"

LIVE_BRANCH_LAW_PACKET_REL = f"{REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_branch_law_packet.json"
LIVE_SUPERSESSION_NOTE_REL = f"{REPORTS_ROOT_REL}/cohort0_successor_gate_d_post_clear_supersession_note.json"
LIVE_ORCHESTRATOR_RECEIPT_REL = f"{REPORTS_ROOT_REL}/cohort0_successor_master_orchestrator_receipt.json"

DEPLOYMENT_PROFILES_REL = f"{PRODUCT_ROOT_REL}/deployment_profiles.json"
CLIENT_WRAPPER_SPEC_REL = f"{PRODUCT_ROOT_REL}/client_wrapper_spec.json"
SUPPORT_BOUNDARY_REL = f"{PRODUCT_ROOT_REL}/support_boundary.json"
ONE_PAGE_TRUTH_SURFACE_REL = f"{PRODUCT_ROOT_REL}/one_page_product_truth_surface.md"
FINAL_PRODUCT_TRUTH_BOUNDARY_REL = f"{PRODUCT_ROOT_REL}/final_product_truth_boundary.json"
OPERATOR_RUNBOOK_REL = f"{PRODUCT_ROOT_REL}/operator_runbook_v2.md"

PRODUCT_INSTALL_RECEIPT_REL = f"{REPORTS_ROOT_REL}/product_install_15m_receipt.json"
OPERATOR_HANDOFF_RECEIPT_REL = f"{REPORTS_ROOT_REL}/operator_handoff_receipt.json"
GREENLINE_RECEIPT_REL = f"{REPORTS_ROOT_REL}/kt_operator_greenline_receipt.json"
COMMERCIAL_TRUTH_PACKET_REL = f"{REPORTS_ROOT_REL}/commercial_truth_packet.json"
PUBLIC_VERIFIER_KIT_REL = f"{REPORTS_ROOT_REL}/public_verifier_kit.json"
DETACHED_VERIFIER_RECEIPT_REL = f"{REPORTS_ROOT_REL}/kt_public_verifier_detached_receipt.json"
EXTERNAL_AUDIT_PACKET_REL = f"{REPORTS_ROOT_REL}/external_audit_packet_manifest.json"
LIVE_VALIDATION_INDEX_REL = f"{REPORTS_ROOT_REL}/live_validation_index.json"

E1_WEDGE_DOC_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/E1_BOUNDED_TRUST_WEDGE.md"
E1_DEMO_DOC_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/E1_DEMO_SCRIPT.md"

GATE_F_WEDGE_ID = "KT_F_NARROW_LOCAL_VERIFIER_EXECUTE_RECEIPT_WEDGE_V1"
ACTIVE_WEDGE_PROFILE_ID = "local_verifier_mode"
ACTIVE_WEDGE_ENTRYPOINT_IDS = ("verify_packet", "detached_pass_fail")
ACTIVE_WEDGE_COMMAND = "python -m tools.operator.public_verifier"
GATE_F_CONFIRMED_POSTURE = "GATE_F_ONE_NARROW_WEDGE_CONFIRMED__LOCAL_VERIFIER_MODE_ONLY"
ACTIVE_WEDGE_RECEIPT_REFS = (
    "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
    "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
)
CURRENT_POSTURE = "GATE_E_OPEN__POST_SUCCESSOR_GATE_D_CLEAR"

TENANT_POSTURE_SINGLE_ONLY = "SINGLE_TENANT_ONLY_DECLARED"
NEXT_MOVE_SCOPE = "AUTHOR_GATE_F_PRODUCT_TRUTH_AND_GOVERNANCE_CONTRACT"
NEXT_MOVE_GOVERNANCE = "EXECUTE_GATE_F_DEPLOYMENT_SMOKE_AND_TENANT_ISOLATION_WAVE"
NEXT_MOVE_DEPLOY = "EXECUTE_GATE_F_FRESH_OPERATOR_BOOTSTRAP_AND_GREENLINE_WAVE"
NEXT_MOVE_BOOTSTRAP = "EXECUTE_GATE_F_EXTERNAL_WORKLOAD_PILOT"
NEXT_MOVE_PILOT = "AUTHOR_GATE_F_BUYER_SAFE_LANGUAGE_AND_SUPPORT_BOUNDARY_PACKET"
NEXT_MOVE_LANGUAGE = "EXECUTE_GATE_F_PRODUCT_WEDGE_ADMISSIBILITY_SCREEN"
NEXT_MOVE_SCREEN = "CONVENE_GATE_F_ONE_NARROW_WEDGE_REVIEW"
NEXT_MOVE_MAINTAIN = "MAINTAIN_GATE_F_ONE_NARROW_WEDGE_POSTURE__LOCAL_VERIFIER_MODE_ONLY"
NEXT_MOVE_FREEZE_LIVE_PRODUCT_TRUTH = "FREEZE_GATE_F_WEDGE_AS_CANONICAL_LIVE_PRODUCT_TRUTH"
NEXT_MOVE_POST_F_REAUDIT = "CONVENE_POST_F_BROAD_CANONICAL_REAUDIT__MINIMUM_PATH_COMPLETE_CANDIDATE"
NEXT_MOVE_POST_F_EXPANSION = "AUTHOR_CONTROLLED_POST_F_EXPANSION_TRACKS__POST_REAUDIT_PASS"


def resolve_path(root: Path, raw: str | Path) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def load_json_required(root: Path, raw: str | Path, *, label: str) -> Dict[str, Any]:
    path = resolve_path(root, raw)
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def read_text_required(root: Path, raw: str | Path, *, label: str) -> str:
    path = resolve_path(root, raw)
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def ensure_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def ensure_live_post_e_state(
    *,
    branch_law_packet: Dict[str, Any],
    supersession_note: Dict[str, Any],
    orchestrator_receipt: Dict[str, Any],
) -> str:
    ensure_pass(branch_law_packet, label="live branch law packet")
    ensure_pass(supersession_note, label="live supersession note")
    ensure_pass(orchestrator_receipt, label="live orchestrator receipt")

    branch_status = dict(branch_law_packet.get("canonical_live_branch_status", {}))
    if not bool(branch_status.get("gate_d_cleared_on_successor_line", False)):
        raise RuntimeError("FAIL_CLOSED: Gate F requires successor-line Gate D clear")
    if not bool(branch_status.get("gate_e_open", False)):
        raise RuntimeError("FAIL_CLOSED: Gate F requires Gate E open on the successor line")
    if not bool(branch_status.get("same_head_counted_reentry_admissible_now", False)):
        raise RuntimeError("FAIL_CLOSED: Gate F requires counted reentry admissible on the successor line")
    if str(orchestrator_receipt.get("current_branch_posture", "")).strip() != CURRENT_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Gate F requires the open-state live posture")
    if not bool(supersession_note.get("successor_line_supersedes_prior_same_head_failure_for_live_branch_posture", False)):
        raise RuntimeError("FAIL_CLOSED: Gate F requires explicit supersession before product claims")
    return str(branch_law_packet.get("subject_head", "")).strip() or str(orchestrator_receipt.get("subject_head", "")).strip()


def first_profile(profiles_payload: Dict[str, Any], *, profile_id: str) -> Dict[str, Any]:
    rows = profiles_payload.get("profiles", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: deployment profiles payload missing profiles list")
    for row in rows:
        if isinstance(row, dict) and str(row.get("profile_id", "")).strip() == profile_id:
            return dict(row)
    raise RuntimeError(f"FAIL_CLOSED: missing required deployment profile: {profile_id}")


def first_entrypoint(wrapper_payload: Dict[str, Any], *, entrypoint_id: str) -> Dict[str, Any]:
    rows = wrapper_payload.get("entrypoints", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: wrapper payload missing entrypoints list")
    for row in rows:
        if isinstance(row, dict) and str(row.get("entrypoint_id", "")).strip() == entrypoint_id:
            return dict(row)
    raise RuntimeError(f"FAIL_CLOSED: missing required entrypoint: {entrypoint_id}")


def find_check(payload: Dict[str, Any], *, check_id: str) -> Dict[str, Any]:
    rows = payload.get("checks", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: checks payload missing checks list")
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("check_id", "")).strip() == check_id or str(row.get("check", "")).strip() == check_id:
            return dict(row)
    raise RuntimeError(f"FAIL_CLOSED: missing required check row: {check_id}")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def report_lines(title: str, rows: Iterable[str]) -> str:
    body = "\n".join(rows)
    return f"# {title}\n\n{body}\n"


def run_public_verifier_smoke(*, root: Path, output_path: Path) -> Dict[str, Any]:
    env = dict(os.environ)
    existing = str(env.get("PYTHONPATH", "")).strip()
    cleanroom = "KT_PROD_CLEANROOM"
    env["PYTHONPATH"] = cleanroom if not existing else f"{cleanroom}{os.pathsep}{existing}"
    command = ["python", "-m", "tools.operator.public_verifier", "--output", output_path.as_posix()]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(
            "FAIL_CLOSED: Gate F live public_verifier smoke failed: "
            + (result.stderr.strip() or result.stdout.strip() or f"rc={result.returncode}")
        )
    if not output_path.is_file():
        raise RuntimeError("FAIL_CLOSED: Gate F public_verifier smoke did not emit output")
    payload = load_json(output_path)
    if not isinstance(payload, dict):
        raise RuntimeError("FAIL_CLOSED: Gate F public_verifier smoke output must be a JSON object")
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Gate F public_verifier smoke must emit PASS")
    return payload


def output_ref_dict(**kwargs: Path) -> Dict[str, str]:
    return {key: value.resolve().as_posix() for key, value in kwargs.items()}


def write_outputs(
    *,
    packet_path: Path,
    receipt_path: Path,
    report_path: Path,
    packet: Dict[str, Any],
    receipt: Dict[str, Any],
    report_text: str,
) -> None:
    write_json_stable(packet_path, packet)
    write_json_stable(receipt_path, receipt)
    write_text(report_path, report_text)


def main_parser(description: str) -> argparse.ArgumentParser:
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--reports-root", default=REPORTS_ROOT_REL)
    parser.add_argument("--branch-law-packet", default=LIVE_BRANCH_LAW_PACKET_REL)
    parser.add_argument("--supersession-note", default=LIVE_SUPERSESSION_NOTE_REL)
    parser.add_argument("--orchestrator-receipt", default=LIVE_ORCHESTRATOR_RECEIPT_REL)
    return parser
