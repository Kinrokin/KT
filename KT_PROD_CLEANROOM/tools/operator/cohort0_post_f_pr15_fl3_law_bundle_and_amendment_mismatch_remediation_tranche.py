from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z
from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle
from tools.verification.law_bundle_change_receipt import (
    _compute_bundle_hash_from_maps,
    _file_digest_map_for_bundle_ref,
    _read_law_bundle_from_ref,
)


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_remediation_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_remediation_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REMEDIATION_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REMEDIATED"
OUTCOME = "POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_SUPPORT_CHAIN_REPAIRED__READY_FOR_T01_RERUN"
NEXT_MOVE = "RERUN_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_PACKET"

AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
T01_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet.json"
T01_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json"
SHA_PATH = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256"
KT_CLI_PATH = "KT_PROD_CLEANROOM/tools/operator/kt_cli.py"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _git_rev_list_first_parent(root: Path, start_ref: str, max_count: int) -> List[str]:
    result = subprocess.run(
        ["git", "rev-list", "--first-parent", f"--max-count={max_count}", start_ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _read_sha_pin(root: Path) -> str:
    return common.resolve_path(root, SHA_PATH).read_text(encoding="utf-8").strip()


def _compute_current_bundle_hash(root: Path) -> str:
    bundle = load_law_bundle(repo_root=root)
    return compute_law_bundle_hash(repo_root=root, bundle=bundle)


def _compute_bundle_hash_for_ref(root: Path, ref: str) -> str:
    bundle = _read_law_bundle_from_ref(repo_root=root, ref=ref, relpath="KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json")
    file_digests = _file_digest_map_for_bundle_ref(repo_root=root, ref=ref, files=bundle.get("files", []))
    return _compute_bundle_hash_from_maps(file_digests=file_digests, laws_obj=bundle.get("laws", []))


def _find_supported_old_ref(root: Path, *, current_hash: str, pinned_hash: str, max_count: int = 16) -> Tuple[str, str]:
    for ref in _git_rev_list_first_parent(root, "HEAD", max_count):
        digest = _compute_bundle_hash_for_ref(root, ref)
        if digest == current_hash:
            continue
        if digest == pinned_hash:
            return ref, digest
    raise RuntimeError("FAIL_CLOSED: unable to locate a first-parent ancestor whose computed LAW_BUNDLE hash matches the pinned support-chain hash")


def _require_hmac_keys() -> Dict[str, str]:
    names = {"SIGNER_A": "KT_HMAC_KEY_SIGNER_A", "SIGNER_B": "KT_HMAC_KEY_SIGNER_B"}
    missing = [env_name for env_name in names.values() if not str(os.environ.get(env_name, "")).strip()]
    if missing:
        raise RuntimeError(f"FAIL_CLOSED: missing required HMAC env keys: {', '.join(missing)}")
    return names


def _sync_law_bundle_sha(root: Path, *, new_hash: str) -> Tuple[str, str]:
    sha_path = common.resolve_path(root, SHA_PATH)
    old_hash = sha_path.read_text(encoding="utf-8").strip()
    if old_hash != new_hash:
        sha_path.write_text(new_hash + "\n", encoding="utf-8", newline="\n")
    return old_hash, new_hash


def _mint_change_receipt(root: Path, *, old_ref: str, out_path: Optional[Path] = None) -> Path:
    cmd = ["python", "-m", "tools.verification.law_bundle_change_receipt", "--old-ref", old_ref]
    if out_path is not None:
        cmd.extend(["--out", out_path.as_posix()])
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str((root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()),
            str((root / "KT_PROD_CLEANROOM").resolve()),
        ]
    )
    result = subprocess.run(
        cmd,
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=True,
    )
    emitted_path = Path(result.stdout.strip().splitlines()[-1]).resolve()
    if not emitted_path.exists():
        raise RuntimeError("FAIL_CLOSED: law_bundle_change_receipt did not emit a valid path")
    return emitted_path


def _ensure_law_amendment_hmac(root: Path, *, bundle_hash: str) -> Path:
    from tools.verification.derive_fl4_seal_artifacts import _ensure_law_amendment_present  # noqa: PLC0415

    path = _ensure_law_amendment_present(repo_root=root, bundle_hash=bundle_hash, write=True, attestation_mode="HMAC")
    if path is None:
        raise RuntimeError("FAIL_CLOSED: unable to ensure HMAC law amendment for active bundle hash")
    return Path(path).resolve()


def _update_kt_cli_support_chain(root: Path, *, new_bundle_hash: str, new_change_receipt_rel: str) -> None:
    path = common.resolve_path(root, KT_CLI_PATH)
    text = path.read_text(encoding="utf-8")

    updated = re.sub(r'law_bundle_hash="[^"]{64}"', f'law_bundle_hash="{new_bundle_hash}"', text, count=1)
    if updated == text:
        raise RuntimeError("FAIL_CLOSED: unable to update kt_cli V1.law_bundle_hash pin")

    updated2 = re.sub(
        r'authoritative_reseal_receipt=\("([^"]+)"\)',
        f'authoritative_reseal_receipt=("{new_change_receipt_rel}")',
        updated,
        count=1,
    )
    if updated2 == updated:
        raise RuntimeError("FAIL_CLOSED: unable to update kt_cli V1.authoritative_reseal_receipt pin")

    path.write_text(updated2, encoding="utf-8", newline="\n")


def build_outputs(
    *,
    branch_name: str,
    branch_head_before: str,
    current_hash: str,
    old_pin_hash: str,
    old_supported_ref: str,
    old_supported_hash: str,
    change_receipt_path: Path,
    amendment_path: Path,
    kt_cli_path: Path,
) -> Dict[str, Dict[str, Any] | str]:
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_remediation_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "claim_boundary": (
            "This remediation packet repairs tranche T01 support-chain drift only. It does not change truth-engine law, "
            "does not widen package truth, and does not authorize replay on main."
        ),
        "authority_header": {
            "authoritative_branch": branch_name,
            "authoritative_branch_head_before_remediation": branch_head_before,
            "package_promotion_still_deferred": True,
            "truth_engine_law_unchanged": True,
            "replay_on_main_still_deferred_until_pr15_merge": True,
        },
        "mapping": {
            "resolution_class": "BIND_SUPERSESSION_AND_AMENDMENT_MAPPING",
            "old_supported_ref": old_supported_ref,
            "old_supported_hash": old_supported_hash,
            "old_pin_hash": old_pin_hash,
            "new_active_tree_hash": current_hash,
            "mapping_summary": (
                "Advance the support chain from the last lawful first-parent ancestor whose computed bundle hash still matched the pinned March-era support chain "
                "to the current active-tree bundle hash."
            ),
        },
        "emitted_support_artifacts": {
            "law_bundle_sha_path": common.resolve_path(repo_root(), SHA_PATH).as_posix(),
            "law_bundle_change_receipt_path": change_receipt_path.as_posix(),
            "law_amendment_path": amendment_path.as_posix(),
            "kt_cli_profile_path": kt_cli_path.as_posix(),
        },
        "non_widening_rules": [
            "Do not change truth-engine derivation law.",
            "Do not widen package truth.",
            "Do not run replay on main before PR15 merges.",
            "Do not promote archive surfaces into active truth.",
        ],
        "success_condition": {
            "active_pin_matches_current_bundle_hash": True,
            "current_hash_has_law_amendment_v2": True,
            "current_hash_has_law_bundle_change_receipt_v1": True,
            "kt_cli_v1_support_chain_updated": True,
            "next_step_is_t01_rerun": True,
        },
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_remediation_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "old_supported_ref": old_supported_ref,
        "old_supported_hash": old_supported_hash,
        "new_active_tree_hash": current_hash,
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Law Bundle And Amendment Mismatch Remediation Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{OUTCOME}`",
            f"- Old supported ref: `{old_supported_ref}`",
            f"- Old supported hash: `{old_supported_hash}`",
            f"- New active-tree hash: `{current_hash}`",
            f"- Change receipt: `{change_receipt_path.as_posix()}`",
            f"- Law amendment: `{amendment_path.as_posix()}`",
            f"- Updated support pin file: `{kt_cli_path.as_posix()}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    t01_packet_path: Path,
    t01_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T01 remediation must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T01 remediation requires a clean worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 remediation authority receipt")
    t01_packet = common.load_json_required(root, t01_packet_path, label="PR15 T01 mismatch packet")
    t01_receipt = common.load_json_required(root, t01_receipt_path, label="PR15 T01 mismatch receipt")
    common.ensure_pass(authority_packet, label="PR15 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 remediation authority receipt")
    common.ensure_pass(t01_packet, label="PR15 T01 mismatch packet")
    common.ensure_pass(t01_receipt, label="PR15 T01 mismatch receipt")

    if str(t01_receipt.get("next_lawful_move", "")).strip() != "EXECUTE_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REMEDIATION":
        raise RuntimeError("FAIL_CLOSED: tranche T01 remediation is not currently authorized by the T01 receipt")

    _require_hmac_keys()

    current_hash = _compute_current_bundle_hash(root)
    old_pin_hash = _read_sha_pin(root)
    if current_hash == old_pin_hash:
        raise RuntimeError("FAIL_CLOSED: tranche T01 remediation is not needed because LAW_BUNDLE pin already matches current active-tree hash")

    old_supported_ref, old_supported_hash = _find_supported_old_ref(root, current_hash=current_hash, pinned_hash=old_pin_hash)

    _old_pin_written, _new_pin_written = _sync_law_bundle_sha(root, new_hash=current_hash)
    change_receipt_path = _mint_change_receipt(root, old_ref=old_supported_ref)
    amendment_path = _ensure_law_amendment_hmac(root, bundle_hash=current_hash)
    change_receipt_rel = str(change_receipt_path.relative_to(root)).replace("\\", "/")
    _update_kt_cli_support_chain(root, new_bundle_hash=current_hash, new_change_receipt_rel=change_receipt_rel)

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head_before=_git_rev_parse(root, "HEAD"),
        current_hash=current_hash,
        old_pin_hash=old_pin_hash,
        old_supported_ref=old_supported_ref,
        old_supported_hash=old_supported_hash,
        change_receipt_path=change_receipt_path,
        amendment_path=amendment_path,
        kt_cli_path=common.resolve_path(root, KT_CLI_PATH),
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "lane_outcome": OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Repair tranche T01 LAW_BUNDLE support-chain drift without widening scope.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--t01-packet", default=T01_PACKET_PATH)
    parser.add_argument("--t01-receipt", default=T01_RECEIPT_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        t01_packet_path=common.resolve_path(root, args.t01_packet),
        t01_receipt_path=common.resolve_path(root, args.t01_receipt),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
