from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import resolve_truth_head_context


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
OUTPUT_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_friendly_host_handoff_pack.json"
ANCHOR_REL = f"{GOVERNANCE_ROOT_REL}/kt_unified_convergence_max_power_campaign_v2_1_1_anchor.json"
PREP_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_trust_prep_receipt.json"
VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
EXTERNAL_REPRO_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_receipt.json"
EXTERNAL_REPRO_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_external_reproduction_matrix.json"
OUTSIDER_PATH_REL = f"{REPORT_ROOT_REL}/kt_outsider_path_receipt.json"
REPLAY_RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"
CANONICAL_SCOPE_MANIFEST_REL = f"{GOVERNANCE_ROOT_REL}/canonical_scope_manifest.json"
DEPENDENCY_INTEGRITY_CONTRACT_REL = f"{GOVERNANCE_ROOT_REL}/dependency_integrity_contract.json"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_lines(root: Path) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True)
    return [line.rstrip("\n") for line in output.splitlines() if line.strip()]


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


def _subject_head(payload: Dict[str, Any]) -> str:
    for key in ("subject_head_commit", "compiled_head_commit", "current_repo_head", "evidence_head_commit"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _binding_row(*, surface_id: str, rel: str, payload: Dict[str, Any], current_head: str) -> Dict[str, Any]:
    subject_head = _subject_head(payload)
    if not subject_head:
        binding = "HEAD_UNDECLARED_PREP_ONLY"
    elif subject_head == current_head:
        binding = "CURRENT_HEAD_BOUND"
    else:
        binding = "CARRIED_FORWARD_PREP_ONLY"
    return {
        "surface_id": surface_id,
        "ref": rel,
        "subject_head_commit": subject_head,
        "head_binding_status": binding,
    }


def _publication_carrier_only_delta(*, root: Path, base_head: str, carrier_head: str) -> bool:
    base = str(base_head).strip()
    carrier = str(carrier_head).strip()
    if not base or not carrier or base == carrier:
        return False
    head_context = resolve_truth_head_context(root=root, live_head=carrier, dirty_lines=[])
    patterns = [str(item).strip() for item in head_context.get("publication_carrier_surface_patterns", []) if str(item).strip()]
    canonical_scope_path = (root / CANONICAL_SCOPE_MANIFEST_REL).resolve()
    if canonical_scope_path.exists():
        canonical_scope = load_json(canonical_scope_path)
        patterns.extend(
            str(item).strip()
            for item in canonical_scope.get("toolchain_proving_surfaces", [])
            if str(item).strip()
        )
    dependency_contract_path = (root / DEPENDENCY_INTEGRITY_CONTRACT_REL).resolve()
    if dependency_contract_path.exists():
        dependency_contract = load_json(dependency_contract_path)
        for item in dependency_contract.get("scope_roots", []):
            normalized = str(item).strip().replace("\\", "/")
            if not normalized.startswith("KT_PROD_CLEANROOM/tests/operator"):
                continue
            patterns.append(f"{normalized.rstrip('/')}/**")
    patterns = list(dict.fromkeys(patterns))
    if not patterns:
        return False
    changed = _git(root, "diff", "--name-only", base, carrier)
    changed_paths = [line.strip().replace("\\", "/") for line in changed.splitlines() if line.strip()]
    if not changed_paths:
        return False
    return all(any(Path(path).match(pattern) for pattern in patterns) for path in changed_paths)


def _current_head_binding_status(
    *,
    root: Path,
    subject_head: str,
    validated_subject_head: str,
    current_head: str,
) -> Dict[str, str]:
    subject = str(subject_head).strip()
    validated = str(validated_subject_head).strip()
    current = str(current_head).strip()
    if not subject:
        return {
            "head_binding_status": "HEAD_UNDECLARED_PREP_ONLY",
            "head_binding_mode": "HEAD_UNDECLARED",
        }
    if subject == validated:
        return {
            "head_binding_status": "CURRENT_HEAD_BOUND",
            "head_binding_mode": "VALIDATED_SUBJECT_EXACT",
        }
    if subject == current:
        return {
            "head_binding_status": "CURRENT_HEAD_BOUND",
            "head_binding_mode": "CURRENT_HEAD_EXACT",
        }
    if _publication_carrier_only_delta(root=root, base_head=subject, carrier_head=current):
        return {
            "head_binding_status": "CURRENT_HEAD_BOUND",
            "head_binding_mode": "PUBLICATION_CARRIER_ONLY_DELTA",
        }
    return {
        "head_binding_status": "CARRIED_FORWARD_PREP_ONLY",
        "head_binding_mode": "CARRIED_FORWARD_PREP_ONLY",
    }


def build_post_wave5_c006_friendly_host_handoff_pack(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    head_context = resolve_truth_head_context(root=root, live_head=current_head, dirty_lines=_git_status_lines(root))
    validated_subject_head = str(head_context.get("validated_subject_head_sha", "")).strip() or current_head
    publication_carrier_head = str(head_context.get("publication_carrier_head_sha", "")).strip()
    head_relation = str(head_context.get("head_relation", "")).strip() or "HEAD_IS_SUBJECT"
    anchor = _load_required(root, ANCHOR_REL)
    prep = _load_required(root, PREP_REL)
    verifier_truth = _load_required(root, VERIFIER_TRUTH_REL)
    external_repro = _load_required(root, EXTERNAL_REPRO_RECEIPT_REL)
    outsider_path = _load_required(root, OUTSIDER_PATH_REL)
    verifier_truth_binding = _current_head_binding_status(
        root=root,
        subject_head=str(verifier_truth.get("compiled_head_commit", "")).strip(),
        validated_subject_head=validated_subject_head,
        current_head=current_head,
    )

    replay_recipe_path = (root / REPLAY_RECIPE_REL).resolve()
    external_matrix_path = (root / EXTERNAL_REPRO_MATRIX_REL).resolve()

    bindings = [
        {
            "surface_id": "v2_1_1_anchor",
            "ref": ANCHOR_REL,
            "subject_head_commit": current_head,
            "head_binding_status": "CURRENT_HEAD_ACTIVE_ANCHOR",
        },
        {
            "surface_id": "wave5_verifier_truth",
            "ref": VERIFIER_TRUTH_REL,
            "subject_head_commit": str(verifier_truth.get("compiled_head_commit", "")).strip(),
            "head_binding_status": verifier_truth_binding["head_binding_status"],
            "head_binding_mode": verifier_truth_binding["head_binding_mode"],
        },
        _binding_row(
            surface_id="external_reproduction_receipt",
            rel=EXTERNAL_REPRO_RECEIPT_REL,
            payload=external_repro,
            current_head=current_head,
        ),
        _binding_row(
            surface_id="outsider_path_receipt",
            rel=OUTSIDER_PATH_REL,
            payload=outsider_path,
            current_head=current_head,
        ),
    ]

    external_scope = str(external_repro.get("summary", {}).get("stronger_claim_not_made", "")).strip().lower()
    checks = [
        _check(
            "anchor_limits_authoritative_scope_to_c006",
            str(anchor.get("current_authorized_scope", {}).get("authoritative_track", "")).strip() == "C006 only",
            "The current active anchor must keep the authoritative lane narrowed to C006 only.",
            [ANCHOR_REL],
        ),
        _check(
            "post_wave5_c006_prep_receipt_still_passes",
            str(prep.get("status", "")).strip() == "PASS"
            and str(prep.get("current_externality_ceiling", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "The post-Wave5 C006 prep receipt must remain PASS and keep the ceiling at E1.",
            [PREP_REL],
        ),
        _check(
            "wave5_verifier_truth_remains_e1_only",
            str(verifier_truth.get("status", "")).strip() == "PASS"
            and str(verifier_truth.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
            "The current-head verifier truth surface must remain explicitly bounded at E1.",
            [VERIFIER_TRUTH_REL],
        ),
        _check(
            "external_reproduction_receipt_remains_bounded_and_present",
            str(external_repro.get("status", "")).strip() == "PASS"
            and "does not claim cross-host" in external_scope,
            "The carried-forward external reproduction receipt must remain present and explicitly bounded below cross-host proof.",
            [EXTERNAL_REPRO_RECEIPT_REL],
        ),
        _check(
            "outsider_path_remains_secret_free_and_bounded",
            str(outsider_path.get("status", "")).strip() == "PASS"
            and str(outsider_path.get("hidden_secret_dependency", "")).strip() == "ABSENT",
            "The outsider verifier path must remain secret-free while not being overread as current-head external capability proof.",
            [OUTSIDER_PATH_REL],
        ),
        _check(
            "friendly_host_recipe_inputs_exist",
            replay_recipe_path.exists() and external_matrix_path.exists(),
            "A second-host handoff pack requires the replay recipe and clean-environment reproduction matrix to exist.",
            [REPLAY_RECIPE_REL, EXTERNAL_REPRO_MATRIX_REL],
        ),
    ]

    failures = [str(row["check"]) for row in checks if str(row.get("status", "")).strip() != "PASS"]
    status = "PASS" if not failures else "FAIL"

    return {
        "schema_id": "kt.operator.post_wave5.c006_friendly_host_handoff_pack.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_repo_head": current_head,
        "validated_subject_head_sha": validated_subject_head,
        "publication_carrier_head_sha": publication_carrier_head,
        "head_relation": head_relation,
        "c006_status": "OPEN_READY_FOR_E2_FRIENDLY_HOST_HANDOFF_NOT_PROMOTED" if status == "PASS" else "BLOCKED",
        "blocker_delta": "C006_NARROWED_TO_EXPLICIT_E2_FRIENDLY_HOST_HANDOFF_AWAITING_SECOND_HOST"
        if status == "PASS"
        else "C006_FRIENDLY_HOST_HANDOFF_BLOCKED",
        "current_externality_ceiling": "E1_SAME_HOST_DETACHED_REPLAY",
        "required_next_environment": "E_CROSS_HOST_FRIENDLY",
        "authoritative_track": str(anchor.get("current_authorized_scope", {}).get("authoritative_track", "")).strip(),
        "handoff_target": "Fresh current-head detached verifier replay on a different friendly host with no hidden secret dependency and explicit returned receipts.",
        "friendly_host_steps": [
            "Copy the detached verifier package and replay instructions into a different friendly host environment.",
            "Run the detached verifier entrypoint exactly as declared by the replay recipe without adding hidden secret material.",
            "Capture the emitted machine-readable result, runtime receipt, and host environment metadata.",
            "Compare the second-host result to the current-head verifier truth boundary and preserve any mismatch as a bounded failure row.",
            "Only raise externality if the fresh second-host result is successful and receipted.",
        ],
        "handoff_inputs": {
            "anchor_ref": ANCHOR_REL,
            "c006_prep_receipt_ref": PREP_REL,
            "verifier_truth_surface_ref": VERIFIER_TRUTH_REL,
            "external_reproduction_receipt_ref": EXTERNAL_REPRO_RECEIPT_REL,
            "external_reproduction_matrix_ref": EXTERNAL_REPRO_MATRIX_REL,
            "outsider_path_receipt_ref": OUTSIDER_PATH_REL,
            "replay_recipe_ref": REPLAY_RECIPE_REL,
        },
        "support_surface_bindings": bindings,
        "exact_remaining_forbidden_claims": [
            "Do not claim E2 cross-host friendly replay until a fresh current-head second-host verifier run succeeds with returned receipts.",
            "Do not narrate carried-forward external reproduction or outsider-path surfaces as direct proof about the current head.",
            "Do not narrate verifier-only second-host success as broad current-head runtime capability without a separately scoped runtime proof.",
            "Do not widen into router, product, procurement, or comparative claims from this handoff pack.",
        ],
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit a post-Wave5 C006 friendly-host handoff pack without promoting externality.")
    parser.add_argument("--output", default=OUTPUT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()

    receipt = build_post_wave5_c006_friendly_host_handoff_pack(root=root)
    write_json_stable(output_path, receipt)
    print(json.dumps({"status": receipt["status"], "blocker_delta": receipt["blocker_delta"]}, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
