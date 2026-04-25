from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


EXIT_PASS = 0
EXIT_BOUNDED_FAIL = 1
EXIT_INPUT_INVALID = 2
EXIT_TRUST_OR_FRESHNESS_FAIL = 3

MANIFEST_NAME = "kt_public_verifier_release_manifest_v2.json"
VSA_NAME = "kt_public_verifier_vsa.json"
ADJUDICATION_NAME = "kt_child_adjudication_packet.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"missing required pack artifact: {path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid json in {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"expected object json in {path.name}")
    return data


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _write_text(path, json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def _check(check_id: str, ok: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [str(ref) for ref in refs],
    }


def build_outsider_verifier_v2_report(*, pack_root: Path) -> Tuple[Dict[str, Any], str, int]:
    manifest_path = (pack_root / MANIFEST_NAME).resolve()
    vsa_path = (pack_root / VSA_NAME).resolve()
    adjudication_path = (pack_root / ADJUDICATION_NAME).resolve()

    manifest = _load_json(manifest_path)
    vsa = _load_json(vsa_path)
    adjudication = _load_json(adjudication_path)

    package_entries = manifest.get("package_entries", [])
    if not isinstance(package_entries, list):
        raise RuntimeError("manifest package_entries must be a list")

    expected_open_blockers = list(manifest.get("expected_open_blockers", []))
    allowed_claims = list(manifest.get("allowed_claims", []))
    forbidden_claims = list(manifest.get("forbidden_claims", []))
    threshold_policy_path = (pack_root / str(manifest.get("threshold_policy_package_path", "")).strip()).resolve()
    tuf_policy_path = (pack_root / str(manifest.get("tuf_policy_package_path", "")).strip()).resolve()
    threshold_policy = _load_json(threshold_policy_path)
    tuf_policy = _load_json(tuf_policy_path)

    entry_checks: List[Dict[str, Any]] = []
    package_entries_ok = True
    for row in package_entries:
        if not isinstance(row, dict):
            package_entries_ok = False
            entry_checks.append(_check("package_entry_malformed", False, "Package entry rows must be objects.", [MANIFEST_NAME]))
            continue
        package_path = str(row.get("package_path", "")).strip()
        expected_sha = str(row.get("sha256", "")).strip()
        full_path = (pack_root / package_path).resolve()
        ok = bool(package_path) and len(expected_sha) == 64 and full_path.exists() and _sha256(full_path) == expected_sha
        entry_checks.append(
            _check(
                f"hash::{package_path or 'missing'}",
                ok,
                "Every packaged file must exist and match the manifest hash.",
                [package_path] if package_path else [MANIFEST_NAME],
            )
        )
        if not ok:
            package_entries_ok = False

    detached_root_ok = not (pack_root / ".git").exists()
    no_secret_dependency = bool(manifest.get("requires_secret_material") is False) and not list(manifest.get("required_env_vars", []))
    adjudication_ok = str(adjudication.get("status", "")).strip() == "PASS"
    vsa_ok = str(vsa.get("status", "")).strip() == "PASS"
    manifest_sha256 = _sha256(manifest_path)
    surface_id = str(manifest.get("surface_id", "")).strip()
    threshold_surface_ok = any(
        isinstance(row, dict)
        and str(row.get("surface_id", "")).strip() == surface_id
        and str(row.get("primary_manifest_sha256", "")).strip() == manifest_sha256
        for row in threshold_policy.get("accepted_verifier_surfaces", [])
    )
    tuf_surface_ok = any(
        isinstance(row, dict)
        and str(row.get("surface_id", "")).strip() == surface_id
        and str(row.get("primary_manifest_sha256", "")).strip() == manifest_sha256
        for row in tuf_policy.get("distribution_targets", [])
    )
    claim_alignment_ok = (
        allowed_claims == list(vsa.get("allowed_claims", [])) == list(adjudication.get("allowed_claims", []))
        and forbidden_claims == list(vsa.get("forbidden_claims", [])) == list(adjudication.get("forbidden_claims", []))
    )
    blockers_ok = (
        expected_open_blockers == list(vsa.get("remaining_open_blockers", []))
        == list(adjudication.get("remaining_open_blockers", []))
    )
    head_binding_ok = (
        str(manifest.get("compiled_head_commit", "")).strip()
        == str(vsa.get("compiled_head_commit", "")).strip()
        == str(adjudication.get("current_repo_head", "")).strip()
        == str(adjudication.get("subject_head_commit", "")).strip()
    )
    split_refs_ok = (
        str(vsa.get("adjudication_packet_ref", "")).strip() == ADJUDICATION_NAME
        and str(manifest.get("adjudication_packet_ref", "")).strip() == ADJUDICATION_NAME
        and str(manifest.get("vsa_ref", "")).strip() == VSA_NAME
    )

    checks = [
        _check("detached_pack_without_git", detached_root_ok, "Detached outsider pack must run without a git checkout.", []),
        _check("manifest_declares_secret_free_runtime", no_secret_dependency, "Manifest must require no secret material or hidden environment keys.", [MANIFEST_NAME]),
        _check("packaged_entries_hash_bound", package_entries_ok, "All packaged files must be hash-bound and present.", [MANIFEST_NAME]),
        _check("threshold_policy_binds_manifest_hash", threshold_surface_ok, "Threshold acceptance policy must bind the outsider verifier manifest hash.", [str(manifest.get("threshold_policy_package_path", "")).strip(), MANIFEST_NAME]),
        _check("tuf_policy_binds_manifest_hash", tuf_surface_ok, "TUF distribution policy must bind the outsider verifier manifest hash.", [str(manifest.get("tuf_policy_package_path", "")).strip(), MANIFEST_NAME]),
        _check("adjudication_packet_pass", adjudication_ok, "Adjudication packet must already have bounded PASS status.", [ADJUDICATION_NAME]),
        _check("vsa_pass", vsa_ok, "Verifier summary attestation must already have bounded PASS status.", [VSA_NAME]),
        _check("claims_align_to_adjudication", claim_alignment_ok, "Allowed and forbidden claims must align across adjudication, VSA, and manifest.", [ADJUDICATION_NAME, VSA_NAME, MANIFEST_NAME]),
        _check("remaining_open_blockers_preserved", blockers_ok, "Outsider verifier must preserve the bounded blocker set and may not erase it.", [ADJUDICATION_NAME, VSA_NAME, MANIFEST_NAME]),
        _check("current_head_binding_consistent", head_binding_ok, "Manifest, VSA, and adjudication packet must bind to the same current head.", [ADJUDICATION_NAME, VSA_NAME, MANIFEST_NAME]),
        _check("claims_compile_from_adjudication_outputs_only", split_refs_ok, "Manifest and VSA must explicitly chain claims through the adjudication packet.", [ADJUDICATION_NAME, VSA_NAME, MANIFEST_NAME]),
    ]
    checks.extend(entry_checks)

    trust_fail = not all(
        row["status"] == "PASS"
        for row in checks
        if row["check"] in {
            "manifest_declares_secret_free_runtime",
            "packaged_entries_hash_bound",
            "threshold_policy_binds_manifest_hash",
            "tuf_policy_binds_manifest_hash",
            "current_head_binding_consistent",
        }
        or row["check"].startswith("hash::")
    )
    status = "PASS" if all(row["status"] == "PASS" for row in checks) else "BLOCKED"
    exit_code = EXIT_PASS if status == "PASS" else (EXIT_TRUST_OR_FRESHNESS_FAIL if trust_fail else EXIT_BOUNDED_FAIL)

    report = {
        "schema_id": "kt.child_campaign.outsider_verifier_v2_result.v1",
        "status": status,
        "pass_verdict": (
            "SECRET_FREE_OUTSIDER_VERIFIER_V2_CONFIRMS_BOUNDED_CHILD_ASSURANCE_SURFACES"
            if status == "PASS"
            else "SECRET_FREE_OUTSIDER_VERIFIER_V2_BLOCKED"
        ),
        "compiled_head_commit": str(manifest.get("compiled_head_commit", "")).strip(),
        "bounded_scope": str(manifest.get("bounded_scope", "")).strip(),
        "allowed_claims": allowed_claims,
        "forbidden_claims": forbidden_claims,
        "remaining_open_blockers": expected_open_blockers,
        "checks": checks,
        "output_contract": {
            "machine_readable_json": str(manifest.get("machine_output_path", "")).strip(),
            "human_readable_summary": str(manifest.get("human_output_path", "")).strip(),
            "exit_codes": dict(manifest.get("exit_code_contract", {})),
        },
    }
    summary_lines = [
        f"status: {report['status']}",
        f"compiled_head_commit: {report['compiled_head_commit']}",
        f"bounded_scope: {report['bounded_scope']}",
        f"remaining_open_blockers: {', '.join(expected_open_blockers) if expected_open_blockers else 'none'}",
        f"allowed_claim_count: {len(allowed_claims)}",
        f"forbidden_claim_count: {len(forbidden_claims)}",
    ]
    return report, "\n".join(summary_lines) + "\n", exit_code


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the KT child-campaign outsider verifier v2 on a packaged public-input bundle.")
    parser.add_argument("--pack-root", default=".", help="Detached package root. Defaults to current working directory.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    pack_root = Path(str(args.pack_root)).expanduser().resolve()
    try:
        report, summary_text, exit_code = build_outsider_verifier_v2_report(pack_root=pack_root)
    except RuntimeError as exc:
        report = {
            "schema_id": "kt.child_campaign.outsider_verifier_v2_result.v1",
            "status": "INPUT_OR_ENV_INVALID",
            "error": str(exc),
        }
        summary_text = f"status: INPUT_OR_ENV_INVALID\nerror: {exc}\n"
        exit_code = EXIT_INPUT_INVALID

    manifest_path = (pack_root / MANIFEST_NAME).resolve()
    manifest = _load_json(manifest_path) if manifest_path.exists() else {}
    machine_output = str(manifest.get("machine_output_path", "outputs/outsider_result.json")).strip() or "outputs/outsider_result.json"
    human_output = str(manifest.get("human_output_path", "outputs/outsider_summary.txt")).strip() or "outputs/outsider_summary.txt"
    _write_json((pack_root / machine_output).resolve(), report)
    _write_text((pack_root / human_output).resolve(), summary_text)
    sys.stdout.write(summary_text)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
