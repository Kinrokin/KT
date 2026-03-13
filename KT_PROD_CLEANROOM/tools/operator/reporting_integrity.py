from __future__ import annotations

import argparse
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.authority_convergence_validate import build_authority_convergence_report
from tools.operator.titanium_common import file_sha256, load_json, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import path_ref


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_REMOTE = "origin"
DEFAULT_LEDGER_BRANCH = "kt_truth_ledger"

STATUS_PASS = "PASS"
STATUS_FAIL_CLOSED = "FAIL_CLOSED"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@dataclass(frozen=True)
class RemoteBranchFact:
    remote: str
    branch: str
    reachable: bool
    published: bool
    head_sha: str
    raw: str
    error: str


def _ls_remote_head(*, root: Path, remote: str, branch: str) -> RemoteBranchFact:
    try:
        raw = _git(root, "ls-remote", "--heads", remote, branch)
    except Exception as exc:  # noqa: BLE001
        return RemoteBranchFact(
            remote=remote,
            branch=branch,
            reachable=False,
            published=False,
            head_sha="",
            raw="",
            error=str(exc),
        )
    raw = raw.strip()
    if not raw:
        return RemoteBranchFact(
            remote=remote,
            branch=branch,
            reachable=True,
            published=False,
            head_sha="",
            raw="",
            error="",
        )
    # Example: "<sha>\trefs/heads/<branch>"
    line = raw.splitlines()[0].strip()
    head_sha = line.split()[0].strip() if line else ""
    return RemoteBranchFact(
        remote=remote,
        branch=branch,
        reachable=True,
        published=True,
        head_sha=head_sha,
        raw=raw,
        error="",
    )


def _load_required(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"FAIL_CLOSED: unable to determine git HEAD: {exc}") from exc


def _nested_get(obj: Dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _receipt_head(obj: Dict[str, Any]) -> str:
    for key in ("validated_head_sha", "pinned_head_sha", "head_sha", "head"):
        value = str(obj.get(key, "")).strip()
        if value:
            return value
    observed = obj.get("observed")
    if isinstance(observed, dict):
        value = str(observed.get("git_head", "")).strip()
        if value:
            return value
    return ""


def build_published_head_self_convergence_receipt(
    *,
    root: Path,
    remote_fact: RemoteBranchFact,
    validated_head_sha: str,
) -> Dict[str, Any]:
    # This receipt is intentionally narrow: it reports publication reachability
    # (remote branch existence) but does not attempt to assert published-head authority.
    blockers: List[str] = []
    if not remote_fact.published:
        blockers.append("LEDGER_BRANCH_LOCAL_ONLY")
    blockers.append("PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED")

    # "Main live truth purged" is treated as a documentary-shape check, not a resolver claim.
    main_pointer_path = (root / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current" / "current_pointer.json").resolve()
    main_pointer = load_json(main_pointer_path) if main_pointer_path.exists() else {}
    main_live_truth_purged = bool(main_pointer.get("live_authority") is False) or bool(main_pointer.get("LIVE_TRUTH_ALLOWED") is False)

    proof_class = "LOCAL_LEDGER_SELF_CONVERGENCE_ONLY"
    status = proof_class
    return {
        "schema_id": "kt.operator.published_head_self_convergence_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "proof_class": proof_class,
        "validated_head_sha": validated_head_sha,
        "published_head_authority_claimed": False,
        "ledger_branch": remote_fact.branch,
        "ledger_branch_published": bool(remote_fact.published),
        "ledger_branch_head_sha": str(remote_fact.head_sha).strip(),
        "ledger_remote": remote_fact.remote,
        "ledger_remote_reachable": bool(remote_fact.reachable),
        "ledger_remote_error": str(remote_fact.error).strip(),
        "blockers": blockers,
        "main_live_truth_purged": bool(main_live_truth_purged),
    }


def _validate_publication_reporting(
    *,
    current_git_head: str,
    remote_fact: RemoteBranchFact,
    authority_convergence: Dict[str, Any],
    published_head_self_convergence: Dict[str, Any],
) -> Tuple[List[str], List[str]]:
    contradictions: List[str] = []
    stale: List[str] = []

    if not remote_fact.reachable:
        stale.append("ledger_remote_unreachable")

    auth_head = str(_nested_get(authority_convergence, "observed", "git_head") or "").strip() or _receipt_head(authority_convergence)
    if not auth_head:
        stale.append("authority_convergence_receipt_missing_head_stamp")
    if auth_head and auth_head != current_git_head:
        stale.append("authority_convergence_receipt_head_mismatch")

    ph_head = _receipt_head(published_head_self_convergence)
    if not ph_head:
        stale.append("published_head_self_convergence_receipt_missing_head_stamp")
    if ph_head and ph_head != current_git_head:
        stale.append("published_head_self_convergence_receipt_head_mismatch")

    auth_published = bool(_nested_get(authority_convergence, "observed", "ledger_branch_published"))
    ph_published = bool(published_head_self_convergence.get("ledger_branch_published"))

    if auth_published != remote_fact.published:
        contradictions.append("authority_convergence_receipt_ledger_branch_published_mismatch")
    if ph_published != remote_fact.published:
        contradictions.append("published_head_self_convergence_receipt_ledger_branch_published_mismatch")
    if auth_published != ph_published:
        contradictions.append("cross_receipt_ledger_branch_published_disagreement")

    ph_ledger_head = str(published_head_self_convergence.get("ledger_branch_head_sha", "")).strip()
    if remote_fact.published and remote_fact.head_sha and not ph_ledger_head:
        stale.append("published_head_self_convergence_receipt_missing_ledger_branch_head_sha")
    if remote_fact.published and remote_fact.head_sha and ph_ledger_head and ph_ledger_head != remote_fact.head_sha:
        contradictions.append("published_head_self_convergence_receipt_ledger_branch_head_sha_mismatch")

    return contradictions, stale


def verify_reporting_integrity(
    *,
    root: Path,
    remote: str = DEFAULT_REMOTE,
    ledger_branch: str = DEFAULT_LEDGER_BRANCH,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
) -> Dict[str, Any]:
    reports_root = (root / report_root_rel).resolve()
    current_git_head = _git_head(root)
    remote_fact = _ls_remote_head(root=root, remote=remote, branch=ledger_branch)

    authority_path = reports_root / "authority_convergence_receipt.json"
    published_head_path = reports_root / "published_head_self_convergence_receipt.json"
    authority_convergence = _load_required(authority_path)
    published_head_self = _load_required(published_head_path)

    contradictions, stale = _validate_publication_reporting(
        current_git_head=current_git_head,
        remote_fact=remote_fact,
        authority_convergence=authority_convergence,
        published_head_self_convergence=published_head_self,
    )

    status = STATUS_PASS if not contradictions and not stale else STATUS_FAIL_CLOSED
    return {
        "schema_id": "kt.operator.reporting_integrity_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_git_head": current_git_head,
        "ledger_remote": remote_fact.remote,
        "ledger_branch": remote_fact.branch,
        "ledger_remote_reachable": bool(remote_fact.reachable),
        "ledger_branch_published": bool(remote_fact.published),
        "ledger_branch_head_sha": str(remote_fact.head_sha).strip(),
        "contradictions": contradictions,
        "stale_findings": stale,
        "targets": {
            "authority_convergence_receipt": path_ref(root=root, path=authority_path),
            "published_head_self_convergence_receipt": path_ref(root=root, path=published_head_path),
        },
    }


def repair_reporting_integrity(
    *,
    root: Path,
    remote: str = DEFAULT_REMOTE,
    ledger_branch: str = DEFAULT_LEDGER_BRANCH,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
    out_receipt_rel: str = f"{DEFAULT_REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json",
) -> Dict[str, Any]:
    reports_root = (root / report_root_rel).resolve()
    current_git_head = _git_head(root)
    remote_fact = _ls_remote_head(root=root, remote=remote, branch=ledger_branch)

    authority_path = reports_root / "authority_convergence_receipt.json"
    published_head_path = reports_root / "published_head_self_convergence_receipt.json"

    before: Dict[str, str] = {}
    for path in (authority_path, published_head_path):
        if path.exists():
            before[path_ref(root=root, path=path)] = file_sha256(path)

    # Recompute the published-head self-convergence receipt directly from remote facts.
    ph_receipt = build_published_head_self_convergence_receipt(
        root=root,
        remote_fact=remote_fact,
        validated_head_sha=current_git_head,
    )
    write_json_stable(published_head_path, ph_receipt)

    # Recompute the authority convergence receipt via its canonical builder.
    convergence = build_authority_convergence_report(root=root)
    write_json_stable(authority_path, convergence)

    after: Dict[str, str] = {}
    for path in (authority_path, published_head_path):
        if path.exists():
            after[path_ref(root=root, path=path)] = file_sha256(path)

    verification_after = verify_reporting_integrity(
        root=root,
        remote=remote,
        ledger_branch=ledger_branch,
        report_root_rel=report_root_rel,
    )
    ok = verification_after["status"] == STATUS_PASS

    repair_receipt = {
        "schema_id": "kt.operator.reporting_integrity_repair_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": STATUS_PASS if ok else "FAIL",
        "current_git_head": current_git_head,
        "remote_fact": {
            "remote": remote_fact.remote,
            "branch": remote_fact.branch,
            "reachable": bool(remote_fact.reachable),
            "published": bool(remote_fact.published),
            "head_sha": str(remote_fact.head_sha).strip(),
            "error": str(remote_fact.error).strip(),
        },
        "touched": [
            {
                "path": path,
                "before_sha256": before.get(path, ""),
                "after_sha256": after.get(path, ""),
                "changed": bool(before.get(path, "") and after.get(path, "") and before.get(path, "") != after.get(path, "")),
            }
            for path in sorted(set(before) | set(after))
        ],
        "verification_after": verification_after,
        "semantic_ceiling": {
            "published_head_authority_claimed": False,
            "h1_allowed": False,
        },
    }
    out_path = (root / out_receipt_rel).resolve()
    write_json_stable(out_path, repair_receipt)
    return repair_receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Repair and verify publication/reporting integrity for ledger publication facts.")
    ap.add_argument("--mode", choices=("verify", "repair"), default="verify")
    ap.add_argument("--remote", default=DEFAULT_REMOTE)
    ap.add_argument("--ledger-branch", default=DEFAULT_LEDGER_BRANCH)
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    ap.add_argument("--out-receipt", default=f"{DEFAULT_REPORT_ROOT_REL}/reporting_integrity_repair_receipt.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(__file__).resolve()
    # Resolve to repo root by walking up until KT_PROD_CLEANROOM is present.
    while root != root.parent and not (root / "KT_PROD_CLEANROOM").exists():
        root = root.parent
    if not (root / "KT_PROD_CLEANROOM").exists():
        raise SystemExit("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM)")

    if str(args.mode).strip() == "repair":
        receipt = repair_reporting_integrity(
            root=root,
            remote=str(args.remote).strip(),
            ledger_branch=str(args.ledger_branch).strip(),
            report_root_rel=str(args.report_root).strip(),
            out_receipt_rel=str(args.out_receipt).strip(),
        )
        print(receipt["status"])
        return 0 if receipt["status"] == STATUS_PASS else 2

    receipt = verify_reporting_integrity(
        root=root,
        remote=str(args.remote).strip(),
        ledger_branch=str(args.ledger_branch).strip(),
        report_root_rel=str(args.report_root).strip(),
    )
    print(receipt["status"])
    return 0 if receipt["status"] == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
