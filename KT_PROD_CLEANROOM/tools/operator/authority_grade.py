from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import kt_cli
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError
from tools.verification.worm_write import write_text_worm


SCHEMA_ID = "kt.operator.authority_grade_report.unbound.v1"


@dataclass(frozen=True)
class LaneRequirement:
    lane_name: str
    verdict_prefixes: Sequence[str]
    delivery_required: bool


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _load_json_object(path: Path) -> Dict[str, Any]:
    obj = json.loads(_read_text(path))
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _resolve_run_dir(*, repo_root: Path, value: str) -> Path:
    p = Path(str(value)).expanduser()
    if not p.is_absolute():
        p = (repo_root / p).resolve()
    p = p.resolve()
    if not p.exists() or not p.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: explicit run dir missing: {p.as_posix()}")
    kt_cli._assert_under_runs_root(repo_root=repo_root, path=p)  # noqa: SLF001 (operator lane safety)
    return p


def _iter_run_dirs_sorted(*, runs_root: Path, name_suffix: str) -> List[Path]:
    if not runs_root.exists():
        return []
    out: List[Path] = []
    suffix = f"_{name_suffix}"
    for d in runs_root.iterdir():
        if d.is_dir() and d.name.endswith(suffix):
            out.append(d)
    out.sort(key=lambda p: p.name)
    return out


def _pick_latest(*, runs: Sequence[Path], count: int) -> List[Path]:
    if count <= 0:
        return []
    if len(runs) < count:
        return []
    return list(runs[-count:])


def _verdict_has_prefix(verdict_line: str, prefixes: Sequence[str]) -> bool:
    v = (verdict_line or "").strip()
    return any(v.startswith(p) for p in prefixes)


def _read_verdict(run_dir: Path) -> str:
    p = (run_dir / "verdict.txt").resolve()
    if not p.exists():
        return ""
    return _read_text(p).strip()


def _pick_latest_passing(
    *,
    runs_root: Path,
    name_suffix: str,
    verdict_prefixes: Sequence[str],
    count: int,
) -> List[Path]:
    candidates = _iter_run_dirs_sorted(runs_root=runs_root, name_suffix=name_suffix)
    passing = [d for d in candidates if _verdict_has_prefix(_read_verdict(d), verdict_prefixes)]
    return _pick_latest(runs=passing, count=count)


def _require_file(path: Path, *, label: str) -> None:
    if not path.exists() or not path.is_file():
        raise FL3ValidationError(f"FAIL_CLOSED: missing required file: {label}: {path.as_posix()}")


def _delivery_integrity_checks(
    *,
    repo_root: Path,
    audit_run_dir: Path,
    lane_name: str,
    lane_run_dir: Path,
    env: Dict[str, str],
) -> Dict[str, Any]:
    """
    Fail-closed delivery contract checks. Does not mutate the lane run root.
    """
    delivery_out_dir = (lane_run_dir / "delivery").resolve()
    hashes_dir = (lane_run_dir / "hashes").resolve()
    evidence_dir = (lane_run_dir / "evidence").resolve()

    delivery_manifest_path = delivery_out_dir / "delivery_manifest.json"
    _require_file(delivery_manifest_path, label=f"{lane_name}:delivery_manifest.json")
    delivery_manifest = _load_json_object(delivery_manifest_path)
    pack_dir_raw = str(delivery_manifest.get("delivery_dir", "")).strip()
    if not pack_dir_raw:
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: delivery_manifest.delivery_dir missing/empty")
    delivery_pack_dir = Path(pack_dir_raw).expanduser()
    if not delivery_pack_dir.is_absolute():
        delivery_pack_dir = (repo_root / delivery_pack_dir).resolve()
    delivery_pack_dir = delivery_pack_dir.resolve()
    if not delivery_pack_dir.exists() or not delivery_pack_dir.is_dir():
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: delivery pack dir missing: {delivery_pack_dir.as_posix()}")
    # Require delivery pack directory is inside the lane run root delivery/ folder.
    try:
        delivery_pack_dir.relative_to(delivery_out_dir)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(
            f"FAIL_CLOSED: {lane_name}: delivery pack dir escapes lane delivery/ root: {delivery_pack_dir.as_posix()}"
        ) from exc

    # Require at least one sha256 receipt file (hashes/*.sha256 or delivery/*.sha256).
    sha_files: List[Path] = []
    if hashes_dir.is_dir():
        sha_files.extend([p for p in hashes_dir.glob("*.sha256") if p.is_file()])
    if delivery_out_dir.is_dir():
        sha_files.extend([p for p in delivery_out_dir.glob("*.sha256") if p.is_file()])
    sha_files = sorted(set(sha_files), key=lambda p: p.as_posix())
    if not sha_files:
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: missing delivery sha256 receipt (*.sha256)")

    # Require replay wrappers (they are part of the client delivery contract).
    _require_file(evidence_dir / "replay.sh", label=f"{lane_name}:evidence/replay.sh")
    _require_file(evidence_dir / "replay.ps1", label=f"{lane_name}:evidence/replay.ps1")

    # Secret scan + delivery lint reports are contract-required; fail if present and not PASS.
    secret_report_path = evidence_dir / "secret_scan_report.json"
    if not secret_report_path.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: missing evidence/secret_scan_report.json")
    secret_report = _load_json_object(secret_report_path)
    if str(secret_report.get("status", "")).strip() != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: secret scan not PASS")

    lint_report_path = delivery_out_dir / "delivery_lint_report.json"
    if not lint_report_path.exists():
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: missing delivery/delivery_lint_report.json")
    lint_report = _load_json_object(lint_report_path)
    if str(lint_report.get("status", "")).strip() != "PASS":
        raise FL3ValidationError(f"FAIL_CLOSED: {lane_name}: delivery lint not PASS")

    # Re-run delivery linter CLI in the audit run dir to prove it passes in the current environment.
    safe_lane = re.sub(r"[^a-zA-Z0-9_.-]+", "_", lane_name).strip("_") or "lane"
    log_name = f"delivery_linter__{safe_lane}"
    _rc, _out, log_path = kt_cli._run_cmd(  # noqa: SLF001
        repo_root=repo_root,
        run_dir=audit_run_dir,
        name=log_name,
        cmd=[sys.executable, "-m", "tools.delivery.delivery_linter", "--delivery-dir", str(delivery_pack_dir)],
        env=env,
        allow_nonzero=False,
    )

    return {
        "delivery_manifest": str(delivery_manifest_path.as_posix()),
        "delivery_pack_dir": str(delivery_pack_dir.as_posix()),
        "sha256_receipts": [p.name for p in sha_files],
        "secret_scan_status": str(secret_report.get("status", "")).strip(),
        "delivery_lint_status": str(lint_report.get("status", "")).strip(),
        "delivery_linter_log": str(log_path.relative_to(audit_run_dir)).replace("\\", "/"),
    }


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT authority grader (minimal fail-closed).")
    ap.add_argument("--profile", default="v1", choices=["v1"])
    ap.add_argument("--run-root", default="", help="Optional explicit run root under exports/_runs (or seal tests root).")
    ap.add_argument("--status-run", default="", help="Optional explicit status run dir.")
    ap.add_argument("--readiness-run", default="", help="Optional explicit readiness-grade run dir.")
    ap.add_argument("--canonical-run", default="", help="Optional explicit certify canonical_hmac run dir.")
    ap.add_argument("--books-run", default="", help="Optional explicit books-run run dir.")
    ap.add_argument("--delta1-run", default="", help="Optional explicit delta-proof iteration #1 run dir.")
    ap.add_argument("--delta2-run", default="", help="Optional explicit delta-proof iteration #2 run dir.")
    ap.add_argument("--forge-run", default="", help="Optional explicit forge run dir.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    profile = kt_cli.V1

    env = kt_cli._base_env(repo_root=repo_root)  # noqa: SLF001
    head = kt_cli._git(repo_root=repo_root, args=["rev-parse", "HEAD"])  # noqa: SLF001

    run_dir = kt_cli._mk_run_dir(  # noqa: SLF001
        repo_root=repo_root,
        cmd_name="authority-grade",
        requested_run_root=(str(args.run_root).strip() or None),
    )
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)

    runs_root = (kt_cli._runs_root(repo_root) / "KT_OPERATOR").resolve()  # noqa: SLF001

    def resolve_or_latest(name_suffix: str, explicit: str, verdict_prefixes: Sequence[str]) -> Optional[Path]:
        if str(explicit).strip():
            return _resolve_run_dir(repo_root=repo_root, value=str(explicit))
        picked = _pick_latest_passing(runs_root=runs_root, name_suffix=name_suffix, verdict_prefixes=verdict_prefixes, count=1)
        return picked[0] if picked else None

    # Resolve delta runs: if explicit not provided, pick two most recent distinct delta-proof runs.
    def resolve_delta_pair(explicit1: str, explicit2: str) -> tuple[Optional[Path], Optional[Path]]:
        if str(explicit1).strip() and str(explicit2).strip():
            return (
                _resolve_run_dir(repo_root=repo_root, value=str(explicit1)),
                _resolve_run_dir(repo_root=repo_root, value=str(explicit2)),
            )
        if str(explicit1).strip() and not str(explicit2).strip():
            first = _resolve_run_dir(repo_root=repo_root, value=str(explicit1))
            candidates = [
                r
                for r in _iter_run_dirs_sorted(runs_root=runs_root, name_suffix="delta-proof")
                if r != first and _verdict_has_prefix(_read_verdict(r), ["KT_DELTA_PROOF_PASS"])
            ]
            picked = _pick_latest(runs=candidates, count=1)
            return (first, picked[0] if picked else None)
        if not str(explicit1).strip() and str(explicit2).strip():
            second = _resolve_run_dir(repo_root=repo_root, value=str(explicit2))
            candidates = [
                r
                for r in _iter_run_dirs_sorted(runs_root=runs_root, name_suffix="delta-proof")
                if r != second and _verdict_has_prefix(_read_verdict(r), ["KT_DELTA_PROOF_PASS"])
            ]
            picked = _pick_latest(runs=candidates, count=1)
            return (picked[0] if picked else None, second)
        picked_two = _pick_latest_passing(
            runs_root=runs_root, name_suffix="delta-proof", verdict_prefixes=["KT_DELTA_PROOF_PASS"], count=2
        )
        if len(picked_two) == 2:
            return (picked_two[0], picked_two[1])
        if len(picked_two) == 1:
            return (picked_two[0], None)
        return (None, None)

    status_run = resolve_or_latest("status", str(args.status_run), ["KT_STATUS_PASS"])
    readiness_run = resolve_or_latest("readiness-grade", str(args.readiness_run), ["KT_READINESS_PASS"])
    canonical_run = resolve_or_latest("certify", str(args.canonical_run), ["KT_CERTIFY_PASS cmd=certify lane=canonical_hmac"])
    books_run = resolve_or_latest("books-run", str(args.books_run), ["KT_BOOKS_SUITE_PASS"])
    delta1_run, delta2_run = resolve_delta_pair(str(args.delta1_run), str(args.delta2_run))
    forge_run = resolve_or_latest("forge", str(args.forge_run), ["KT_FORGE_PASS"])

    lane_requirements: List[tuple[LaneRequirement, Optional[Path]]] = [
        (LaneRequirement("S0_status", ["KT_STATUS_PASS"], delivery_required=False), status_run),
        (LaneRequirement("S0_readiness", ["KT_READINESS_PASS"], delivery_required=False), readiness_run),
        (
            LaneRequirement(
                "S0_canonical_hmac",
                ["KT_CERTIFY_PASS cmd=certify lane=canonical_hmac"],
                delivery_required=True,
            ),
            canonical_run,
        ),
        (LaneRequirement("S2_books", ["KT_BOOKS_SUITE_PASS"], delivery_required=True), books_run),
        (LaneRequirement("S5_delta_proof_1", ["KT_DELTA_PROOF_PASS"], delivery_required=True), delta1_run),
        (LaneRequirement("S5_delta_proof_2", ["KT_DELTA_PROOF_PASS"], delivery_required=True), delta2_run),
        (LaneRequirement("S7_forge", ["KT_FORGE_PASS"], delivery_required=True), forge_run),
    ]

    blockers: List[str] = []
    lanes: Dict[str, Any] = {}
    integrity_failures = 0

    for req, lane_dir in lane_requirements:
        if lane_dir is None:
            blockers.append(f"MISSING_RUN:{req.lane_name}")
            continue

        verdict_path = (lane_dir / "verdict.txt").resolve()
        if not verdict_path.exists():
            blockers.append(f"MISSING_VERDICT:{req.lane_name}:{lane_dir.as_posix()}")
            continue
        verdict = _read_text(verdict_path).strip()
        if not _verdict_has_prefix(verdict, req.verdict_prefixes):
            blockers.append(f"BAD_VERDICT:{req.lane_name}:{verdict}")
            continue

        lane_entry: Dict[str, Any] = {"run_dir": lane_dir.as_posix(), "verdict": verdict}

        if req.delivery_required:
            try:
                lane_entry["delivery_integrity"] = _delivery_integrity_checks(
                    repo_root=repo_root,
                    audit_run_dir=run_dir,
                    lane_name=req.lane_name,
                    lane_run_dir=lane_dir,
                    env=env,
                )
            except Exception as exc:
                integrity_failures += 1
                blockers.append(f"DELIVERY_INTEGRITY_FAIL:{req.lane_name}:{exc}")
                lane_entry["delivery_integrity"] = {"pass": False, "error": str(exc)}
        lanes[req.lane_name] = lane_entry

    grade = "A" if not blockers else "B"
    status = "PASS" if grade == "A" else "HOLD"

    report = {
        "schema_id": SCHEMA_ID,
        "created_utc": _utc_now_iso_z(),
        "profile": profile.name,
        "head": head,
        "status": status,
        "grade": grade,
        "integrity_failures": int(integrity_failures),
        "blockers": blockers,
        "lanes": lanes,
    }
    _write_json_worm(path=(run_dir / "reports" / "authority_grade.json").resolve(), obj=report, label="authority_grade.json")

    verdict_line = (
        f"KT_AUTHORITY_GRADE_{grade} status={status} blockers={len(blockers)} integrity_failures={int(integrity_failures)} "
        f"head={head} run_id={run_dir.name}"
    )
    write_text_worm(path=(run_dir / "verdict.txt").resolve(), text=verdict_line + "\n", label="verdict.txt")
    write_text_worm(
        path=(run_dir / "reports" / "one_line_verdict.txt").resolve(),
        text=verdict_line + "\n",
        label="one_line_verdict.txt",
    )

    print(verdict_line)
    return 0 if grade == "A" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        print(str(exc))
        raise SystemExit(2)
