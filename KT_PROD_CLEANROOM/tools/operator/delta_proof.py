from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator import kt_cli
from tools.verification.worm_write import write_text_worm


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=_canonical_json(obj) + "\n", label=label)


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _resolve_run_dir(*, repo_root: Path, value: str) -> Path:
    p = Path(str(value)).expanduser()
    if not p.is_absolute():
        p = (repo_root / p).resolve()
    p = p.resolve()
    if not p.exists() or not p.is_dir():
        raise RuntimeError(f"FAIL_CLOSED: run dir missing: {p.as_posix()}")
    kt_cli._assert_under_runs_root(repo_root=repo_root, path=p)  # noqa: SLF001 (operator lane safety)
    return p


def _load_taxonomy(run_dir: Path) -> Dict[str, Any]:
    path = (run_dir / "reports" / "failure_taxonomy.json").resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing failure_taxonomy.json in run: {run_dir.as_posix()}")
    return _load_json(path)


def _lane_integrity(run_dir: Path) -> Tuple[str, str]:
    secret_path = (run_dir / "evidence" / "secret_scan_report.json").resolve()
    lint_path = (run_dir / "delivery" / "delivery_lint_report.json").resolve()
    secret = _load_json(secret_path) if secret_path.exists() else {}
    lint = _load_json(lint_path) if lint_path.exists() else {}
    secret_status = str(secret.get("status", "")).strip() or ("MISSING" if not secret_path.exists() else "UNKNOWN")
    lint_status = str(lint.get("status", "")).strip() or ("MISSING" if not lint_path.exists() else "UNKNOWN")
    return secret_status, lint_status


def _counts_by_severity(tax: Dict[str, Any]) -> Dict[str, int]:
    raw = tax.get("counts_by_severity")
    out: Dict[str, int] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(k, str):
                try:
                    out[k] = int(v)  # type: ignore[arg-type]
                except Exception:
                    out[k] = 0
    return out


def _counts_by_class(tax: Dict[str, Any]) -> Dict[str, int]:
    raw = tax.get("counts_by_class")
    out: Dict[str, int] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(k, str):
                try:
                    out[k] = int(v)  # type: ignore[arg-type]
                except Exception:
                    out[k] = 0
    return out


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="KT delta-proof lane (baseline vs post run comparison; WORM evidence + delivery).")
    ap.add_argument("--profile", default="v1", choices=["v1"])
    ap.add_argument("--run-root", default="", help="Optional explicit run root under KT_PROD_CLEANROOM/exports/_runs.")
    ap.add_argument("--allow-dirty", action="store_true", help="Allow dirty worktree (practice only).")
    ap.add_argument("--baseline-run", required=True, help="Baseline run directory under exports/_runs (or seal tests root).")
    ap.add_argument("--post-run", required=True, help="Post-mitigation run directory under exports/_runs (or seal tests root).")
    ap.add_argument("--patch-card", default="", help="Optional patch card JSON (path or inline JSON).")
    ap.add_argument("--allow-mismatch", action="store_true", help="Allow pack/seed mismatches (default: fail-closed).")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    profile = kt_cli.V1

    run_dir = kt_cli._mk_run_dir(  # noqa: SLF001
        repo_root=repo_root, cmd_name="delta-proof", requested_run_root=str(args.run_root).strip() or None
    )
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)

    head = kt_cli._git(repo_root=repo_root, args=["rev-parse", "HEAD"])  # noqa: SLF001
    git_status = kt_cli._git(repo_root=repo_root, args=["status", "--porcelain=v1"])  # noqa: SLF001
    _write_json_worm(
        path=(run_dir / "env_keys.json").resolve(),
        obj={"hmac_keys": kt_cli._keys_presence_len(), "allow_dirty": bool(args.allow_dirty)},  # noqa: SLF001
        label="env_keys.json",
    )
    write_text_worm(path=(run_dir / "git_head.txt").resolve(), text=head + "\n", label="git_head.txt")
    write_text_worm(path=(run_dir / "git_status.txt").resolve(), text=git_status + "\n", label="git_status.txt")
    if not bool(args.allow_dirty) and git_status.strip():
        raise RuntimeError("FAIL_CLOSED: repo is not clean (git status --porcelain=v1 non-empty)")

    baseline = _resolve_run_dir(repo_root=repo_root, value=str(args.baseline_run))
    post = _resolve_run_dir(repo_root=repo_root, value=str(args.post_run))

    baseline_tax = _load_taxonomy(baseline)
    post_tax = _load_taxonomy(post)

    baseline_secret, baseline_lint = _lane_integrity(baseline)
    post_secret, post_lint = _lane_integrity(post)

    # Optional patch card (record only).
    patch_card: Optional[Dict[str, Any]] = None
    raw_patch = str(args.patch_card).strip()
    if raw_patch:
        p = Path(raw_patch).expanduser()
        if p.exists():
            if not p.is_absolute():
                p = (repo_root / p).resolve()
            patch_card = _load_json(p)
        else:
            obj = json.loads(raw_patch)
            if not isinstance(obj, dict):
                raise RuntimeError("FAIL_CLOSED: patch-card must be JSON object")
            patch_card = obj

    # Lock checks (best-effort) from red_assault_summary if present.
    def ra_facts(run: Path) -> Dict[str, Any]:
        s = (run / "reports" / "red_assault_summary.json").resolve()
        if not s.exists():
            return {}
        obj = _load_json(s)
        return {
            "pack_id": str(obj.get("pack_id", "")).strip(),
            "pressure_level": str(obj.get("pressure_level", "")).strip(),
            "seed": obj.get("seed"),
            "probe_pack_id": str(obj.get("probe_pack_id", "")).strip(),
            "probe_payload_bundle_sha256": str(obj.get("probe_payload_bundle_sha256", "")).strip(),
            "probe_engine": str(obj.get("probe_engine", "")).strip(),
        }

    bfacts = ra_facts(baseline)
    pfacts = ra_facts(post)
    mismatches: List[str] = []
    for k in ("pack_id", "pressure_level", "seed"):
        if bfacts.get(k) and pfacts.get(k) and bfacts.get(k) != pfacts.get(k):
            mismatches.append(f"{k}:{bfacts.get(k)}!={pfacts.get(k)}")
    for k in ("probe_pack_id", "probe_payload_bundle_sha256", "probe_engine"):
        b = bfacts.get(k)
        p = pfacts.get(k)
        if (b or p) and b != p:
            mismatches.append(f"{k}:{b}!={p}")

    if mismatches and not bool(args.allow_mismatch):
        raise RuntimeError("FAIL_CLOSED: baseline/post mismatch (use --allow-mismatch to override): " + ",".join(mismatches))

    base_sev = _counts_by_severity(baseline_tax)
    post_sev = _counts_by_severity(post_tax)
    levels = ["BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_delta = {lvl: int(post_sev.get(lvl, 0) - base_sev.get(lvl, 0)) for lvl in levels}

    base_cls = _counts_by_class(baseline_tax)
    post_cls = _counts_by_class(post_tax)
    class_keys = sorted(set(base_cls.keys()) | set(post_cls.keys()))
    class_deltas = [
        {"failure_class": k, "baseline": int(base_cls.get(k, 0)), "post": int(post_cls.get(k, 0)), "delta": int(post_cls.get(k, 0) - base_cls.get(k, 0))}
        for k in class_keys
    ]
    class_deltas.sort(key=lambda r: (int(r["delta"]), r["failure_class"]))
    top_regressions = [r for r in reversed(class_deltas) if int(r["delta"]) > 0][:25]
    top_fixes = [r for r in class_deltas if int(r["delta"]) < 0][:25]

    status = "PASS"
    if baseline_secret != "PASS" or post_secret != "PASS":
        status = "HOLD"
    if baseline_lint != "PASS" or post_lint != "PASS":
        status = "HOLD"

    delta_report: Dict[str, Any] = {
        "schema_id": "kt.operator.delta_proof.unbound.v1",
        "created_utc": _utc_now_iso_z(),
        "delta_proof_id": "",
        "profile": str(args.profile),
        "head": head,
        "baseline_run_dir": baseline.as_posix(),
        "post_run_dir": post.as_posix(),
        "lock_facts": {"baseline": bfacts, "post": pfacts, "mismatches": mismatches},
        "integrity": {
            "baseline": {"secret_scan_status": baseline_secret, "delivery_lint_status": baseline_lint},
            "post": {"secret_scan_status": post_secret, "delivery_lint_status": post_lint},
        },
        "severity_counts": {
            "baseline": {lvl: int(base_sev.get(lvl, 0)) for lvl in levels},
            "post": {lvl: int(post_sev.get(lvl, 0)) for lvl in levels},
            "delta": sev_delta,
        },
        "top_regressions": top_regressions,
        "top_fixes": top_fixes,
        "patch_card": patch_card,
        "status": status,
    }
    delta_report["delta_proof_id"] = _sha256_text(_canonical_json({k: v for k, v in delta_report.items() if k not in {"created_utc", "delta_proof_id"}}))

    out_delta = (run_dir / "reports" / "delta_proof.json").resolve()
    _write_json_worm(path=out_delta, obj=delta_report, label="delta_proof.json")
    write_text_worm(path=(run_dir / "reports" / "delta_proof.json.sha256.txt").resolve(), text=_sha256_file(out_delta) + "  delta_proof.json\n", label="delta_proof.json.sha256.txt")

    verdict_kind = "PASS" if status == "PASS" else "HOLD"
    verdict = (
        f"KT_DELTA_PROOF_{verdict_kind} cmd=delta-proof head={head} run_id={run_dir.name} "
        f"baseline={baseline.name} post={post.name} blockers={int(sev_delta.get('BLOCKER', 0))}"
    )

    kt_cli._emit_delivery_bundle(  # noqa: SLF001
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_DELTA_PROOF_V1",
        lane_label="delta_proof.v1",
        verdict_line=verdict,
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts")],
        run_protocol_notes=f"Delta proof lane: baseline={baseline.as_posix()} post={post.as_posix()}",
        delivery_manifest_extras={"delta_proof": {"status": status, "baseline_run": baseline.as_posix(), "post_run": post.as_posix()}},
    )

    write_text_worm(path=(run_dir / "reports" / "one_line_verdict.txt").resolve(), text=verdict + "\n", label="one_line_verdict.txt")
    write_text_worm(path=(run_dir / "verdict.txt").resolve(), text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
