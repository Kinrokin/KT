from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
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
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=_canonical_json(obj) + "\n", label=label)


def _run_subprocess(
    *, repo_root: Path, run_dir: Path, name: str, cmd: Sequence[str], env: Dict[str, str], allow_nonzero: bool
) -> Tuple[int, str]:
    p = subprocess.run(list(cmd), cwd=str(repo_root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = p.stdout or ""
    log_path = (run_dir / "transcripts" / f"{name}.log").resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_worm(path=log_path, text=out if out.endswith("\n") else out + "\n", label=f"{name}.log")
    rc = int(p.returncode)
    if rc != 0 and not allow_nonzero:
        raise RuntimeError(f"FAIL_CLOSED: command failed: {name} rc={rc} cmd={' '.join(cmd)}")
    return rc, out


def _env_key_fingerprint(v: str) -> str:
    return hashlib.sha256((v or "").encode("utf-8")).hexdigest()


def _expected_hmac_fingerprints_from_suite_registry(repo_root: Path) -> Dict[str, str]:
    suite_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITE_REGISTRY_FL3.json").resolve()
    obj = json.loads(suite_path.read_text(encoding="utf-8"))
    suites = obj.get("suites") if isinstance(obj.get("suites"), list) else []
    fps: Dict[str, str] = {}
    for row in suites:
        if not isinstance(row, dict):
            continue
        signoffs = row.get("signoffs") if isinstance(row.get("signoffs"), list) else []
        for s in signoffs:
            if not isinstance(s, dict):
                continue
            if str(s.get("attestation_mode", "")).strip().upper() != "HMAC":
                continue
            kid = str(s.get("key_id", "")).strip().upper()
            fp = str(s.get("hmac_key_fingerprint", "")).strip()
            if not kid or len(fp) != 64:
                continue
            if kid in fps and fps[kid] != fp:
                raise RuntimeError(f"FAIL_CLOSED: inconsistent hmac_key_fingerprint for key_id={kid}")
            fps[kid] = fp
    return fps


@dataclass(frozen=True)
class LaneResult:
    lane: str
    run_dir: str
    rc: int
    verdict: str
    has_delivery: bool
    secret_scan_status: str
    delivery_lint_status: str


def _load_optional_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _summarize_lane_run(*, lane: str, lane_dir: Path) -> LaneResult:
    verdict_path = (lane_dir / "verdict.txt").resolve()
    verdict = verdict_path.read_text(encoding="utf-8", errors="replace").strip() if verdict_path.exists() else ""

    secret_path = (lane_dir / "evidence" / "secret_scan_report.json").resolve()
    lint_path = (lane_dir / "delivery" / "delivery_lint_report.json").resolve()
    secret = _load_optional_json(secret_path) or {}
    lint = _load_optional_json(lint_path) or {}
    has_delivery = bool((lane_dir / "delivery" / "delivery_manifest.json").exists())

    # Prefer explicit status fields where available.
    secret_status = str(secret.get("status", "")).strip() or ("UNKNOWN" if secret_path.exists() else "MISSING")
    lint_status = str(lint.get("status", "")).strip() or ("UNKNOWN" if lint_path.exists() else "MISSING")

    # rc is recorded by the wrapper logs; if missing, treat as unknown.
    rc_path = (lane_dir / "transcripts" / "wrapper_rc.txt").resolve()
    rc = int(rc_path.read_text(encoding="utf-8").strip()) if rc_path.exists() else 0

    return LaneResult(
        lane=lane,
        run_dir=lane_dir.as_posix(),
        rc=rc,
        verdict=verdict,
        has_delivery=has_delivery,
        secret_scan_status=secret_status,
        delivery_lint_status=lint_status,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KT readiness grader (operator-factory focused; WORM outputs).")
    p.add_argument("--profile", default="v1", choices=["v1"])
    p.add_argument("--run-root", default="", help="Optional explicit run root under KT_PROD_CLEANROOM/exports/_runs.")
    p.add_argument("--allow-dirty", action="store_true", help="Allow dirty worktree (practice readiness).")
    return p.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))

    # Run root (WORM).
    base_run_dir = kt_cli._mk_run_dir(  # noqa: SLF001 (intentional reuse of operator primitives)
        repo_root=repo_root, cmd_name="readiness-grade", requested_run_root=str(args.run_root).strip() or None
    )
    (base_run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    (base_run_dir / "reports").mkdir(parents=True, exist_ok=True)
    (base_run_dir / "inputs").mkdir(parents=True, exist_ok=True)

    # Provenance.
    head = kt_cli._git(repo_root=repo_root, args=["rev-parse", "HEAD"])  # noqa: SLF001
    branch = kt_cli._git(repo_root=repo_root, args=["rev-parse", "--abbrev-ref", "HEAD"])  # noqa: SLF001
    git_status = kt_cli._git(repo_root=repo_root, args=["status", "--porcelain=v1"])  # noqa: SLF001

    # Key posture (presence/length + fingerprint compare to pinned).
    env_keys = {k: os.environ.get(k, "") for k in ("KT_HMAC_KEY_SIGNER_A", "KT_HMAC_KEY_SIGNER_B")}
    env_key_meta = {
        k: {
            "present": bool(v),
            "length": len(v) if v else 0,
            "fingerprint_sha256": (_env_key_fingerprint(v) if v else ""),
        }
        for k, v in env_keys.items()
    }
    expected_fps = _expected_hmac_fingerprints_from_suite_registry(repo_root=repo_root)
    expected_meta = {
        "SIGNER_A": expected_fps.get("SIGNER_A", ""),
        "SIGNER_B": expected_fps.get("SIGNER_B", ""),
    }
    keys_match_pins = (
        bool(env_key_meta["KT_HMAC_KEY_SIGNER_A"]["fingerprint_sha256"])
        and bool(env_key_meta["KT_HMAC_KEY_SIGNER_B"]["fingerprint_sha256"])
        and env_key_meta["KT_HMAC_KEY_SIGNER_A"]["fingerprint_sha256"] == expected_meta["SIGNER_A"]
        and env_key_meta["KT_HMAC_KEY_SIGNER_B"]["fingerprint_sha256"] == expected_meta["SIGNER_B"]
    )

    # Domain posture (docs present).
    fintech_playbook = (repo_root / "KT_PROD_CLEANROOM" / "docs" / "operator" / "domains" / "FINTECH_SUITE_PORTFOLIO_V1.md").resolve()
    domain_standard = (repo_root / "KT_PROD_CLEANROOM" / "docs" / "operator" / "domains" / "DOMAIN_SUITE_STANDARD.md").resolve()
    has_fintech_playbook = fintech_playbook.exists()
    has_domain_standard = domain_standard.exists()

    # Execute representative lanes (practice-safe). Each lane gets its own WORM subdir.
    env = kt_cli._base_env(repo_root=repo_root)  # noqa: SLF001
    lanes: List[LaneResult] = []
    lane_failures: List[Dict[str, Any]] = []

    def run_lane(lane_name: str, cli_args: List[str], *, allow_nonzero: bool) -> Path:
        lane_dir = (base_run_dir / "lanes" / lane_name).resolve()
        lane_dir.parent.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-m", "tools.operator.kt_cli", "--profile", str(args.profile), "--run-root", str(lane_dir)]
        if bool(args.allow_dirty):
            cmd.append("--allow-dirty")
        cmd.extend(cli_args)
        rc, _out = _run_subprocess(
            repo_root=repo_root,
            run_dir=base_run_dir,
            name=f"lane_{lane_name}",
            cmd=cmd,
            env=dict(env),
            allow_nonzero=True,
        )
        write_text_worm(path=lane_dir / "transcripts" / "wrapper_rc.txt", text=str(rc) + "\n", label="wrapper_rc.txt")
        if rc != 0 and not allow_nonzero:
            lane_failures.append({"lane": lane_name, "rc": rc, "kind": "RC_NONZERO", "cmd": cmd})
        return lane_dir

    # 1) Status (pins + determinism anchor; no key validation required).
    status_dir = run_lane("status", ["status"], allow_nonzero=False)
    lanes.append(_summarize_lane_run(lane="status", lane_dir=status_dir))

    # 2) CI simulation (runs tests + meta-evaluator expected-fail behavior).
    ci_sim_dir = run_lane("certify_ci_sim", ["certify", "--lane", "ci_sim"], allow_nonzero=False)
    lanes.append(_summarize_lane_run(lane="certify.ci_sim", lane_dir=ci_sim_dir))

    # 3) Overlay apply (domain.fintech).
    ov_dir = run_lane(
        "overlay_apply_fintech",
        ["overlay-apply", "--overlay-id", "domain.fintech.v1", "--target-lane", "certify", "--strict"],
        allow_nonzero=False,
    )
    lanes.append(_summarize_lane_run(lane="overlay_apply.v1", lane_dir=ov_dir))

    # 4) Red assault (factory pack).
    ra_dir = run_lane(
        "red_assault_factory",
        ["red-assault", "--pack-id", "fl3_factory_v1", "--pressure-level", "high", "--sample-count", "50", "--seed", "1337"],
        allow_nonzero=False,
    )
    lanes.append(_summarize_lane_run(lane="red_assault.v1", lane_dir=ra_dir))

    # 5) Continuous governance diff vs overlay baseline.
    cg_dir = run_lane(
        "continuous_gov",
        [
            "continuous-gov",
            "--baseline-run",
            str(ov_dir),
            "--window",
            "1",
            "--thresholds",
            "{}",
        ],
        allow_nonzero=False,
    )
    lanes.append(_summarize_lane_run(lane="continuous_gov.v1", lane_dir=cg_dir))

    # 6) Forge lane (intentional FAIL_CLOSED training engine gate: hf_lora without enable-real-engine).
    forge_dataset = (base_run_dir / "inputs" / "forge_demo_dataset.jsonl").resolve()
    if not forge_dataset.exists():
        # Safe, minimal, deterministic dataset line.
        write_text_worm(path=forge_dataset, text='{"text":"readiness_demo"}\n', label="forge_demo_dataset.jsonl")
    holdout_manifest = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "UTILITY_PACK_V1" / "UTILITY_PACK_MANIFEST.json").resolve()
    train_cfg = json.dumps({"job_id": "readiness_demo", "training_mode": "lora"}, sort_keys=True, separators=(",", ":"))
    forge_dir = run_lane(
        "forge_training_gated",
        [
            "forge",
            "--failure-source",
            str(forge_dataset),
            "--holdout-pack",
            str(holdout_manifest),
            "--train-config",
            train_cfg,
            "--adapter-id",
            "ADAPTER_READINESS_DEMO",
            "--seed",
            "1337",
            "--engine",
            "hf_lora",
        ],
        allow_nonzero=True,  # forge may BLOCKED but should still emit artifacts
    )
    lanes.append(_summarize_lane_run(lane="forge.v1", lane_dir=forge_dir))

    # Score calculation (rubric-aligned, evidence-backed).
    blockers: List[str] = []
    score = 0

    # Integrity anchors (20): rely on status lane PASS.
    status_ok = "KT_STATUS_PASS" in (lanes[0].verdict or "")
    if status_ok:
        score += 20
    else:
        blockers.append("STATUS_LANE_NOT_PASS")

    # Evidence discipline (20): require secret scan + delivery lint PASS for delivery-bearing lanes.
    delivery_lanes = [r for r in lanes if r.lane not in {"status", "certify.ci_sim"}]
    evidence_ok = True
    for r in delivery_lanes:
        if r.secret_scan_status != "PASS":
            evidence_ok = False
            blockers.append(f"SECRET_SCAN_NOT_PASS:{r.lane}")
        if r.delivery_lint_status != "PASS":
            evidence_ok = False
            blockers.append(f"DELIVERY_LINT_NOT_PASS:{r.lane}")
        if not r.has_delivery:
            evidence_ok = False
            blockers.append(f"DELIVERY_MISSING:{r.lane}")
    if evidence_ok:
        score += 20

    # Factory lanes operable (20).
    lanes_ok = True
    for r in lanes:
        first_token = (r.verdict or "").strip().split()[0].upper() if (r.verdict or "").strip() else ""
        if not first_token or "FAIL_CLOSED" in first_token:
            lanes_ok = False
            blockers.append(f"LANE_NOT_OK:{r.lane}")
    if lanes_ok:
        score += 10  # base for practice lanes executed
    # Canonical lane readiness check (keys + clean worktree).
    clean = not bool(git_status.strip())
    if clean and keys_match_pins:
        score += 10
    else:
        blockers.append("CANONICAL_HMAC_NOT_RUNNABLE_CLEAN")  # audit-grade blocker

    # Domain pressure posture (20): docs present + policy declared (partial credit).
    if has_domain_standard:
        score += 5
    if has_fintech_playbook:
        score += 10
    # Dual-use gating is policy-only in v1; award partial credit if playbook exists.
    if has_fintech_playbook:
        score += 5

    # Promotion governance (10): forge lane exists + emits promotion gate (even if skipped).
    promo_gate_path = (forge_dir / "forge" / "promotion_gate.json").resolve()
    if promo_gate_path.exists():
        score += 10
    else:
        blockers.append("FORGE_PROMOTION_GATE_MISSING")

    # Operational hardening (10): key rotation tooling exists + does not print values by design.
    key_tool = (repo_root / "KT_PROD_CLEANROOM" / "tools" / "operator" / "rotate_hmac_keys.ps1").resolve()
    key_doc = (repo_root / "KT_PROD_CLEANROOM" / "docs" / "operator" / "HMAC_KEY_ROTATION.md").resolve()
    if key_tool.exists() and key_doc.exists():
        score += 10
    else:
        blockers.append("KEY_ROTATION_TOOLING_MISSING")

    score = max(0, min(100, int(score)))
    grade = "F"
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"

    # Overall status: HOLD if audit-grade blockers present.
    audit_blockers = [b for b in blockers if b in {"CANONICAL_HMAC_NOT_RUNNABLE_CLEAN"} or b.startswith("SECRET_SCAN_NOT_PASS") or b.startswith("DELIVERY_LINT_NOT_PASS")]
    overall_status = "PASS" if not audit_blockers else "HOLD"

    report: Dict[str, Any] = {
        "schema_id": "kt.operator.readiness_grade.unbound.v1",
        "created_utc": _utc_now_iso_z(),
        "run_dir": base_run_dir.as_posix(),
        "head": head,
        "branch": branch,
        "worktree_clean": clean,
        "allow_dirty": bool(args.allow_dirty),
        "hmac_keys": {
            "env": env_key_meta,
            "expected_from_suite_registry": expected_meta,
            "keys_match_pins": bool(keys_match_pins),
        },
        "domain_posture": {
            "domain_standard_present": bool(has_domain_standard),
            "fintech_playbook_present": bool(has_fintech_playbook),
        },
        "lanes": [r.__dict__ for r in lanes],
        "lane_failures": lane_failures,
        "blockers": blockers,
        "score": score,
        "grade": grade,
        "overall_status": overall_status,
        "rubric_ref": "KT_PROD_CLEANROOM/docs/operator/KT_READINESS_GRADE_RUBRIC.md",
        "report_id": "",
    }
    report["report_id"] = _sha256_text(_canonical_json({k: v for k, v in report.items() if k != "report_id"}))

    out_json = (base_run_dir / "reports" / "readiness_grade.json").resolve()
    _write_json_worm(path=out_json, obj=report, label="readiness_grade.json")

    # Human summary (deterministic).
    md: List[str] = []
    md.append("# KT Readiness Grade")
    md.append("")
    md.append(f"- overall_status: `{overall_status}`")
    md.append(f"- grade: `{grade}` score: `{score}/100`")
    md.append(f"- head: `{head}` branch: `{branch}`")
    md.append(f"- worktree_clean: `{int(clean)}` allow_dirty: `{int(bool(args.allow_dirty))}`")
    md.append(f"- keys_match_pins: `{int(bool(keys_match_pins))}` (required for canonical_hmac in clean audit runs)")
    if blockers:
        md.append("")
        md.append("## Blockers / gaps")
        for b in blockers:
            md.append(f"- {b}")
    md.append("")
    md.append("## Lane evidence")
    for r in lanes:
        md.append(
            f"- {r.lane}: verdict=`{r.verdict or '<missing>'}` delivery={int(r.has_delivery)} "
            f"secret_scan={r.secret_scan_status} delivery_lint={r.delivery_lint_status}"
        )
    md.append("")
    md.append("## Replay / client delivery")
    md.append("- Delivery acceptance is mechanical: `delivery/delivery_manifest.json`, zip sha256 receipt, replay wrappers, secret scan PASS.")
    md.append("")
    md.append("## Notes")
    md.append("- This grade is evidence-backed for the operator factory lanes executed under this run root.")
    md.append("- Audit-grade delivery requires a clean worktree and canonical HMAC keys that match the pinned suite registry fingerprints.")

    out_md = (base_run_dir / "reports" / "readiness_grade.md").resolve()
    write_text_worm(path=out_md, text="\n".join(md) + "\n", label="readiness_grade.md")

    verdict_line = f"KT_READINESS_{overall_status} grade={grade} score={score} head={head} run_dir={base_run_dir.as_posix()}"
    write_text_worm(path=base_run_dir / "verdict.txt", text=verdict_line + "\n", label="verdict.txt")
    print(verdict_line)
    return 0 if overall_status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
