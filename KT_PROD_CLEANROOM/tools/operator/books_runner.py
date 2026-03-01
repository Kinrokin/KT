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
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import kt_cli
from tools.verification.worm_write import write_text_worm


def _utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _repo_root_from(this_file: Path) -> Path:
    p = this_file.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").exists():
            return parent
    raise RuntimeError("FAIL_CLOSED: unable to locate repo root (missing KT_PROD_CLEANROOM/)")


def _write_json_worm(*, path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=_canonical_json(obj) + "\n", label=label)


def _run(
    *,
    cwd: Path,
    env: Dict[str, str],
    run_dir: Path,
    name: str,
    cmd: Sequence[str],
    allow_nonzero: bool,
) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(list(cmd), cwd=str(cwd), env=env, text=True, capture_output=True)
    combined = (p.stdout or "") + ("\n" if (p.stdout or "").endswith("\n") or not (p.stdout or "") else "\n")
    if p.stderr:
        combined += (p.stderr if p.stderr.endswith("\n") else p.stderr + "\n")
    log_path = (run_dir / "transcripts" / f"{name}.log").resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    write_text_worm(path=log_path, text=combined, label=f"{name}.log")
    if p.returncode != 0 and not allow_nonzero:
        raise RuntimeError(f"FAIL_CLOSED: command failed: {name} rc={p.returncode}")
    return p


def _parse_book_set(value: str) -> List[str]:
    v = str(value or "").strip()
    if not v or v == "00-07":
        return [f"{i:02d}" for i in range(0, 8)]
    parts: List[str] = []
    for chunk in v.split(","):
        c = chunk.strip()
        if not c:
            continue
        if "-" in c:
            a, b = c.split("-", 1)
            start = int(a)
            end = int(b)
            for i in range(start, end + 1):
                parts.append(f"{i:02d}")
        else:
            parts.append(f"{int(c):02d}")
    return sorted({p for p in parts})


@dataclass(frozen=True)
class BookSpec:
    book_id: str
    name: str
    notebook_plan_path: str
    exec_steps: List[Dict[str, Any]]


def _load_suite_manifest(path: Path) -> List[BookSpec]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError("FAIL_CLOSED: suite manifest must be a JSON object")
    books = obj.get("books")
    if not isinstance(books, list) or not books:
        raise RuntimeError("FAIL_CLOSED: suite manifest missing books list")

    out: List[BookSpec] = []
    for b in books:
        if not isinstance(b, dict):
            raise RuntimeError("FAIL_CLOSED: suite manifest book entry must be object")
        bid = str(b.get("book_id", "")).strip()
        name = str(b.get("name", "")).strip()
        nb = str(b.get("notebook_plan_path", "")).strip()
        steps = b.get("exec")
        if not bid or len(bid) != 2 or not bid.isdigit():
            raise RuntimeError("FAIL_CLOSED: invalid book_id in suite manifest")
        if not name or not nb:
            raise RuntimeError("FAIL_CLOSED: invalid book entry (missing name/notebook_plan_path)")
        if not isinstance(steps, list):
            raise RuntimeError("FAIL_CLOSED: invalid book entry (exec must be list)")
        out.append(BookSpec(book_id=bid, name=name, notebook_plan_path=nb, exec_steps=[s for s in steps if isinstance(s, dict)]))
    out.sort(key=lambda x: x.book_id)
    return out


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="KT golden notebook suite runner (Markdown plans; WORM evidence; canonize + optional execution)."
    )
    ap.add_argument("--profile", default="v1", choices=["v1"])
    ap.add_argument("--run-root", default="", help="Optional explicit run root under KT_PROD_CLEANROOM/exports/_runs.")
    ap.add_argument("--allow-dirty", action="store_true", help="Allow dirty worktree (practice only).")
    ap.add_argument(
        "--suite-manifest",
        default="KT_PROD_CLEANROOM/docs/operator/notebooks/NOTEBOOK_SUITE_MANIFEST.v1.json",
        help="Path to NOTEBOOK_SUITE_MANIFEST.v1.json (repo-relative or absolute).",
    )
    ap.add_argument("--book-set", default="00-07", help="Which books to run: 00-07, or comma/range list like 00,02,06.")
    ap.add_argument("--mode", default="execute", choices=["execute", "canonize_only"], help="Execution mode.")
    ap.add_argument("--strict-scan", action="store_true", help="Fail-closed if notebook plan contains blocked patterns.")
    return ap.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root_from(Path(__file__))
    profile = kt_cli.V1

    run_dir = kt_cli._mk_run_dir(  # noqa: SLF001
        repo_root=repo_root, cmd_name="books-run", requested_run_root=str(args.run_root).strip() or None
    )
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    (run_dir / "reports").mkdir(parents=True, exist_ok=True)
    (run_dir / "books").mkdir(parents=True, exist_ok=True)

    # Minimal provenance (same shape as kt_cli lanes).
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

    suite_manifest_path = Path(str(args.suite_manifest)).expanduser()
    if not suite_manifest_path.is_absolute():
        suite_manifest_path = (repo_root / suite_manifest_path).resolve()
    if not suite_manifest_path.exists():
        raise RuntimeError(f"FAIL_CLOSED: suite manifest missing: {suite_manifest_path.as_posix()}")

    wanted_books = set(_parse_book_set(str(args.book_set)))
    all_books = _load_suite_manifest(suite_manifest_path)
    books = [b for b in all_books if b.book_id in wanted_books]
    if not books:
        raise RuntimeError("FAIL_CLOSED: no books selected")

    env = kt_cli._base_env(repo_root=repo_root)  # noqa: SLF001
    mode = str(args.mode).strip()

    per_book_reports: List[Dict[str, Any]] = []
    overall_ok = True

    for b in books:
        book_dir = (run_dir / "books" / f"book_{b.book_id}").resolve()
        book_dir.mkdir(parents=True, exist_ok=True)

        nb_path = Path(b.notebook_plan_path)
        if not nb_path.is_absolute():
            nb_path = (repo_root / nb_path).resolve()
        if not nb_path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing notebook plan for book {b.book_id}: {nb_path.as_posix()}")

        # Canonize plan.
        canon_dir = (book_dir / "canonize").resolve()
        canon_dir.mkdir(parents=True, exist_ok=True)
        if any(canon_dir.iterdir()):
            raise RuntimeError("FAIL_CLOSED: canonize out_dir is not empty (WORM directory reuse forbidden)")

        canon_cmd: List[str] = [
            sys.executable,
            "-m",
            "tools.notebooks.notebook_canonize",
            "--notebook",
            str(nb_path),
            "--out-dir",
            str(canon_dir),
        ]
        if bool(args.strict_scan):
            canon_cmd.append("--strict-scan")
        _run(cwd=repo_root, env=env, run_dir=run_dir, name=f"book_{b.book_id}_canonize", cmd=canon_cmd, allow_nonzero=False)
        canon_manifest_path = (canon_dir / "notebook_manifest.json").resolve()
        if not canon_manifest_path.exists():
            raise RuntimeError("FAIL_CLOSED: notebook_canonize did not produce notebook_manifest.json")

        exec_results: List[Dict[str, Any]] = []
        exec_ok = True
        if mode == "execute":
            for i, step in enumerate(b.exec_steps):
                kind = str(step.get("kind", "")).strip()
                if kind == "kt_cli":
                    step_args = step.get("args")
                    if not isinstance(step_args, list) or not all(isinstance(x, str) for x in step_args):
                        raise RuntimeError("FAIL_CLOSED: kt_cli step args must be list[str]")
                    step_run_dir = (book_dir / "exec" / f"{i:02d}_kt_cli").resolve()
                    step_run_dir.mkdir(parents=True, exist_ok=True)
                    cmd: List[str] = [
                        sys.executable,
                        "-m",
                        "tools.operator.kt_cli",
                        "--profile",
                        str(args.profile),
                        "--run-root",
                        str(step_run_dir),
                    ]
                    if bool(args.allow_dirty):
                        cmd.append("--allow-dirty")
                    cmd.extend([str(x) for x in step_args])
                    p = _run(
                        cwd=repo_root,
                        env=env,
                        run_dir=run_dir,
                        name=f"book_{b.book_id}_step_{i:02d}_kt_cli",
                        cmd=cmd,
                        allow_nonzero=True,
                    )
                    verdict = (p.stdout.strip().splitlines()[-1].strip() if p.stdout and p.stdout.strip() else "")
                    exec_ok = exec_ok and (p.returncode == 0)
                    exec_results.append(
                        {"kind": "kt_cli", "args": [str(x) for x in step_args], "rc": int(p.returncode), "run_dir": step_run_dir.as_posix(), "verdict": verdict}
                    )
                elif kind == "policy_c_sweep_smoke":
                    # Minimal sweep plan under exports/policy_c (allowlisted by runtime registry).
                    cleanroom_root = (repo_root / "KT_PROD_CLEANROOM").resolve()
                    out_root = (cleanroom_root / "exports" / "policy_c" / run_dir.name / f"book_{b.book_id}").resolve()
                    plan_path = (book_dir / "policy_c_sweep_plan.json").resolve()
                    example = json.loads((cleanroom_root / "policy_c" / "example_plan_override.json").read_text(encoding="utf-8"))
                    plan = {
                        "schema_id": "kt.policy_c.sweep_plan.v1",
                        "sweep_id": f"books_{run_dir.name}_{b.book_id}",
                        "baseline_epoch_id": "run_base",
                        "max_runs": 2,
                        "seed": 0,
                        "export": {"export_root": str(out_root.relative_to(cleanroom_root).as_posix())},
                        "runs": example.get("runs", []),
                    }
                    write_text_worm(path=plan_path, text=json.dumps(plan, indent=2, sort_keys=True) + "\n", label="policy_c_sweep_plan.json")
                    cmd = [sys.executable, "-m", "policy_c.sweep_runner", "--plan", str(plan_path), "--out-root", str(out_root)]
                    p = _run(
                        cwd=repo_root,
                        env=env,
                        run_dir=run_dir,
                        name=f"book_{b.book_id}_step_{i:02d}_policy_c",
                        cmd=cmd,
                        allow_nonzero=True,
                    )
                    exec_ok = exec_ok and (p.returncode == 0)
                    exec_results.append({"kind": "policy_c_sweep_smoke", "rc": int(p.returncode), "out_root": out_root.as_posix()})
                elif kind == "forge_smoke":
                    engine = str(step.get("engine", "stub")).strip() or "stub"
                    ds_dir = (book_dir / "forge_smoke_dataset").resolve()
                    ds_dir.mkdir(parents=True, exist_ok=True)
                    write_text_worm(
                        path=(ds_dir / "ds.jsonl").resolve(),
                        text=json.dumps({"text": "stub training line"}, sort_keys=True) + "\n",
                        label="forge_smoke_ds.jsonl",
                    )
                    cfg_path = (book_dir / "forge_smoke_train_config.json").resolve()
                    cfg = {"job_id": f"books_{run_dir.name}_{b.book_id}", "adapter_id": f"books.adapter.{run_dir.name}", "seed": 1337}
                    write_text_worm(path=cfg_path, text=json.dumps(cfg, indent=2, sort_keys=True) + "\n", label="forge_smoke_train_config.json")
                    forge_run_dir = (book_dir / "exec" / f"{i:02d}_forge").resolve()
                    forge_run_dir.mkdir(parents=True, exist_ok=True)
                    holdout = "KT-Codex/packs/KT_FORGE_PROMOTION_ELIGIBLE_HOLDOUT_v1/pack_manifest.json"
                    cmd = [
                        sys.executable,
                        "-m",
                        "tools.operator.kt_cli",
                        "--profile",
                        str(args.profile),
                        "--run-root",
                        str(forge_run_dir),
                    ]
                    if bool(args.allow_dirty):
                        cmd.append("--allow-dirty")
                    cmd += [
                        "forge",
                        "--failure-source",
                        str(ds_dir),
                        "--holdout-pack",
                        holdout,
                        "--train-config",
                        str(cfg_path),
                        "--adapter-id",
                        str(cfg["adapter_id"]),
                        "--seed",
                        "1337",
                        "--engine",
                        engine,
                    ]
                    p = _run(
                        cwd=repo_root,
                        env=env,
                        run_dir=run_dir,
                        name=f"book_{b.book_id}_step_{i:02d}_forge",
                        cmd=cmd,
                        allow_nonzero=True,
                    )
                    verdict = (p.stdout.strip().splitlines()[-1].strip() if p.stdout and p.stdout.strip() else "")
                    exec_ok = exec_ok and (p.returncode == 0)
                    exec_results.append({"kind": "forge_smoke", "engine": engine, "rc": int(p.returncode), "run_dir": forge_run_dir.as_posix(), "verdict": verdict})
                elif kind == "suite_finalize":
                    exec_results.append({"kind": "suite_finalize", "rc": 0})
                else:
                    raise RuntimeError(f"FAIL_CLOSED: unknown exec step kind: {kind}")

        exec_status = "PASS" if exec_ok else "HOLD"
        if mode != "execute":
            exec_status = "SKIPPED"

        book_report = {
            "schema_id": "kt.operator.books.book_final_report.unbound.v1",
            "created_utc": _utc_now_iso_z(),
            "book_id": b.book_id,
            "book_name": b.name,
            "notebook_plan_path": nb_path.as_posix(),
            "canonize": {
                "notebook_sha256": _sha256_file(nb_path),
                "notebook_manifest_path": canon_manifest_path.as_posix(),
                "notebook_manifest_sha256": _sha256_file(canon_manifest_path),
            },
            "execution": {"mode": mode, "status": exec_status, "steps": exec_results},
        }
        book_final_path = (book_dir / "FINAL_REPORT.json").resolve()
        _write_json_worm(path=book_final_path, obj=book_report, label=f"book_{b.book_id}.FINAL_REPORT.json")
        book_sha = _sha256_file(book_final_path)
        write_text_worm(path=(book_dir / "FINAL_REPORT.sha256").resolve(), text=book_sha + "\n", label=f"book_{b.book_id}.FINAL_REPORT.sha256")

        per_book_reports.append(
            {"book_id": b.book_id, "status": exec_status, "final_report": book_final_path.as_posix(), "sha256": book_sha}
        )
        overall_ok = overall_ok and exec_ok

    suite_report = {
        "schema_id": "kt.operator.books.suite_final_report.unbound.v1",
        "created_utc": _utc_now_iso_z(),
        "head": head,
        "profile": str(args.profile),
        "mode": mode,
        "books": per_book_reports,
        "status": "PASS" if overall_ok else "HOLD",
    }
    suite_final_path = (run_dir / "FINAL_REPORT.json").resolve()
    _write_json_worm(path=suite_final_path, obj=suite_report, label="FINAL_REPORT.json")
    suite_sha = _sha256_file(suite_final_path)
    write_text_worm(path=(run_dir / "FINAL_REPORT.sha256").resolve(), text=suite_sha + "\n", label="FINAL_REPORT.sha256")
    _write_json_worm(path=(run_dir / "reports" / "books_suite_final_report.json").resolve(), obj=suite_report, label="books_suite_final_report.json")

    verdict_kind = "PASS" if overall_ok else "HOLD"
    verdict = f"KT_BOOKS_SUITE_{verdict_kind} cmd=books-run head={head} run_id={run_dir.name} books={len(per_book_reports)}"

    kt_cli._emit_delivery_bundle(  # noqa: SLF001
        repo_root=repo_root,
        profile=profile,
        run_dir=run_dir,
        head=head,
        lane_id="KT_OPERATOR_BOOKS_SUITE_V1",
        lane_label="books_suite.v1",
        verdict_line=verdict,
        core_copy_dirs=[("reports", "reports"), ("transcripts", "transcripts"), ("books", "books")],
        run_protocol_notes="Golden notebook suite runner (Markdown plans): canonize + optional execution.",
        delivery_manifest_extras={"books_suite": {"status": verdict_kind, "book_count": len(per_book_reports)}},
    )

    write_text_worm(path=(run_dir / "reports" / "one_line_verdict.txt").resolve(), text=verdict + "\n", label="one_line_verdict.txt")
    write_text_worm(path=(run_dir / "verdict.txt").resolve(), text=verdict + "\n", label="verdict.txt")
    print(verdict)
    return 0 if overall_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
