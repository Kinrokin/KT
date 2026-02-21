from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json_dict(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL_CLOSED: unreadable JSON {label}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        _fail_closed(f"{label} must be a JSON object: {path.as_posix()}")
    return obj


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay verifier: compare a sha256 manifest against a directory tree (fail-closed).")
    ap.add_argument("--manifest", required=True, help="Path to sha256 manifest JSON (mapping relpath->sha256).")
    ap.add_argument("--root", required=True, help="Root directory that contains the manifest's files.")
    ap.add_argument("--out", required=True, help="Output divergence report JSON path (WORM).")
    ap.add_argument("--deny-extra", action="store_true", help="Fail if extra files exist under root beyond manifest keys.")
    args = ap.parse_args(argv)

    manifest_path = Path(args.manifest).resolve()
    root = Path(args.root).resolve()
    out_path = Path(args.out).resolve()

    if not manifest_path.is_file():
        _fail_closed("manifest missing")
    if not root.is_dir():
        _fail_closed("root missing")

    manifest = _read_json_dict(manifest_path, label="sha256_manifest")
    missing: List[str] = []
    mismatches: List[Dict[str, str]] = []

    for rel, exp in sorted(manifest.items(), key=lambda kv: str(kv[0])):
        rel_s = str(rel).replace("\\", "/").lstrip("/")
        exp_s = str(exp).strip()
        if not rel_s or len(exp_s) != 64:
            _fail_closed("invalid manifest entry")
        p = (root / rel_s).resolve()
        if not p.is_file():
            missing.append(rel_s)
            continue
        act = _sha256_file(p)
        if act != exp_s:
            mismatches.append({"path": rel_s, "expected": exp_s, "actual": act})

    extra: List[str] = []
    if bool(args.deny_extra):
        keys = {str(k).replace("\\", "/").lstrip("/") for k in manifest.keys()}
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            relp = str(p.relative_to(root)).replace("\\", "/")
            if relp not in keys:
                extra.append(relp)

    status = "PASS" if (not missing and not mismatches and not extra) else "FAIL"
    report = {
        "schema_id": "kt.replay_divergence_report.v1",
        "status": status,
        "manifest_path": manifest_path.as_posix(),
        "root": root.as_posix(),
        "missing": missing,
        "hash_mismatches": mismatches,
        "extra_files": extra,
    }
    write_text_worm(
        path=out_path,
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="replay_divergence_report.json",
    )
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())

