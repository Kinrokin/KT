#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    raise SystemExit("unable to locate repo root from staging path")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def build_manifest_digest(staging_manifest_path: Path) -> str:
    manifest = json.loads(staging_manifest_path.read_text(encoding="utf-8"))
    excluded = {
        "governance/H1_EXPERIMENT_MANIFEST.json",
        "staging/manifest.json",
        "reports/cohort0_current_head_receipt.json",
    }
    rows = []
    for row in manifest["files"]:
        if row["path"] in excluded:
            continue
        rows.append(
            {
                "mime_type": row["mime_type"],
                "path": row["path"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
            }
        )
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return sha256_hex(payload)


def build_receipt(staging_root: Path) -> dict:
    repo = find_repo_root(staging_root)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    head = git(repo, "rev-parse", "HEAD")
    branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    tree_digest = subprocess.run(
        'git ls-tree -r HEAD --full-tree | python -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"',
        cwd=repo,
        capture_output=True,
        text=True,
        shell=True,
        check=True,
    ).stdout.strip()
    schema_path = staging_root / "governance" / "RMR_SCHEMA_v1.json"
    staging_manifest_path = staging_root / "staging" / "manifest.json"
    frozen_manifest_digest = build_manifest_digest(staging_manifest_path)
    payload = json.dumps(
        {
            "repo": "KT_PROD_CLEANROOM",
            "current_git_head": head,
            "current_branch": branch,
            "timestamp": now,
            "frozen_manifest_digest": frozen_manifest_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "__generated_by_agent__": True,
        "repo": "KT_PROD_CLEANROOM",
        "current_git_head": head,
        "current_branch": branch,
        "clean_worktree_status": "clean" if not status else "dirty_outside_mutable_paths_must_be_checked_by_preflight",
        "tree_digest": tree_digest,
        "frozen_manifest_digest": frozen_manifest_digest,
        "rmr_schema_digest": sha256_hex(schema_path.read_bytes()),
        "timestamp": now,
        "external_timestamp_or_transparency_reference": {
            "mode": "mock",
            "timestamp": now,
            "reference": "mock_rekor/index.json",
        },
        "mock_signed_payload": base64.b64encode(payload).decode(),
        "signer_keys": [
            {
                "name": "mock-cosign",
                "path": "keys/mock_cosign_key.pem",
                "key_id": "mock-key-id",
            },
            {
                "name": "mock-rekor",
                "path": "keys/mock_rekor_key.pem",
                "key_id": "mock-rekor-key-id",
            },
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--staging-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--out")
    args = ap.parse_args()

    staging_root = Path(args.staging_root).resolve()
    out_path = Path(args.out) if args.out else staging_root / "reports" / "cohort0_current_head_receipt.json"
    receipt = build_receipt(staging_root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
