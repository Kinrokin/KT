from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path


PATTERNS = [
    r"\bcommercial launch ready\b",
    r"\bS-tier earned\b",
    r"\bbeyond[- ]SOTA earned\b",
    r"\brouter superiority proven\b",
    r"\blearned-router superiority proven\b",
    r"\b7B amplification proven\b",
    r"\bexternal validation complete\b",
    r"\bexternal audit complete\b",
    r"\bmulti-lobe superiority proven\b",
    r"\bproduction ready\b",
]
ALLOW_CONTEXT = [
    "forbidden",
    "blocked",
    "do not",
    "not authorize",
    "not authorized",
    "unsafe",
    "claim ceiling",
    "blocked_claims",
    "forbidden_claims",
]
ALLOW_PATH_TOKENS = [
    "claim_admissibility",
    "claim_boundary",
    "claim_ceiling",
    "current_claim_ceiling",
    "current_truth_head",
    "failure_confession",
    "forbidden_claim",
    "hard_refusal",
    "attestation_blocker",
    "customer_safe_language_pack",
    "statistical_analysis_plan",
    "accountability_common.py",
]
SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "archive",
    "archive_index",
    "runs",
    "KT_PROD_CLEANROOM",
}
TEXT_SUFFIXES = {".md", ".txt", ".json", ".py", ".yaml", ".yml"}
MAX_TEXT_BYTES = 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    bad: list[str] = []
    rg_args = [
        "rg",
        "--no-heading",
        "--line-number",
        "--ignore-case",
        "--max-filesize",
        "1M",
        "--glob",
        "*.md",
        "--glob",
        "*.txt",
        "--glob",
        "*.json",
        "--glob",
        "*.py",
        "--glob",
        "*.yaml",
        "--glob",
        "*.yml",
    ]
    for skipped in sorted(SKIP_DIRS):
        rg_args.extend(["--glob", f"!**/{skipped}/**"])
    rg_args.extend(["--glob", "!**/*.zip", "--glob", "!**/*.safetensors"])
    for pattern in PATTERNS:
        rg_args.extend(["-e", pattern])
    rg_args.append(str(root))
    try:
        result = subprocess.run(rg_args, text=True, capture_output=True, check=False)
        if result.returncode not in {0, 1}:
            raise FileNotFoundError(result.stderr)
        for line in result.stdout.splitlines():
            lowered_line = line.lower()
            if any(token in lowered_line for token in ALLOW_PATH_TOKENS):
                continue
            if any(token in lowered_line for token in ALLOW_CONTEXT):
                continue
            bad.append(line)
    except FileNotFoundError:
        rx = re.compile("|".join(PATTERNS), re.I)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
            base = Path(dirpath)
            for filename in filenames:
                path = base / filename
                if path.suffix.lower() not in TEXT_SUFFIXES:
                    continue
                if path.stat().st_size > MAX_TEXT_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                for line_no, line in enumerate(lines, 1):
                    rel = path.relative_to(root).as_posix().lower()
                    if any(token in rel for token in ALLOW_PATH_TOKENS):
                        continue
                    if rx.search(line) and not any(token in line.lower() for token in ALLOW_CONTEXT):
                        bad.append(f"{path.relative_to(root)}:{line_no}:{line.strip()}")
    if bad:
        print("FORBIDDEN_CLAIM_SCAN FAIL")
        print("\n".join(bad[:100]))
        return 1
    print("FORBIDDEN_CLAIM_SCAN PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
