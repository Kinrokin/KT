#!/usr/bin/env python3
"""Cumulative nested-archive safety validator.

Budgets apply to the entire recursive archive tree, not once per nested ZIP.
"""
from __future__ import annotations

import argparse
import io
import json
import stat
import sys
import unicodedata
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath


@dataclass
class Budget:
    max_depth: int = 4
    max_total_members: int = 20000
    max_total_expanded_bytes: int = 4 * 1024**3
    max_total_compressed_bytes: int = 2 * 1024**3
    max_single_member_bytes: int = 1024**3
    max_path_length: int = 240
    max_total_filename_bytes: int = 8 * 1024**2
    max_expansion_ratio: float = 500.0


@dataclass
class Totals:
    total_members: int = 0
    total_expanded_bytes: int = 0
    total_compressed_bytes: int = 0
    total_filename_bytes: int = 0
    nested_archive_count: int = 0
    maximum_depth_seen: int = 0


class ArchiveViolation(ValueError):
    pass


def reject(condition: bool, code: str) -> None:
    if condition:
        raise ArchiveViolation(code)


def normalized_key(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


def inspect_zip(zf: zipfile.ZipFile, *, label: str, depth: int, budget: Budget, totals: Totals) -> None:
    reject(depth > budget.max_depth, f"archive:max_depth:{label}")
    totals.maximum_depth_seen = max(totals.maximum_depth_seen, depth)
    seen: set[str] = set()
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        reject(info.flag_bits & 0x1 != 0, f"archive:encrypted:{label}:{name}")
        reject("\x00" in name, f"archive:nul_name:{label}")
        path = PurePosixPath(name)
        reject(path.is_absolute() or any(part in {"..", ""} for part in path.parts), f"archive:path_traversal:{label}:{name}")
        reject(len(name) > budget.max_path_length, f"archive:path_too_long:{label}:{name}")
        key = normalized_key(name)
        reject(key in seen, f"archive:unicode_or_case_collision:{label}:{name}")
        seen.add(key)
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode:
            reject(stat.S_ISLNK(mode), f"archive:symlink:{label}:{name}")
            file_type = stat.S_IFMT(mode)
            reject(file_type not in {0, stat.S_IFREG, stat.S_IFDIR}, f"archive:special_file:{label}:{name}")
        reject(info.file_size > budget.max_single_member_bytes, f"archive:member_too_large:{label}:{name}")
        totals.total_members += 1
        totals.total_expanded_bytes += info.file_size
        totals.total_compressed_bytes += info.compress_size
        totals.total_filename_bytes += len(name.encode("utf-8"))
        reject(totals.total_members > budget.max_total_members, "archive:cumulative_member_limit")
        reject(totals.total_expanded_bytes > budget.max_total_expanded_bytes, "archive:cumulative_expanded_limit")
        reject(totals.total_compressed_bytes > budget.max_total_compressed_bytes, "archive:cumulative_compressed_limit")
        reject(totals.total_filename_bytes > budget.max_total_filename_bytes, "archive:cumulative_filename_bytes_limit")
        if info.compress_size > 0:
            reject(info.file_size / info.compress_size > budget.max_expansion_ratio, f"archive:member_expansion_ratio:{label}:{name}")
        if info.is_dir():
            continue
        suffix = PurePosixPath(name).suffix.lower()
        if suffix == ".zip":
            totals.nested_archive_count += 1
            reject(depth >= budget.max_depth, f"archive:nested_depth_limit:{label}:{name}")
            data = zf.read(info)
            reject(not zipfile.is_zipfile(io.BytesIO(data)), f"archive:invalid_nested_zip:{label}:{name}")
            with zipfile.ZipFile(io.BytesIO(data)) as nested:
                inspect_zip(nested, label=f"{label}!{name}", depth=depth + 1, budget=budget, totals=totals)


def validate(path: Path, budget: Budget) -> Totals:
    reject(not path.is_file(), "archive:not_file")
    reject(not zipfile.is_zipfile(path), "archive:not_zip")
    totals = Totals()
    with zipfile.ZipFile(path) as zf:
        inspect_zip(zf, label=path.name, depth=0, budget=budget, totals=totals)
    if totals.total_compressed_bytes:
        reject(totals.total_expanded_bytes / totals.total_compressed_bytes > budget.max_expansion_ratio,
               "archive:cumulative_expansion_ratio")
    return totals


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("archive")
    p.add_argument("--max-depth", type=int, default=4)
    p.add_argument("--max-total-members", type=int, default=20000)
    p.add_argument("--max-total-expanded-bytes", type=int, default=4 * 1024**3)
    p.add_argument("--max-total-compressed-bytes", type=int, default=2 * 1024**3)
    p.add_argument("--max-single-member-bytes", type=int, default=1024**3)
    p.add_argument("--max-path-length", type=int, default=240)
    p.add_argument("--max-total-filename-bytes", type=int, default=8 * 1024**2)
    p.add_argument("--max-expansion-ratio", type=float, default=500.0)
    args = p.parse_args()
    budget = Budget(
        max_depth=args.max_depth,
        max_total_members=args.max_total_members,
        max_total_expanded_bytes=args.max_total_expanded_bytes,
        max_total_compressed_bytes=args.max_total_compressed_bytes,
        max_single_member_bytes=args.max_single_member_bytes,
        max_path_length=args.max_path_length,
        max_total_filename_bytes=args.max_total_filename_bytes,
        max_expansion_ratio=args.max_expansion_ratio,
    )
    try:
        totals = validate(Path(args.archive), budget)
    except (ArchiveViolation, zipfile.BadZipFile, OSError) as exc:
        print(f"archive_safety_fail:{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "PASS", "archive": str(Path(args.archive)), "budget": asdict(budget), "totals": asdict(totals)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
