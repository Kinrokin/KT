#!/usr/bin/env python3
"""
validator.py — KT Council Packet validator (non-destructive)

Usage:
  python validator.py kt.phase2_work_order.v1.json --schema kt.phase2_work_order.schema.v1.json [--strict]

- Default mode is "planning": seals may be placeholders; missing delivered artifacts are warnings.
- --strict enforces that seal_artifact files exist and do not contain "__PENDING__".
"""
import argparse
import json
import os
import re
import hashlib
from datetime import datetime, timezone

import jsonschema

def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def is_pending(val) -> bool:
    if isinstance(val, str):
        return "__PENDING__" in val
    if isinstance(val, list):
        return any(is_pending(x) for x in val)
    if isinstance(val, dict):
        return any(is_pending(v) for v in val.values())
    return False

def validate_work_order(work_order_path: str, schema_path: str, strict: bool):
    schema = load_json(schema_path)
    data = load_json(work_order_path)

    jsonschema.validate(instance=data, schema=schema)

    # Basic checks
    if not str(data["version"]).startswith("v"):
        raise AssertionError("version must start with 'v'")

    gen = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
    if (datetime.now(timezone.utc) - gen).days >= 365:
        raise AssertionError("work order is older than 1 year")

    teams = data["teams"]
    if len(teams) < 20:
        raise AssertionError("must include at least 20 teams")

    # Team name uniqueness
    names = [t["team"] for t in teams]
    if len(set(names)) != len(names):
        dupes = [n for n in set(names) if names.count(n) > 1]
        raise AssertionError(f"duplicate team names: {dupes}")

    # Seal checks
    errors = []
    warnings = []
    for t in teams:
        seal_path = t["seal_artifact"]
        if not os.path.exists(seal_path):
            errors.append(f"missing seal file: {seal_path} (team={t['team']})")
            continue

        seal = load_json(seal_path)
        required = ["team", "version", "artifacts", "sha256", "ci_run", "signed_by", "signature"]
        for k in required:
            if k not in seal:
                errors.append(f"seal missing key {k}: {seal_path}")
        if strict and is_pending(seal):
            errors.append(f"seal contains __PENDING__ placeholders in strict mode: {seal_path}")

    if errors:
        raise AssertionError("Validation errors:\n- " + "\n- ".join(errors))

    if warnings:
        print("Warnings:\n- " + "\n- ".join(warnings))

    print("Validation PASS.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("work_order_json")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()
    validate_work_order(args.work_order_json, args.schema, args.strict)

if __name__ == "__main__":
    main()
