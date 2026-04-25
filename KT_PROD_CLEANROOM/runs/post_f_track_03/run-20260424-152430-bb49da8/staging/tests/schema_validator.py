#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import mimetypes
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

EXIT_SUCCESS = 0
EXIT_PREFLIGHT = 10
EXIT_FRESHNESS = 20
EXIT_SCHEMA = 30
EXIT_BETA = 40
EXIT_HOLDOUT = 50
EXIT_RUNTIME = 60
EXIT_PUBLISH = 70
EXIT_UNKNOWN = 99

REASON_CODES = {
    "RC001_CONTEXT_ALIGNMENT","RC002_POLICY_COMPATIBLE","RC003_MARGIN_SUFFICIENT",
    "RC004_COUNTERFACTUAL_STABLE","RC005_MASKED_INVARIANT","RC006_ROUTE_SUPERIOR",
    "RC007_RISK_LOW","RC008_EVIDENCE_COMPLETE","RC009_DEFER_REQUIRED","RC010_RUNTIME_BOUNDED"
}
WHY_NOT_CODES = {
    "WN001_NO_POLICY_MATCH","WN002_LOW_MARGIN","WN003_MASKED_DRIFT","WN004_MIRROR_BREAK",
    "WN005_PROVIDER_REFUSED","WN006_BETA_CONTAMINATED","WN007_HOLDOUT_LEAKAGE",
    "WN008_RUNTIME_MISSING","WN009_ROUTE_UNSAFE","WN010_HUMAN_REVIEW_REQUIRED"
}

def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_hex_path(path: Path) -> str:
    return sha256_hex_bytes(path.read_bytes())

def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def is_rfc3339_z(value: str) -> bool:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.tzinfo is not None
    except Exception:
        return False

def validate_provider_call(call: Dict[str, Any]) -> None:
    required = {"provider", "prompt_sha256", "response_sha256", "receipt_id"}
    if set(call.keys()) != required:
        raise ValueError(f"provider call keys mismatch: {call.keys()}")
    if len(call["prompt_sha256"]) != 64 or len(call["response_sha256"]) != 64:
        raise ValueError("provider call digest length invalid")

def validate_rmr(row: Dict[str, Any]) -> None:
    required = {
        "rmr_id","case_id","family","variant","input_hash","router_choice","baseline_choice",
        "decision_label","reason_codes","why_not","provider_calls","margin","confidence",
        "beta","holdout","counted","timestamp","notes"
    }
    missing = required.difference(row.keys())
    if missing:
        raise ValueError(f"missing fields: {sorted(missing)}")
    if not row["rmr_id"].startswith("RMR-"):
        raise ValueError("rmr_id invalid")
    if not row["case_id"].startswith("CASE-"):
        raise ValueError("case_id invalid")
    if len(row["input_hash"]) != 64:
        raise ValueError("input_hash invalid")
    if not set(row["reason_codes"]).issubset(REASON_CODES):
        raise ValueError("reason_codes invalid")
    if not set(row["why_not"]).issubset(WHY_NOT_CODES):
        raise ValueError("why_not invalid")
    if not isinstance(row["provider_calls"], list) or not row["provider_calls"]:
        raise ValueError("provider_calls missing")
    for call in row["provider_calls"]:
        validate_provider_call(call)
    if not (0 <= row["margin"] <= 1):
        raise ValueError("margin invalid")
    if not (0 <= row["confidence"] <= 1):
        raise ValueError("confidence invalid")
    if not is_rfc3339_z(row["timestamp"]):
        raise ValueError("timestamp invalid")

def validate_schema_examples(schema_path: str | Path) -> None:
    schema = load_json(schema_path)
    if schema.get("$schema") != "http://json-schema.org/draft-07/schema#":
        raise ValueError("schema must declare draft-07")
    examples = schema.get("examples", [])
    if len(examples) != 10:
        raise ValueError("schema must contain 10 examples")
    for row in examples:
        validate_rmr(row)

def validate_manifest_schema_digest(schema_path: str | Path, manifest_path: str | Path) -> None:
    manifest = load_json(manifest_path)
    actual = sha256_hex_path(Path(schema_path))
    expected = manifest["expected_schema_digest"]
    if actual != expected:
        raise SystemExit(EXIT_SCHEMA)

def validate_receipt_freshness(receipt_path: str | Path, manifest_path: str | Path) -> None:
    receipt = load_json(receipt_path)
    manifest = load_json(manifest_path)
    ts = datetime.fromisoformat(receipt["timestamp"].replace("Z", "+00:00"))
    ttl = int(manifest["ttl_seconds"])
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    if age > ttl:
        raise SystemExit(EXIT_FRESHNESS)

def validate_runtime_receipt(receipt_path: str | Path) -> None:
    obj = load_json(receipt_path)
    if not obj.get("provider_calls") or not obj.get("receipt", {}).get("signature"):
        raise SystemExit(EXIT_RUNTIME)

def validate_bundle(bundle_path: str | Path, sha_path: str | Path) -> None:
    bundle = Path(bundle_path)
    sha_file = Path(sha_path)
    actual = sha256_hex_path(bundle)
    listed = sha_file.read_text(encoding="utf-8").split()[0]
    if actual != listed:
        raise SystemExit(EXIT_PUBLISH)
    with tarfile.open(bundle, "r:gz") as tf:
        names = tf.getnames()
        if names != sorted(names):
            raise SystemExit(EXIT_PUBLISH)

def build_manifest_entries(root: Path, exclude: Iterable[str] = ()) -> List[Dict[str, Any]]:
    exclude = set(exclude)
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel in exclude:
            continue
        mime = mimetypes.guess_type(rel)[0] or "application/octet-stream"
        entries.append({
            "path": rel,
            "sha256": sha256_hex_path(path),
            "size_bytes": path.stat().st_size,
            "mime_type": mime,
        })
    return entries

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema")
    ap.add_argument("--manifest")
    ap.add_argument("--receipt")
    ap.add_argument("--bundle")
    ap.add_argument("--sha-file")
    ap.add_argument("--examples", action="store_true")
    args = ap.parse_args()

    if args.schema and args.examples:
        validate_schema_examples(args.schema)
    if args.schema and args.manifest:
        validate_manifest_schema_digest(args.schema, args.manifest)
    if args.receipt and args.manifest:
        validate_receipt_freshness(args.receipt, args.manifest)
    if args.receipt and not args.manifest:
        validate_runtime_receipt(args.receipt)
    if args.bundle and args.sha_file:
        validate_bundle(args.bundle, args.sha_file)
    return EXIT_SUCCESS

if __name__ == "__main__":
    raise SystemExit(main())
