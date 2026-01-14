"""
Builds a scrubbed, observer-only dataset for the KT_OBSERVER_B Phase 2.5 adapter.

Rules enforced (per kt_observer_b_manifest_vOmega13.yaml):
  - Drop prescriptive/imperative/optimization language.
  - Drop agency/future/action-selection language.
  - Reject any floating-point literals (prevents threshold leakage).
  - Drop forbidden keys that imply control/execution/targets.
  - Convert known scalars -> enums, then drop raw scalars.
  - Reject any record where floats survive after transforms.
  - Produce a build report with rejection reasons.

Outputs:
  observer_only.jsonl         (scrubbed records)
  kt_observer_b_build_report.json (counts + reject reasons)
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


@dataclass
class Reject:
    source: str
    line: int
    reason: str


def iter_jsonl(path: Path) -> Iterable[Tuple[int, Dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            yield idx, json.loads(line)


def has_float_literal(obj: Any) -> bool:
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(has_float_literal(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_float_literal(v) for v in obj)
    return False


def drop_keys_recursive(d: Any, forbidden_keys: set) -> Any:
    if isinstance(d, dict):
        return {k: drop_keys_recursive(v, forbidden_keys) for k, v in d.items() if k not in forbidden_keys}
    if isinstance(d, list):
        return [drop_keys_recursive(x, forbidden_keys) for x in d]
    return d


def bin_scalar(value: Any, bins: List[Dict[str, Any]]) -> str:
    if not isinstance(value, (int, float)):
        return "UNKNOWN"
    for b in bins:
        lt = b.get("lt")
        gte = b.get("gte")
        if lt is not None and gte is None and value < lt:
            return b["value"]
        if lt is not None and gte is not None and (value >= gte and value < lt):
            return b["value"]
        if lt is None and gte is not None and value >= gte:
            return b["value"]
    return "UNKNOWN"


def apply_scalar_to_enum(record: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    for scalar_key, spec in cfg.items():
        if scalar_key in record:
            out_key = spec["out_key"]
            record[out_key] = bin_scalar(record.get(scalar_key), spec["bins"])
    return record


def replace_floats(obj: Any, replacement: str = "FLOAT_REDACTED") -> Any:
    if isinstance(obj, float):
        return replacement
    if isinstance(obj, dict):
        return {k: replace_floats(v, replacement) for k, v in obj.items()}
    if isinstance(obj, list):
        return [replace_floats(x, replacement) for x in obj]
    return obj


NUMERIC_STRING_RX = re.compile(r"^[+-]?\d+(\.\d+)?$")


def sanitize_numeric_strings(obj: Any) -> Any:
    """Remove numeric-looking strings to prevent scalar leakage."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and NUMERIC_STRING_RX.match(v):
                # Drop numeric strings entirely (observer-only regime).
                continue
            out[k] = sanitize_numeric_strings(v)
        return out
    if isinstance(obj, list):
        return [sanitize_numeric_strings(x) for x in obj]
    return obj


def main(manifest_path: str, out_path: str, report_path: str) -> None:
    manifest = yaml.safe_load(Path(manifest_path).read_text(encoding="utf-8"))

    sources = manifest["source_artifacts"]
    forbidden_patterns = manifest["enforcement_layer"]["forbidden_patterns"]
    forbidden_keys = set(manifest["enforcement_layer"]["forbidden_keys"])

    rx_prescriptive = re.compile(forbidden_patterns["prescriptive_verbs"])
    rx_agency = re.compile(forbidden_patterns["causal_agency"])
    rx_floatlit = re.compile(forbidden_patterns["scalar_literals"])

    transforms = manifest["enforcement_layer"]["transformations"]
    scalar_to_enum_cfg = transforms.get("scalars_to_enums", {})
    drop_after = set(transforms.get("drop_keys_after_transform", []))

    rejects: List[Reject] = []
    kept: List[Dict[str, Any]] = []

    for src in sources:
        src_path = Path(src["path"])
        if not src_path.exists():
            raise FileNotFoundError(f"Missing source artifact: {src_path}")

        for line_no, record in iter_jsonl(src_path):
            # Drop numeric-looking strings up front (prevents scalar literals encoded as strings).
            record = sanitize_numeric_strings(record)
            raw_text = json.dumps(record, ensure_ascii=False)

            # Hard regex stops on raw text
            if rx_prescriptive.search(raw_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern:prescriptive_verbs"))
                continue
            if rx_agency.search(raw_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern:causal_agency"))
                continue
            # Transform scalars -> enums (only if scalars exist)
            record = apply_scalar_to_enum(record, scalar_to_enum_cfg)

            # Drop forbidden keys recursively
            record = drop_keys_recursive(record, forbidden_keys)

            # Drop scalar keys after transform
            for k in drop_after:
                record.pop(k, None)

            # Replace any remaining floats to keep observer-only output non-numeric.
            record = replace_floats(record)

            # Reject if any float values remain (even if not literal text)
            if has_float_literal(record):
                rejects.append(Reject(str(src_path), line_no, "float_value_survived"))
                continue

            # Second pass regex check post-transform and key-drop
            scrubbed_text = json.dumps(record, ensure_ascii=False)
            if rx_prescriptive.search(scrubbed_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern_post:prescriptive_verbs"))
                continue
            if rx_agency.search(scrubbed_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern_post:causal_agency"))
                continue
            if rx_floatlit.search(scrubbed_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern_post:scalar_literals"))
                continue

            kept.append(record)

    # Write outputs
    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("w", encoding="utf-8") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Build report
    report = {
        "dataset_build_id": manifest.get("dataset_build_id"),
        "kept_records": len(kept),
        "rejected_records": len(rejects),
        "rejects": [r.__dict__ for r in rejects[:200]],  # cap report size
        "notes": {
            "observer_outputs_never_targets": bool(
                manifest.get("training_rules", {}).get("no_model_outputs_as_targets", True)
            ),
            "lane_blindness_check": bool(manifest.get("validation_gate", {}).get("lane_blindness_check", True)),
            "honey_pot_injection": bool(manifest.get("validation_gate", {}).get("honey_pot_injection", True)),
        },
    }
    Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: build_observer_only_dataset.py <manifest.yaml> <out.jsonl> <report.json>")
    main(sys.argv[1], sys.argv[2], sys.argv[3])
