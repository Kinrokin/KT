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
from tools.growth.utils.normalize_jsonl import normalize_jsonl

KT_ROOT = Path(__file__).resolve().parents[4]


def resolve_source_path(src_path: str, kt_root: Path) -> Path:
    p = Path(src_path)
    if p.is_absolute():
        return p
    if p.parts and p.parts[0] == "KT_PROD_CLEANROOM":
        return (kt_root / p).resolve()
    return (kt_root / "KT_PROD_CLEANROOM" / p).resolve()


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


NUMERIC_STRING_RX = re.compile(r"^\s*-?\d+(\.\d+)?\s*$")


def _is_numeric_string(value: str) -> bool:
    return bool(NUMERIC_STRING_RX.match(value))


def scrub_numerics(obj: Any) -> Any:
    """
    Fail-closed safety scrub:
      - Drops all int/float values.
      - Drops any string that looks numeric.
      - Preserves booleans, enums, and non-numeric text.
    """
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return None
    if isinstance(obj, str):
        return None if _is_numeric_string(obj) else obj
    if isinstance(obj, list):
        out_list = []
        for entry in obj:
            cleaned = scrub_numerics(entry)
            if cleaned is not None:
                out_list.append(cleaned)
        return out_list
    if isinstance(obj, dict):
        out_dict = {}
        for key, value in obj.items():
            cleaned = scrub_numerics(value)
            if cleaned is None:
                continue
            out_dict[key] = cleaned
        return out_dict
    return str(obj)


def assert_no_numerics(obj: Any) -> None:
    if isinstance(obj, bool):
        return
    if isinstance(obj, (int, float)):
        raise ValueError("numeric literal survived scrub")
    if isinstance(obj, str) and _is_numeric_string(obj):
        raise ValueError("numeric string survived scrub")
    if isinstance(obj, list):
        for entry in obj:
            assert_no_numerics(entry)
    if isinstance(obj, dict):
        for value in obj.values():
            assert_no_numerics(value)


def contains_scalar_literal(obj: Any) -> bool:
    if isinstance(obj, bool):
        return False
    if isinstance(obj, (int, float)):
        return True
    if isinstance(obj, str):
        return _is_numeric_string(obj)
    if isinstance(obj, list):
        return any(contains_scalar_literal(entry) for entry in obj)
    if isinstance(obj, dict):
        return any(contains_scalar_literal(value) for value in obj.values())
    return False


CONTROL_LEAK_KEYS = {
    "confidence",
    "policy_confidence",
    "policy_distribution",
    "entropy",
    "temperature",
    "curvature",
    "novelty_pressure",
    "risk_pressure",
    "time_pressure",
    "verification_pressure",
    "proof_density",
    "paradox_pressure",
    "forced_resolve_count",
    "low_coherence_count",
    "delayed_violation_count",
    "regret_pressure",
    "regret_global",
    "regret_prev_global",
    "coverage_fatigue",
    "coverage_cost",
    "coverage_streak",
}

FORBIDDEN_SCHEMAS = {
    "KT_PHASE_A2_DATASET_V1",
    "KT_PHASE_A2_DATASET",
}


def is_observer_eligible(record: Dict[str, Any]) -> bool:
    schema = record.get("schema")
    if schema in FORBIDDEN_SCHEMAS:
        return False
    return True


def build_observer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Re-materialize a minimal observer-only record.
    Never forward execution/control fields from source artifacts.
    """
    epoch_ref = record.get("epoch_id") or record.get("epoch_ref") or record.get("row_id")
    return {
        "schema": "KT_OBSERVER_B_RECORD_V1",
        "record_type": "observer",
        "source_schema": record.get("schema"),
        "epoch_ref": epoch_ref,
        "epoch_hash": record.get("epoch_hash"),
        "epoch_profile": record.get("epoch_profile"),
        "epoch_verdict": record.get("epoch_verdict"),
        "lane_intent": record.get("lane_intent_enum") or record.get("lane_intent"),
        "triggered_rules": record.get("triggered_rules") or record.get("triggered") or [],
        "constraints": record.get("constraints") or {},
        "signals_enum": record.get("signals_enum") or {},
        "stability": record.get("stability_enum") or record.get("stability"),
    }


def main(manifest_path: str, out_path: str, report_path: str) -> None:
    manifest = yaml.safe_load(Path(manifest_path).read_text(encoding="utf-8"))

    contract = manifest.get("serialization_contract", {})
    if contract.get("format") != "JSONL" or not contract.get("one_object_per_line", False):
        raise RuntimeError("Dataset manifest missing JSONL serialization contract (fail-closed)")

    sources = manifest["source_artifacts"]
    forbidden_patterns = manifest["enforcement_layer"]["forbidden_patterns"]
    forbidden_keys = set(manifest["enforcement_layer"]["forbidden_keys"])
    forbidden_keys |= CONTROL_LEAK_KEYS

    rx_prescriptive = re.compile(forbidden_patterns["prescriptive_verbs"])
    rx_agency = re.compile(forbidden_patterns["causal_agency"])

    transforms = manifest["enforcement_layer"]["transformations"]
    scalar_to_enum_cfg = transforms.get("scalars_to_enums", {})
    drop_after = set(transforms.get("drop_keys_after_transform", []))

    rejects: List[Reject] = []
    kept: List[Dict[str, Any]] = []

    for src in sources:
        src_path = resolve_source_path(src["path"], KT_ROOT)
        if not src_path.exists():
            raise FileNotFoundError(f"Missing source artifact: {src_path}")
        # Guardrail: normalize inputs to strict JSONL before reading.
        normalize_jsonl(src_path, src_path)

        for line_no, record in iter_jsonl(src_path):
            if not is_observer_eligible(record):
                rejects.append(Reject(str(src_path), line_no, "non_observer_schema"))
                continue
            record = build_observer_record(record)
            # Canonical order: drop mechanics -> project enums -> scrub numerics -> then regex checks.
            record = drop_keys_recursive(record, forbidden_keys)
            record = apply_scalar_to_enum(record, scalar_to_enum_cfg)
            for k in drop_after:
                record.pop(k, None)
            record = scrub_numerics(record)
            assert_no_numerics(record)

            scrubbed_text = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            if rx_prescriptive.search(scrubbed_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern_post:prescriptive_verbs"))
                continue
            if rx_agency.search(scrubbed_text):
                rejects.append(Reject(str(src_path), line_no, "forbidden_pattern_post:causal_agency"))
                continue
            if contains_scalar_literal(record):
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
            "transform_order": "drop_keys -> enum_projection -> scrub_numerics -> forbidden_patterns",
        },
    }
    Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: build_observer_only_dataset.py <manifest.yaml> <out.jsonl> <report.json>")
    main(sys.argv[1], sys.argv[2], sys.argv[3])
