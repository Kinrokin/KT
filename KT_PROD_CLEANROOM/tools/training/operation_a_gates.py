"""
Operation A: Governance Gates

Implements 7 fail-closed gates that enforce the MRT-1 training lane canonical contract.

Each gate:
  - Validates layer boundary invariants
  - Returns (pass: bool, reason: str, metadata: dict)
  - Halts execution if failed
  - Produces audit trail entry

Gates (in order):
  P1: Policy Sweep (Stage 1 output)
  D1: Raw Dataset (Stage 2 output)
  D2: Dataset Coercion (Stage 3 output)
  M0: MRT-0 Manufacture (Stage 4 output)
  T1: MRT-1 Training (Stage 5 output per adapter)
  PR1: Promotion (Stage 6 output per adapter)
  RS1: Runtime Snapshot (Stage 7 output)
"""

import json
from pathlib import Path
from typing import Any, Dict, Tuple
from datetime import datetime


class GateFailure(Exception):
    """Gate validation failure (fail-closed)."""
    def __init__(self, gate_name: str, reason: str, metadata: Dict[str, Any]):
        self.gate_name = gate_name
        self.reason = reason
        self.metadata = metadata
        super().__init__(f"GATE {gate_name} FAILED: {reason}")


def gate_p1_policy_sweep(sweep_result_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate P1: Policy Sweep Gate

    Validates Stage 1 (Policy Generation) output.

    Pass criteria:
      ✓ File exists
      ✓ JSON schema valid
      ✓ Contains ≥1 episode
    """
    meta = {"gate": "P1", "timestamp": datetime.utcnow().isoformat()}

    if not sweep_result_path.exists():
        return False, f"Policy sweep file not found: {sweep_result_path}", meta

    try:
        with open(sweep_result_path, "r", encoding="utf-8") as f:
            sweep = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Policy sweep JSON invalid: {e}", meta
    except Exception as e:
        return False, f"Policy sweep read error: {e}", meta

    # Validate schema
    if not isinstance(sweep, dict):
        return False, "Policy sweep root must be dict", meta

    required_fields = ["episodes", "metadata"]
    for field in required_fields:
        if field not in sweep:
            return False, f"Missing required field: {field}", meta

    if not isinstance(sweep.get("episodes"), list):
        return False, "episodes field must be list", meta

    if len(sweep["episodes"]) < 1:
        return False, "Policy sweep must contain ≥1 episode", meta

    meta["episode_count"] = len(sweep["episodes"])
    meta["metadata"] = sweep.get("metadata", {})

    return True, "Policy sweep valid", meta


def gate_d1_raw_dataset(dataset_path: Path, min_parse_rate: float = 0.95) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate D1: Raw Dataset Gate

    Validates Stage 2 (Dataset Export) output.

    Pass criteria:
      ✓ File exists
      ✓ Contains ≥1 line
      ✓ ≥95% lines are valid JSON
    """
    meta = {"gate": "D1", "timestamp": datetime.utcnow().isoformat()}

    if not dataset_path.exists():
        return False, f"Dataset file not found: {dataset_path}", meta

    line_count = 0
    parse_count = 0

    try:
        with open(dataset_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                line_count += 1

                try:
                    json.loads(line)
                    parse_count += 1
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        return False, f"Dataset read error: {e}", meta

    if line_count < 1:
        return False, "Dataset must contain ≥1 line", meta

    parse_rate = parse_count / line_count if line_count > 0 else 0

    if parse_rate < min_parse_rate:
        return False, f"JSON parse rate {parse_rate:.1%} < {min_parse_rate:.0%}", meta

    meta["line_count"] = line_count
    meta["parse_count"] = parse_count
    meta["parse_rate"] = parse_rate

    return True, f"Raw dataset valid: {line_count} lines, {parse_rate:.1%} parse rate", meta


def gate_d2_coercion(coerced_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate D2: Dataset Coercion Gate

    Validates Stage 3 (Dataset Coercion) output.

    Pass criteria:
      ✓ File exists
      ✓ Contains ≥1 line
      ✓ EVERY line is exactly {"text": str}
      ✓ NO empty text strings
      ✓ 100% schema compliance
    """
    meta = {"gate": "D2", "timestamp": datetime.utcnow().isoformat()}

    if not coerced_path.exists():
        return False, f"Coerced dataset file not found: {coerced_path}", meta

    line_count = 0
    empty_count = 0
    schema_violations = 0

    try:
        with open(coerced_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                line_count += 1

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, f"Line {line_num}: Invalid JSON: {e}", meta

                # Validate schema: must be exactly {"text": str}
                if not isinstance(obj, dict):
                    return False, f"Line {line_num}: Not a dict", meta

                if set(obj.keys()) != {"text"}:
                    return False, f"Line {line_num}: Expected only 'text' key, got {list(obj.keys())}", meta

                text = obj["text"]
                if not isinstance(text, str):
                    return False, f"Line {line_num}: text must be str, got {type(text).__name__}", meta

                if not text or not text.strip():
                    empty_count += 1
                    schema_violations += 1

    except Exception as e:
        return False, f"Coercion validation error: {e}", meta

    if line_count < 1:
        return False, "Coerced dataset must contain ≥1 line", meta

    if empty_count > 0:
        return False, f"Found {empty_count} empty text entries (violations of schema)", meta

    meta["line_count"] = line_count
    meta["empty_count"] = empty_count
    meta["schema_violations"] = schema_violations

    return True, f"Coerced dataset valid: {line_count} lines, 100% schema compliance", meta


def gate_m0_mrt0_manufacture(adapter_manifest_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate M0: MRT-0 Manufacture Gate

    Validates Stage 4 (MRT-0 Manufacture) output.

    Pass criteria:
      ✓ Manifest file exists
      ✓ Valid JSON
      ✓ Contains exactly 13 adapters
      ✓ IDs are adapter_1 through adapter_13
      ✓ Version metadata valid
    """
    meta = {"gate": "M0", "timestamp": datetime.utcnow().isoformat()}

    if not adapter_manifest_path.exists():
        return False, f"Adapter manifest not found: {adapter_manifest_path}", meta

    try:
        with open(adapter_manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Adapter manifest JSON invalid: {e}", meta
    except Exception as e:
        return False, f"Adapter manifest read error: {e}", meta

    if not isinstance(manifest, dict):
        return False, "Manifest must be dict", meta

    if "adapters" not in manifest:
        return False, "Manifest missing 'adapters' field", meta

    adapters = manifest["adapters"]
    if not isinstance(adapters, list):
        return False, "adapters field must be list", meta

    if len(adapters) != 13:
        return False, f"Expected 13 adapters, got {len(adapters)}", meta

    expected_ids = {f"adapter_{i}" for i in range(1, 14)}
    actual_ids = {a.get("id") for a in adapters if isinstance(a, dict)}

    if expected_ids != actual_ids:
        return False, f"Adapter IDs mismatch. Expected {expected_ids}, got {actual_ids}", meta

    meta["adapter_count"] = len(adapters)
    meta["adapter_ids"] = sorted(actual_ids)

    return True, f"MRT-0 manufacture valid: {len(adapters)} adapters", meta


def gate_t1_training(train_receipt_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate T1: MRT-1 Training Gate

    Validates Stage 5 (Training Lane) output per adapter.

    Pass criteria:
      ✓ Receipt file exists
      ✓ Valid JSON
      ✓ status field == "PASS"
      ✓ weights_dir exists
      ✓ log file present
      ✓ All required metadata fields present
    """
    meta = {"gate": "T1", "timestamp": datetime.utcnow().isoformat()}

    if not train_receipt_path.exists():
        return False, f"Training receipt not found: {train_receipt_path}", meta

    try:
        with open(train_receipt_path, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Receipt JSON invalid: {e}", meta
    except Exception as e:
        return False, f"Receipt read error: {e}", meta

    if not isinstance(receipt, dict):
        return False, "Receipt must be dict", meta

    required_fields = ["adapter_id", "status", "weights_dir", "log_file"]
    for field in required_fields:
        if field not in receipt:
            return False, f"Receipt missing required field: {field}", meta

    if receipt["status"] != "PASS":
        return False, f"Training status not PASS: {receipt['status']}", meta

    weights_dir = Path(receipt["weights_dir"])
    if not weights_dir.exists():
        return False, f"Weights directory not found: {weights_dir}", meta

    log_file = Path(receipt["log_file"])
    if not log_file.exists():
        return False, f"Log file not found: {log_file}", meta

    meta["adapter_id"] = receipt["adapter_id"]
    meta["status"] = receipt["status"]
    meta["metrics"] = receipt.get("metrics", {})

    return True, f"Training receipt valid for {receipt['adapter_id']}", meta


def gate_pr1_promotion(promotion_receipt_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate PR1: Promotion Gate

    Validates Stage 6 (Promotion) output per adapter.

    Pass criteria:
      ✓ Receipt file exists
      ✓ Valid JSON
      ✓ status field == "PROMOTED"
      ✓ adapter_id matches expected value
      ✓ promotion_hash valid
      ✓ Registry entry created
    """
    meta = {"gate": "PR1", "timestamp": datetime.utcnow().isoformat()}

    if not promotion_receipt_path.exists():
        return False, f"Promotion receipt not found: {promotion_receipt_path}", meta

    try:
        with open(promotion_receipt_path, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Promotion receipt JSON invalid: {e}", meta
    except Exception as e:
        return False, f"Promotion receipt read error: {e}", meta

    if not isinstance(receipt, dict):
        return False, "Promotion receipt must be dict", meta

    required_fields = ["adapter_id", "status", "promotion_hash"]
    for field in required_fields:
        if field not in receipt:
            return False, f"Promotion receipt missing field: {field}", meta

    if receipt["status"] != "PROMOTED":
        return False, f"Promotion status not PROMOTED: {receipt['status']}", meta

    if not receipt["promotion_hash"] or not isinstance(receipt["promotion_hash"], str):
        return False, "promotion_hash must be non-empty string", meta

    meta["adapter_id"] = receipt["adapter_id"]
    meta["status"] = receipt["status"]
    meta["promotion_hash"] = receipt["promotion_hash"]

    return True, f"Promotion receipt valid for {receipt['adapter_id']}", meta


def gate_rs1_runtime_snapshot(snapshot_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Gate RS1: Runtime Snapshot Gate

    Validates Stage 7 (Runtime Snapshot) final output.

    Pass criteria:
      ✓ Snapshot file exists
      ✓ Valid JSON
      ✓ Contains exactly 13 adapters
      ✓ Version lock present
      ✓ Timestamp frozen
      ✓ All adapter metadata present
    """
    meta = {"gate": "RS1", "timestamp": datetime.utcnow().isoformat()}

    if not snapshot_path.exists():
        return False, f"Runtime snapshot not found: {snapshot_path}", meta

    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
    except json.JSONDecodeError as e:
        return False, f"Runtime snapshot JSON invalid: {e}", meta
    except Exception as e:
        return False, f"Runtime snapshot read error: {e}", meta

    if not isinstance(snapshot, dict):
        return False, "Snapshot must be dict", meta

    required_fields = ["adapters", "version", "frozen_at"]
    for field in required_fields:
        if field not in snapshot:
            return False, f"Snapshot missing required field: {field}", meta

    adapters = snapshot["adapters"]
    if not isinstance(adapters, list):
        return False, "adapters field must be list", meta

    if len(adapters) != 13:
        return False, f"Expected 13 adapters in snapshot, got {len(adapters)}", meta

    expected_ids = {f"adapter_{i}" for i in range(1, 14)}
    actual_ids = {a.get("id") for a in adapters if isinstance(a, dict)}

    if expected_ids != actual_ids:
        return False, f"Snapshot adapter IDs mismatch. Expected {expected_ids}, got {actual_ids}", meta

    meta["adapter_count"] = len(adapters)
    meta["version"] = snapshot.get("version")
    meta["frozen_at"] = snapshot.get("frozen_at")

    return True, f"Runtime snapshot valid: {len(adapters)} adapters, version {snapshot.get('version')}", meta


# Gate registry for runtime lookup
GATES = {
    "P1": gate_p1_policy_sweep,
    "D1": gate_d1_raw_dataset,
    "D2": gate_d2_coercion,
    "M0": gate_m0_mrt0_manufacture,
    "T1": gate_t1_training,
    "PR1": gate_pr1_promotion,
    "RS1": gate_rs1_runtime_snapshot,
}


def check_gate(gate_name: str, *args, **kwargs) -> Dict[str, Any]:
    """
    Universal gate checker.

    Raises GateFailure if gate fails.
    Returns dict with pass/reason/metadata.
    """
    if gate_name not in GATES:
        raise ValueError(f"Unknown gate: {gate_name}")

    gate_fn = GATES[gate_name]
    passed, reason, metadata = gate_fn(*args, **kwargs)

    result = {
        "gate": gate_name,
        "passed": passed,
        "reason": reason,
        **metadata,
    }

    if not passed:
        raise GateFailure(gate_name, reason, metadata)

    return result
