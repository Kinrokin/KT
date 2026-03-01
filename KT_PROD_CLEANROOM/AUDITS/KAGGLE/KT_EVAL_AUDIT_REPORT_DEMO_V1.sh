#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-$(pwd)}"
RUN_DIR="${RUN_DIR:-$ROOT/tmp/eval_audit_report_demo_$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$RUN_DIR"

export PYTHONPATH="$ROOT/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$ROOT/KT_PROD_CLEANROOM"

SUITE_DEF="KT_PROD_CLEANROOM/AUDITS/SUITES/SUITE_FORMAT_CONTROL.v1.json"
SUITE_OUT="$RUN_DIR/suite_outputs.json"
EVAL_OUT="$RUN_DIR/eval_out"
AUDIT_OUT="$RUN_DIR/audit_out"

echo "=== Build canned suite_outputs (format control) ==="
python - <<'PY'
import hashlib, json, sys
from pathlib import Path

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.verification.fl3_validators import validate_schema_bound_object

suite_def_path = Path(sys.argv[1]).resolve()
out_path = Path(sys.argv[2]).resolve()

suite_root_hash = sha256_file_canonical(suite_def_path)

outputs_by_case = {
    "F01_JSON_EXACT": "{\"a\":1,\"b\":2,\"c\":3}",
    "F02_4_SENTENCES": "One. Two. Three. Four.",
    "F03_2_BULLETS": "- a\\n- b",
}

rows = []
for case_id in sorted(outputs_by_case.keys()):
    txt = outputs_by_case[case_id]
    rows.append({"case_id": case_id, "output_text": txt, "output_sha256": hashlib.sha256(txt.encode(\"utf-8\")).hexdigest()})

obj = {
    "schema_id": "kt.suite_outputs.v1",
    "schema_version_hash": schema_version_hash("fl3/kt.suite_outputs.v1.json"),
    "suite_outputs_id": "",
    "base_model_id": "mistral-7b",
    "subject": {"subject_kind": "ADAPTER", "subject_id": "lobe.architect.v1", "adapter_root_hash": None},
    "suite_id": "SUITE_FORMAT_CONTROL",
    "suite_root_hash": suite_root_hash,
    "decode_policy_id": "greedy_v1",
    "decode_cfg_hash": "0" * 64,
    "outputs": rows,
    "created_at": "1970-01-01T00:00:00Z",
    "notes": None,
}
obj["suite_outputs_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "suite_outputs_id"})
validate_schema_bound_object(obj)
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + \"\\n\", encoding=\"utf-8\", newline=\"\\n\")
print(out_path.as_posix())
PY "$SUITE_DEF" "$SUITE_OUT"

echo "=== EPIC_17: run suite eval (WORM) ==="
python -m tools.eval.run_suite_eval --suite-def "$SUITE_DEF" --suite-outputs "$SUITE_OUT" --out-dir "$EVAL_OUT"

echo "=== EPIC_18: generate consolidated audit eval report (WORM) ==="
python -m tools.verification.generate_audit_eval_report \
  --run-id "AUDIT_REPORT_DEMO_V1" \
  --suite-def "$SUITE_DEF" \
  --suite-eval-report "$EVAL_OUT/suite_eval_report.json" \
  --axis-fitness-report "$EVAL_OUT/axis_fitness_report.json" \
  --out-dir "$AUDIT_OUT" \
  --attestation-mode SIMULATED

echo "DONE. Artifacts in: $RUN_DIR"

