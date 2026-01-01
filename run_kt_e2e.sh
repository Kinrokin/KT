#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "KT END-TO-END EXECUTION (FAIL-CLOSED)"
echo "========================================"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ARTIFACTS="$ROOT/KT_PROD_CLEANROOM/tools/growth/artifacts"

echo "[0] Sanity checks"

python --version >/dev/null
test -d KT_PROD_CLEANROOM || { echo "Missing KT_PROD_CLEANROOM"; exit 1; }

mkdir -p "$ARTIFACTS"

echo "----------------------------------------"
echo "[1] Single Crucible (C019)"
echo "----------------------------------------"

python KT_PROD_CLEANROOM/tools/growth/crucible_runner.py \
  --crucible KT_PROD_CLEANROOM/tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml \
  --kernel V2_SOVEREIGN \
  --seed 0

echo "----------------------------------------"
echo "[2] Epoch Orchestration (C018)"
echo "----------------------------------------"

EPOCH_PLAN="KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json"
EPOCH_ID="EPOCH-0001-GOV-HONESTY"
EPOCH_DIR="$ARTIFACTS/epochs/$EPOCH_ID"
EPOCH_SUMMARY="$EPOCH_DIR/epoch_summary.json"

if [[ -f "$EPOCH_SUMMARY" ]]; then
  echo "[2] Epoch already present (append-only): $EPOCH_SUMMARY"
else
  python KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py \
    --epoch "$EPOCH_PLAN" \
    --resume
fi

echo "----------------------------------------"
echo "[3] Evaluation + Drift / Paradox Metrics (C023+)"
echo "----------------------------------------"

EVAL_PLUS_OUT="$ARTIFACTS/eval_harness_plus/${EPOCH_ID}.eval_plus.json"
mkdir -p "$(dirname "$EVAL_PLUS_OUT")"

python KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py \
  --epoch-dir "$EPOCH_DIR" \
  --epoch-id "$EPOCH_ID" \
  --out "$EVAL_PLUS_OUT" \
  --allow-existing

echo "----------------------------------------"
echo "[4] Teacher Factory (C021)"
echo "----------------------------------------"

PACKAGE_JSON="$(
python - <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

repo = Path.cwd()
bundle_path = repo / "KT_PROD_CLEANROOM/tools/growth/teacher_factory/bundles/BUNDLE-GOV-HONESTY-01.json"
out_dir = repo / "KT_PROD_CLEANROOM/tools/growth/artifacts/curriculum"
out_dir.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str((repo / "KT_PROD_CLEANROOM/tools/growth/teacher_factory").resolve()))
from curriculum_compiler import compile_bundle  # noqa: E402
from curriculum_signer import sign_package  # noqa: E402
from teacher_schemas import CurriculumPackageSchema, CurriculumSignatureSchema  # noqa: E402

compiled = compile_bundle(bundle_path)
pkg = compiled.package

pkg_obj = pkg.to_dict()
package_id = pkg_obj.get("package_id")
if not isinstance(package_id, str) or not package_id:
    raise SystemExit("package_id_missing (fail-closed)")

pkg_path = out_dir / f"{package_id}.json"
if pkg_path.exists():
    existing = json.loads(pkg_path.read_text(encoding="utf-8"))
    CurriculumPackageSchema.validate(existing)
else:
    pkg_path.write_text(
        json.dumps(pkg.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

signed = sign_package(package=pkg)
sig_path = out_dir / f"{package_id}.signature.json"
if sig_path.exists():
    existing = json.loads(sig_path.read_text(encoding="utf-8"))
    CurriculumSignatureSchema.validate(existing)
else:
    sig_path.write_text(
        json.dumps(signed.signature.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

print(pkg_path.as_posix())
PY
)"

echo "[4] Curriculum package: $PACKAGE_JSON"

echo "----------------------------------------"
echo "[5] Dream Loop (C020)"
echo "----------------------------------------"

DREAM_ID="DREAM-GOV-HONESTY-01"
DREAM_SPEC="$ARTIFACTS/dream_loop/${DREAM_ID}.json"
DREAM_RESULT="$ARTIFACTS/dream_loop/${DREAM_ID}/dream_result.json"
mkdir -p "$ARTIFACTS/dream_loop"

if [[ -f "$DREAM_RESULT" ]]; then
  echo "[5] Dream already present (append-only): $DREAM_RESULT"
else
  if [[ ! -f "$DREAM_SPEC" ]]; then
    cat > "$DREAM_SPEC" <<'JSON'
{
  "schema": "kt.dream.spec",
  "schema_version": 1,
  "dream_id": "DREAM-GOV-HONESTY-01",
  "hypothesis": "Governance honesty under refusal pressure; evidence-first; replay required.",
  "kernel_target": "V2_SOVEREIGN",
  "seed": 0,
  "candidate_bounds": {
    "max_candidates": 2,
    "max_hypothesis_chars": 1024,
    "max_prompt_chars": 32768
  },
  "budget_caps": {
    "time_ms": 20000,
    "stdout_max_bytes": 200000,
    "stderr_max_bytes": 200000,
    "runner_memory_max_mb": 1024,
    "kernel_timeout_kill_ms": 20500
  }
}
JSON
  fi

  python KT_PROD_CLEANROOM/tools/growth/dream_loop/dream_runner.py \
    --spec "$DREAM_SPEC"
fi

echo "----------------------------------------"
echo "[6] Training Warehouse (C024)"
echo "----------------------------------------"

python - <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

repo = Path.cwd()
artifacts = (repo / "KT_PROD_CLEANROOM/tools/growth/artifacts").resolve()
warehouse = (artifacts / "training_warehouse").resolve()
warehouse.mkdir(parents=True, exist_ok=True)

epoch_id = "EPOCH-0001-GOV-HONESTY"
crucible_id = "CRU-GOV-HONESTY-01"
kernel_target = "V2_SOVEREIGN"

run_record = artifacts / "epochs" / epoch_id / crucible_id / "run_record.json"
rr = json.loads(run_record.read_text(encoding="utf-8"))
run_id = rr.get("run_id")
if not isinstance(run_id, str) or len(run_id) != 64:
    raise SystemExit("run_id_missing_or_invalid (fail-closed)")

c019_run_dir = artifacts / "c019_runs" / kernel_target / run_id
if not c019_run_dir.exists():
    raise SystemExit("c019_run_dir_missing (fail-closed)")

crucible_spec_path = (repo / "KT_PROD_CLEANROOM/tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml").resolve()

sys.path.insert(0, str((repo / "KT_PROD_CLEANROOM/tools/growth/training_warehouse").resolve()))
from warehouse_store import append_exemplar_to_warehouse, create_exemplar_from_c019_run  # noqa: E402

exemplar, exemplar_path = create_exemplar_from_c019_run(
    artifacts_root=warehouse,
    kernel_target=kernel_target,
    epoch_id=epoch_id,
    crucible_id=crucible_id,
    run_id=run_id,
    crucible_spec_path=crucible_spec_path,
    c019_run_dir=c019_run_dir,
    license="UNKNOWN",
)
append_exemplar_to_warehouse(artifacts_root=warehouse, exemplar_path=exemplar_path)
print((warehouse / "warehouse_manifest.jsonl").as_posix())
PY

echo "----------------------------------------"
echo "[7] Distillation (C025)"
echo "----------------------------------------"

mkdir -p "$ARTIFACTS/distillation"

python KT_PROD_CLEANROOM/tools/growth/distillation/distill_runner.py \
  --warehouse-manifest "$ARTIFACTS/training_warehouse/warehouse_manifest.jsonl" \
  --out-dir "$ARTIFACTS/distillation/DISTILL-0001" \
  --allow-existing

echo "========================================"
echo "KT E2E RUN COMPLETE — ALL PHASES PASS"
echo "========================================"
