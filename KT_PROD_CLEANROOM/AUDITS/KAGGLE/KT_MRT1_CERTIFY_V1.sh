#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-$(pwd)}"
RUN_DIR="${RUN_DIR:-$ROOT/tmp/mrt1_certify_$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$RUN_DIR"

export PYTHONPATH="$ROOT/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$ROOT/KT_PROD_CLEANROOM"

echo "RUN_DIR=$RUN_DIR"
echo "GIT_SHA=$(git rev-parse HEAD 2>/dev/null || echo unknown)"

echo "=== Batteries (tests) ==="
python -m pytest -q KT_PROD_CLEANROOM/tests
python -m pytest -q KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests
python -m pytest -q KT_PROD_CLEANROOM/tools/verification/tests

echo "=== Meta-evaluator (non-canonical lane) ==="
python -m tools.verification.fl3_meta_evaluator

echo "=== Meta-evaluator (canonical lane) ==="
KT_CANONICAL_LANE=1 python -m tools.verification.fl3_meta_evaluator

echo "=== Deterministic organ contract (WORM) ==="
python -m tools.verification.mk_min_organ_contract --out "$RUN_DIR/organ_contract.json"

echo "=== Determinism canary (run twice) ==="
python -m tools.verification.fl4_determinism_canary \
  --organ-contract "$RUN_DIR/organ_contract.json" \
  --out "$RUN_DIR/canary_artifact_pre.json"

python -m tools.verification.fl4_determinism_canary \
  --organ-contract "$RUN_DIR/organ_contract.json" \
  --out "$RUN_DIR/canary_artifact_rerun.json"

python - <<'PY'
import json, sys
from pathlib import Path

p1 = Path(sys.argv[1])
p2 = Path(sys.argv[2])
a = json.loads(p1.read_text(encoding="utf-8"))
b = json.loads(p2.read_text(encoding="utf-8"))
ha = a.get("hash_manifest_root_hash")
hb = b.get("hash_manifest_root_hash")
print(f"canary_pre_root_hash={ha}")
print(f"canary_rerun_root_hash={hb}")
if ha != hb:
    raise SystemExit("FAIL_CLOSED: determinism canary mismatch")
print("PASS: determinism canary rerun matched")
PY "$RUN_DIR/canary_artifact_pre.json" "$RUN_DIR/canary_artifact_rerun.json"

echo "DONE. Artifacts in: $RUN_DIR"

