#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${ROOT:-$(pwd)}"
RUN_DIR="${RUN_DIR:-$ROOT/tmp/router_hat_demo_$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$RUN_DIR"

export PYTHONPATH="$ROOT/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$ROOT/KT_PROD_CLEANROOM"

python -m tools.router.run_router_hat_demo \
  --policy "KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_POLICY_HAT_V1.json" \
  --suite "KT_PROD_CLEANROOM/AUDITS/ROUTER/ROUTER_DEMO_SUITE_V1.json" \
  --run-id "ROUTER_HAT_DEMO_V1" \
  --out-dir "$RUN_DIR"

echo "DONE. Artifacts in: $RUN_DIR"

