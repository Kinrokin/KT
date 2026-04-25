#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
source "${ROOT_DIR}/scripts/preflight_common.sh"

SEED=42
PACKET="${ROOT_DIR}/packet/residual_alpha_packet_spec.json"
WORK_DIR="${ROOT_DIR}/work/smoke"
LOG_DIR="${ROOT_DIR}/work/logs"
ARTIFACTS_DIR="$(cd "${ROOT_DIR}/.." && pwd)/artifacts"
mkdir -p "${WORK_DIR}" "${LOG_DIR}" "${ARTIFACTS_DIR}"
LOG_FILE="${LOG_DIR}/run_h1_smoke.log"

{
  echo "[INFO] Starting H1 smoke run"
  ensure_clean_worktree || exit $?
  ensure_schema_digest || exit $?
  ensure_receipt_fresh || exit $?
  ensure_multisig_count || exit $?
  ensure_clean_beta "${PACKET}" || exit $?
  ensure_no_holdout_leakage "${PACKET}" || exit $?
  python "${ROOT_DIR}/runtime/minimal_lobe_shim.py" --input "${PACKET}" --seed "${SEED}" --out "${WORK_DIR}/receipt.json"
  python "${ROOT_DIR}/scripts/anti_shortcut_detector.py" --input "${PACKET}" --json-out "${WORK_DIR}/invariance.json"
  "${ROOT_DIR}/scripts/proof_bundle_publish.sh" --mock --seed "${SEED}" --run-id "$(json_get "${MANIFEST_FILE}" run_id)" --inputs reports governance packet runtime docs >/tmp/proof_bundle_smoke.json
  python - "${ARTIFACTS_DIR}/smoke_path_receipt.json" "${WORK_DIR}/receipt.json" "${WORK_DIR}/invariance.json" "${PACKET}" "${MANIFEST_FILE}" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

out_path, runtime_receipt, invariance, packet, manifest = map(Path, sys.argv[1:6])
payload = {
    "__generated_by_agent__": True,
    "event": "track03_smoke_path",
    "status": "PASS",
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "runtime_receipt_sha256": hashlib.sha256(runtime_receipt.read_bytes()).hexdigest(),
    "invariance_sha256": hashlib.sha256(invariance.read_bytes()).hexdigest(),
    "packet_sha256": hashlib.sha256(packet.read_bytes()).hexdigest(),
    "manifest_digest": json.load(open(manifest, "r", encoding="utf-8"))["manifest_digest"],
}
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  cat /tmp/proof_bundle_smoke.json
  echo "[INFO] Smoke run completed successfully"
} > "${LOG_FILE}" 2>&1 || {
  code=$?
  echo "[ERROR] Smoke run failed with exit code ${code}" >> "${LOG_FILE}"
  exit ${code}
}
cat "${LOG_FILE}"
