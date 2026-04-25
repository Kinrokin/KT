#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
source "${ROOT_DIR}/scripts/preflight_common.sh"

SEED=42
DEFAULT_PACKET="${ROOT_DIR}/packet/residual_alpha_packet_spec.json"
PACKET="${DEFAULT_PACKET}"
WORK_DIR="${ROOT_DIR}/work/counted"
LOG_DIR="${ROOT_DIR}/work/logs"
ROLLBACK_DIR="${ROOT_DIR}/work/rollback"
ARTIFACTS_DIR="$(cd "${ROOT_DIR}/.." && pwd)/artifacts"
mkdir -p "${WORK_DIR}" "${LOG_DIR}" "${ROLLBACK_DIR}" "${ARTIFACTS_DIR}"
LOG_FILE="${LOG_DIR}/run_h1_counted.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) PACKET="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 99 ;;
  esac
done

rollback() {
  local reason="$1"
  printf "[ROLLBACK] %s\n" "${reason}" >> "${LOG_FILE}"
  rm -rf "${WORK_DIR}/current"
  mkdir -p "${ROLLBACK_DIR}"
  if [[ -f "${PACKET}" ]]; then cp "${PACKET}" "${ROLLBACK_DIR}/last_input.json"; fi
}

{
  echo "[INFO] Starting counted H1 run"
  ensure_clean_worktree || exit $?
  if [[ "${PACKET}" == "${DEFAULT_PACKET}" ]]; then
    ensure_smoke_completed || exit $?
    ensure_counted_unused || exit $?
  fi
  ensure_schema_digest || exit $?
  ensure_receipt_fresh || exit $?
  ensure_multisig_count || exit $?
  ensure_clean_beta "${PACKET}" || exit $?
  ensure_no_holdout_leakage "${PACKET}" || exit $?
  mkdir -p "${WORK_DIR}/current"
  python "${ROOT_DIR}/runtime/minimal_lobe_shim.py" --input "${PACKET}" --seed "${SEED}" --out "${WORK_DIR}/current/receipt.json"
  python - "${WORK_DIR}/current/receipt.json" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
if not obj.get("provider_calls") or not obj.get("receipt", {}).get("signature"):
    raise SystemExit(60)
PY
  python "${ROOT_DIR}/scripts/anti_shortcut_detector.py" --input "${PACKET}" --json-out "${WORK_DIR}/current/invariance.json"
  "${ROOT_DIR}/scripts/proof_bundle_publish.sh" --mock --seed "${SEED}" --run-id "$(json_get "${MANIFEST_FILE}" run_id)" --inputs reports governance packet runtime docs >/tmp/proof_bundle_counted.json
  if [[ "${PACKET}" == "${DEFAULT_PACKET}" ]]; then
    python - "${ARTIFACTS_DIR}/counted_path_receipt.json" "${WORK_DIR}/current/receipt.json" "${WORK_DIR}/current/invariance.json" "${PACKET}" "${MANIFEST_FILE}" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

out_path, runtime_receipt, invariance, packet, manifest = map(Path, sys.argv[1:6])
payload = {
    "__generated_by_agent__": True,
    "event": "track03_counted_path",
    "status": "PASS",
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "runtime_receipt_sha256": hashlib.sha256(runtime_receipt.read_bytes()).hexdigest(),
    "invariance_sha256": hashlib.sha256(invariance.read_bytes()).hexdigest(),
    "packet_sha256": hashlib.sha256(packet.read_bytes()).hexdigest(),
    "manifest_digest": json.load(open(manifest, "r", encoding="utf-8"))["manifest_digest"],
}
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  fi
  cat /tmp/proof_bundle_counted.json
  echo "[INFO] Counted H1 run completed successfully"
} > "${LOG_FILE}" 2>&1 || {
  code=$?
  rollback "counted run failed with exit code ${code}"
  echo "[ERROR] Counted run failed with exit code ${code}" >> "${LOG_FILE}"
  exit ${code}
}
cat "${LOG_FILE}"
