#!/usr/bin/env bash
set -euo pipefail

EXIT_SUCCESS=0
EXIT_PREFLIGHT=10
EXIT_FRESHNESS=20
EXIT_SCHEMA=30
EXIT_BETA=40
EXIT_HOLDOUT=50
EXIT_RUNTIME=60
EXIT_PUBLISH=70
EXIT_UNKNOWN=99

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
MANIFEST_FILE="${ROOT_DIR}/governance/H1_EXPERIMENT_MANIFEST.json"
RECEIPT_FILE="${ROOT_DIR}/reports/cohort0_current_head_receipt.json"
SCHEMA_FILE="${ROOT_DIR}/governance/RMR_SCHEMA_v1.json"
STAGING_MANIFEST="${ROOT_DIR}/staging/manifest.json"
ARTIFACTS_DIR="$(cd "${ROOT_DIR}/.." && pwd)/artifacts"
SMOKE_RECEIPT_FILE="${ARTIFACTS_DIR}/smoke_path_receipt.json"
COUNTED_RECEIPT_FILE="${ARTIFACTS_DIR}/counted_path_receipt.json"
REPO_ROOT="$(git -C "${ROOT_DIR}" rev-parse --show-toplevel 2>/dev/null || true)"

json_get() {
  python - "$1" "$2" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
obj = json.load(open(path, 'r', encoding='utf-8'))
cur = obj
for part in key.split('.'):
    if isinstance(cur, list):
        part = int(part)
    cur = cur[part]
print(cur if not isinstance(cur, (dict,list)) else json.dumps(cur))
PY
}

ensure_schema_digest() {
  local expected
  expected="$(json_get "${MANIFEST_FILE}" expected_schema_digest)"
  local actual
  actual="$(python - "${SCHEMA_FILE}" <<'PY'
from pathlib import Path
import hashlib, sys
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  if [[ "${expected}" != "${actual}" ]]; then
    echo "schema digest mismatch: expected=${expected} actual=${actual}" >&2
    return ${EXIT_SCHEMA}
  fi
  return 0
}

ensure_receipt_fresh() {
  python - "${RECEIPT_FILE}" "${MANIFEST_FILE}" <<'PY'
import json, sys
from datetime import datetime, timezone
receipt = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
manifest = json.load(open(sys.argv[2], 'r', encoding='utf-8'))
ts = datetime.fromisoformat(receipt["timestamp"].replace("Z","+00:00"))
now = datetime.now(timezone.utc)
ttl = int(manifest["ttl_seconds"])
age = (now - ts).total_seconds()
raise SystemExit(0 if age <= ttl else 20)
PY
}

ensure_multisig_count() {
  local approvals_file="${ROOT_DIR}/governance/multisig_approvals.json"
  python - "${approvals_file}" "${MANIFEST_FILE}" <<'PY'
import json, sys
ap = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
mf = json.load(open(sys.argv[2], 'r', encoding='utf-8'))
required = int(mf["required_multisig"])
count = len(ap.get("approvals", []))
raise SystemExit(0 if count >= required else 10)
PY
}

ensure_clean_beta() {
  local packet="$1"
  python - "${packet}" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
rows = obj["rows"] if isinstance(obj, dict) and "rows" in obj else obj
bad = [r.get("rmr_id") for r in rows if r.get("counted") and r.get("beta")]
raise SystemExit(0 if not bad else 40)
PY
}

ensure_no_holdout_leakage() {
  local packet="$1"
  local holdout_file="${ROOT_DIR}/data/holdout_ids.txt"
  python - "${packet}" "${holdout_file}" <<'PY'
import json, sys
obj = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
rows = obj["rows"] if isinstance(obj, dict) and "rows" in obj else obj
holdout_ids = {line.strip() for line in open(sys.argv[2], 'r', encoding='utf-8') if line.strip()}
counted_ids = {r.get("case_id") for r in rows if r.get("counted")}
raise SystemExit(0 if not (holdout_ids & counted_ids) else 50)
PY
}

ensure_clean_worktree() {
  if [[ -z "${REPO_ROOT}" ]]; then
    return 0
  fi
  python - "${REPO_ROOT}" "${ROOT_DIR}" "${MANIFEST_FILE}" <<'PY'
from pathlib import Path
import json
import subprocess
import sys

repo = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
run_root = root.parent
manifest = json.load(open(sys.argv[3], 'r', encoding='utf-8'))
status_lines = subprocess.run(
    ['git', '-C', str(repo), 'status', '--porcelain'],
    capture_output=True,
    text=True,
    check=True,
).stdout.splitlines()
if not status_lines:
    raise SystemExit(0)

root_rel = root.relative_to(repo).as_posix()
run_root_rel = run_root.relative_to(repo).as_posix()
allowed_prefixes = []
for item in manifest.get("mutable_files", []):
    clean_item = item.rstrip("/")
    staging_prefix = root_rel if not clean_item else f"{root_rel}/{clean_item}"
    allowed_prefixes.append(staging_prefix)
    run_root_prefix = run_root_rel if not clean_item else f"{run_root_rel}/{clean_item}"
    if run_root_prefix not in allowed_prefixes:
        allowed_prefixes.append(run_root_prefix)

def allowed(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in allowed_prefixes)

bad = []
for line in status_lines:
    path = line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    path = path.replace("\\", "/")
    if not allowed(path):
        bad.append(path)

raise SystemExit(0 if not bad else 10)
PY
}

ensure_smoke_completed() {
  [[ -f "${SMOKE_RECEIPT_FILE}" ]] || {
    echo "missing smoke receipt: ${SMOKE_RECEIPT_FILE}" >&2
    return ${EXIT_PREFLIGHT}
  }
  python - "${SMOKE_RECEIPT_FILE}" <<'PY'
import json
import sys

receipt = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
raise SystemExit(0 if receipt.get("status") == "PASS" else 10)
PY
}

ensure_counted_unused() {
  [[ ! -f "${COUNTED_RECEIPT_FILE}" ]] || {
    echo "counted receipt already exists: ${COUNTED_RECEIPT_FILE}" >&2
    return ${EXIT_PREFLIGHT}
  }
  return 0
}
