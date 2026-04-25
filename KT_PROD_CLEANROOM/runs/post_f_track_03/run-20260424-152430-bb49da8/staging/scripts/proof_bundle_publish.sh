#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
BUNDLE_DIR="${ROOT_DIR}/bundle"
SIG_DIR="${ROOT_DIR}/signatures"
MOCK_REKOR_DIR="${ROOT_DIR}/mock_rekor"
mkdir -p "${BUNDLE_DIR}" "${SIG_DIR}" "${MOCK_REKOR_DIR}"

MODE="mock"
SEED=42
RUN_ID=""
INPUTS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mock) MODE="mock"; shift ;;
    --prod) MODE="prod"; shift ;;
    --seed) SEED="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --inputs)
      shift
      while [[ $# -gt 0 && ! "$1" =~ ^-- ]]; do INPUTS+=("$1"); shift; done
      ;;
    *) echo "unknown arg: $1" >&2; exit 99 ;;
  esac
done
if [[ -z "${RUN_ID}" ]]; then
  echo "missing --run-id" >&2
  exit 10
fi
if [[ ${#INPUTS[@]} -eq 0 ]]; then
  INPUTS=("reports" "governance" "packet" "runtime" "docs")
fi

BUNDLE="${BUNDLE_DIR}/proof_bundle_${RUN_ID}.tar.gz"
SHA_FILE="${BUNDLE}.sha256"
SIG_FILE="${SIG_DIR}/proof_bundle_${RUN_ID}.sig"
TMP_DIR="${BUNDLE_DIR}/.publish_tmp_${RUN_ID}"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"

# Copy inputs to temp so tar ordering and metadata are controlled.
for item in "${INPUTS[@]}"; do
  src="${ROOT_DIR}/${item}"
  if [[ -e "${src}" ]]; then
    dest="${TMP_DIR}/$(basename "${item}")"
    if [[ -d "${src}" ]]; then
      mkdir -p "${dest}"
      cp -R "${src}/." "${dest}/"
    else
      mkdir -p "$(dirname "${dest}")"
      cp "${src}" "${dest}"
    fi
  fi
done

tar --sort=name --mtime='UTC 2024-01-01' --owner=0 --group=0 --numeric-owner -czf "${BUNDLE}" -C "${TMP_DIR}" .
DIGEST="$(python - "${BUNDLE}" <<'PY'
import hashlib, sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
printf "%s  %s\n" "${DIGEST}" "$(basename "${BUNDLE}")" > "${SHA_FILE}"

if [[ "${MODE}" == "mock" ]]; then
  SIG_B64="$(python - "${DIGEST}" <<'PY'
import base64, sys
print(base64.b64encode(sys.argv[1].encode()).decode())
PY
)"
  printf "%s\n%s\n" "${SIG_B64}" "mock-signer:mock-key-id" > "${SIG_FILE}"
  UUID="$(python - "${DIGEST}" "${SEED}" <<'PY'
import hashlib, sys
seeded = hashlib.sha256(f"{sys.argv[1]}:{sys.argv[2]}".encode()).hexdigest()[:32]
# force uuid4 version/variant bits
chars = list(seeded)
chars[12] = '4'
chars[16] = 'a'
u = ''.join(chars)
print(f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:32]}")
PY
)"
  TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  INDEX="${MOCK_REKOR_DIR}/index.json"
  [[ -f "${INDEX}" ]] || echo "[]" > "${INDEX}"
  python - "${INDEX}" "${UUID}" "$(basename "${BUNDLE}")" "${TS}" <<'PY'
import json, sys
path, uuid_, bundle, ts = sys.argv[1:5]
data = json.load(open(path, 'r', encoding='utf-8'))
data.append({"uuid": uuid_, "bundle": bundle, "timestamp": ts})
json.dump(data, open(path, 'w', encoding='utf-8'), indent=2, sort_keys=True)
open(path, 'a', encoding='utf-8').write("\n")
PY
else
  : "${COSIGN_KEY:?COSIGN_KEY must be set for --prod}"
  : "${REKOR_URL:?REKOR_URL must be set for --prod}"
  command -v cosign >/dev/null 2>&1 || { echo "cosign missing" >&2; exit 10; }
  cosign sign-blob --yes --key "${COSIGN_KEY}" --output-signature "${SIG_FILE}" "${BUNDLE}"
  cosign upload blob --rekor-url "${REKOR_URL}" --yes "${BUNDLE}" >/dev/null
fi

rm -rf "${TMP_DIR}"
echo "{\"bundle\":\"${BUNDLE}\",\"sha256\":\"${DIGEST}\",\"signature\":\"${SIG_FILE}\",\"mode\":\"${MODE}\"}"
