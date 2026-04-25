#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
source "${ROOT_DIR}/scripts/preflight_common.sh"

CHECK_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-multisig-only) CHECK_ONLY=true; shift ;;
    *) echo "unknown arg $1" >&2; exit 99 ;;
  esac
done

ensure_multisig_count || exit $?
if [[ "${CHECK_ONLY}" == "true" ]]; then
  echo "multisig approvals satisfied"
  exit 0
fi

CANONICAL_DIR="${ROOT_DIR}/canonical"
PROMOTION_RECEIPT="${CANONICAL_DIR}/promotion_receipt.json"
mkdir -p "${CANONICAL_DIR}"
TMP_DIR="${CANONICAL_DIR}.tmp"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}"

python - "${ROOT_DIR}" "${TMP_DIR}" <<'PY'
from pathlib import Path
import shutil, sys, json
root = Path(sys.argv[1])
tmp = Path(sys.argv[2])
selected = ["reports", "governance", "packet", "runtime", "docs"]
skipped = []
for rel in selected:
    src = root / rel
    if not src.exists():
        continue
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        text = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").splitlines()[:10]
        except Exception:
            text = []
        if any("human_review_required: true" in line for line in text):
            skipped.append(str(path.relative_to(root).as_posix()))
            continue
        dest = tmp / path.relative_to(root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
receipt = {"skipped_human_review_required": skipped}
(tmp / "promotion_selection.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

mv "${TMP_DIR}" "${CANONICAL_DIR}"

python - "${PROMOTION_RECEIPT}" <<'PY'
import json, sys
receipt = {
  "__generated_by_agent__": True,
  "event": "atomic_promotion",
  "status": "PASS",
  "note": "Promotion completed after multisig validation. Human-review-required files were skipped automatically."
}
json.dump(receipt, open(sys.argv[1], "w", encoding="utf-8"), indent=2, sort_keys=True)
open(sys.argv[1], "a", encoding="utf-8").write("\n")
PY

if [[ -d "${ROOT_DIR}/.git" ]]; then
  git -C "${ROOT_DIR}" add canonical
  git -C "${ROOT_DIR}" commit -m "promote: canonical Track 03 package" || true
fi

echo "promotion complete"
