#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

fail() {
  echo "FAIL_CLOSED: $*" 1>&2
  exit 2
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

for cmd in git tar sha256sum curl unzip find gzip python tee awk sort head tail; do
  need "$cmd"
done

export PYTHONNOUSERSITE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export TOKENIZERS_PARALLELISM=false
export HF_HUB_DISABLE_TELEMETRY=1
export HF_HUB_DISABLE_PROGRESS_BARS=1
export PIP_PROGRESS_BAR=off
export PIP_DISABLE_PIP_VERSION_CHECK=1
unset PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE PYTHONHOME || true

PINNED_SHA="${PINNED_SHA:-497f9988db125fc2243d066e24734d76d10cc6f3}"
[ -n "$PINNED_SHA" ] || fail "PINNED_SHA is required"
KT_REPO_URL="${KT_REPO_URL:-https://github.com/Kinrokin/KT.git}"
HF_MODEL_REPO="${HF_MODEL_REPO:-mistralai/Mistral-7B-Instruct-v0.2}"
HF_MODEL_REVISION="${HF_MODEL_REVISION:-main}"
HF_TOKEN_SECRET_NAME="${HF_TOKEN_SECRET_NAME:-HF_TOKEN}"
KT_AUDIT_LEVEL="${KT_AUDIT_LEVEL:-full}"

MRT1_BATCH_SIZE="${MRT1_BATCH_SIZE:-1}"
MRT1_MAX_ADAPTERS="${MRT1_MAX_ADAPTERS:-13}"
MRT1_MAX_STEPS="${MRT1_MAX_STEPS:-10}"
MRT1_LR="${MRT1_LR:-1e-4}"
MRT1_NUM_EPOCHS="${MRT1_NUM_EPOCHS:-1}"
MRT1_MAX_SEQ_LEN="${MRT1_MAX_SEQ_LEN:-256}"
MRT1_MAX_SAMPLES="${MRT1_MAX_SAMPLES:-0}"
MRT1_WARMUP_STEPS="${MRT1_WARMUP_STEPS:-10}"
MRT1_LOAD_IN_4BIT="${MRT1_LOAD_IN_4BIT:-1}"
MRT1_GRADIENT_CHECKPOINTING="${MRT1_GRADIENT_CHECKPOINTING:-1}"
MRT1_BNB_4BIT_QUANT_TYPE="${MRT1_BNB_4BIT_QUANT_TYPE:-nf4}"
MRT1_BNB_4BIT_COMPUTE_DTYPE="${MRT1_BNB_4BIT_COMPUTE_DTYPE:-float16}"
MRT1_BNB_4BIT_USE_DOUBLE_QUANT="${MRT1_BNB_4BIT_USE_DOUBLE_QUANT:-1}"
MRT1_BASE_MODEL_ID="${MRT1_BASE_MODEL_ID:-mistral-7b}"
ADAPTER_VERSION="${ADAPTER_VERSION:-1}"
SEED_BASE="${SEED_BASE:-0}"

WORK="/kaggle/working"
REPO_DIR="$WORK/KT"
OUT_ROOT="${KT_OUT_ROOT:-$WORK/kt_artifacts}"
RUN_ID_INPUT="${RUN_ID:-}"
OUT_DIR_INPUT="${OUT_DIR:-}"
RUN_FINGERPRINT="$(printf '%s' "${PINNED_SHA}|${HF_MODEL_REPO}|${HF_MODEL_REVISION}|${MRT1_BASE_MODEL_ID}|${ADAPTER_VERSION}|${SEED_BASE}" | sha256sum | awk '{print substr($1,1,16)}')"
RUN_ID="${RUN_ID:-KT_MRT1_${RUN_FINGERPRINT}}"
OUT_DIR="${OUT_DIR:-$OUT_ROOT/$RUN_ID}"
TMP_ROOT="$OUT_DIR/_tmp"
LOG="$OUT_DIR/cell_transcript.log"

export HF_HOME="${HF_HOME:-/kaggle/temp/hf_home}"
export HF_CACHE_DIR="${HF_CACHE_DIR:-/kaggle/temp/hf_cache}"
if [ -d "$OUT_DIR" ] && [ -n "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | head -n 1)" ]; then
  if [ -n "$RUN_ID_INPUT" ] || [ -n "$OUT_DIR_INPUT" ]; then
    fail "OUT_DIR already exists and is non-empty: $OUT_DIR (set a different RUN_ID/OUT_DIR or remove it)"
  fi
  retry=1
  while [ -d "${OUT_DIR}.r${retry}" ] && [ -n "$(find "${OUT_DIR}.r${retry}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | head -n 1)" ]; do
    retry=$((retry + 1))
  done
  OUT_DIR="${OUT_DIR}.r${retry}"
  RUN_ID="$(basename "$OUT_DIR")"
  TMP_ROOT="$OUT_DIR/_tmp"
  LOG="$OUT_DIR/cell_transcript.log"
fi
mkdir -p "$OUT_DIR" "$TMP_ROOT" "$HF_HOME" "$HF_CACHE_DIR"
: > "$LOG"

exec > >(tee -a "$LOG") 2>&1
trap 'rc=$?; echo "FAIL rc=$rc line=$LINENO cmd=${BASH_COMMAND:-unknown}"; tail -n 300 "$LOG" || true; exit $rc' ERR

echo "KT MRT-1 GOVERNED E2E"
echo "RUN_ID=$RUN_ID"
echo "PINNED_SHA=$PINNED_SHA"
echo "OUT_DIR=$OUT_DIR"

echo
echo "[0] Host sanity"
python -V || true
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi || true
fi

echo
echo "[1] Repo materialization"
cd "$WORK"
rm -rf "$REPO_DIR"
if GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 git clone --filter=blob:none "$KT_REPO_URL" "$REPO_DIR"; then
  cd "$REPO_DIR"
  git checkout "$PINNED_SHA" || fail "git checkout failed: $PINNED_SHA"
  test -z "$(git status --porcelain)" || fail "dirty tree after checkout"
  PINNED_SHA_ACTUAL="$(git rev-parse HEAD)"
else
  ZIP_URL="https://github.com/Kinrokin/KT/archive/${PINNED_SHA}.zip"
  ZIP_PATH="$TMP_ROOT/KT_${PINNED_SHA}.zip"
  curl -fsSL --retry 6 --retry-delay 2 -o "$ZIP_PATH" "$ZIP_URL" || fail "archive download failed"
  rm -rf "$TMP_ROOT/KT_ARCHIVE_UNZIP"
  mkdir -p "$TMP_ROOT/KT_ARCHIVE_UNZIP"
  unzip -q "$ZIP_PATH" -d "$TMP_ROOT/KT_ARCHIVE_UNZIP" || fail "archive unzip failed"
  SRC_DIR="$(ls -d "$TMP_ROOT"/KT_ARCHIVE_UNZIP/KT-* 2>/dev/null | head -n 1)"
  [ -d "$SRC_DIR" ] || fail "archive unpack failed"
  mv "$SRC_DIR" "$REPO_DIR"
  cd "$REPO_DIR"
  PINNED_SHA_ACTUAL="$PINNED_SHA"
fi

[ -d "$REPO_DIR/KT_PROD_CLEANROOM" ] || fail "missing KT_PROD_CLEANROOM at pin=$PINNED_SHA_ACTUAL"
export RUN_ID PINNED_SHA PINNED_SHA_ACTUAL OUT_DIR KT_REPO_URL
python - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

receipt = {
    "kind": "repo_receipt",
    "requested_pin": os.environ["PINNED_SHA"],
    "actual_pin": os.environ["PINNED_SHA_ACTUAL"],
    "repo_url": os.environ["KT_REPO_URL"],
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
Path(os.environ["OUT_DIR"]).joinpath("repo_receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

echo
echo "[2] Python venv"
cd "$WORK"
if command -v python3.11 >/dev/null 2>&1; then
  BASE_PY="$(command -v python3.11)"
elif command -v python3 >/dev/null 2>&1; then
  BASE_PY="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  BASE_PY="$(command -v python)"
else
  fail "python executable not found"
fi

ENV_DIR="$WORK/kt_py_env"
rm -rf "$ENV_DIR"
"$BASE_PY" -m venv --without-pip "$ENV_DIR" || fail "venv creation failed"
PY="$ENV_DIR/bin/python"
[ -x "$PY" ] || fail "venv python not executable: $PY"
export PY

SITEPKG_DIR="$("$PY" - <<'PY'
import site
paths = [p for p in site.getsitepackages() if p.endswith("site-packages")]
print(paths[0] if paths else "")
PY
)"
[ -n "$SITEPKG_DIR" ] || fail "could not locate venv site-packages"
cat > "$SITEPKG_DIR/sitecustomize.py" <<'PY'
# Minimal sitecustomize for KT venv bootstrap.
PY

GETPIP="$TMP_ROOT/get-pip.py"
curl -fsSL --retry 6 --retry-delay 2 -o "$GETPIP" https://bootstrap.pypa.io/get-pip.py || fail "get-pip download failed"
"$PY" "$GETPIP" >/tmp/kt_get_pip.log 2>&1 || { tail -n 200 /tmp/kt_get_pip.log || true; fail "get-pip bootstrap failed"; }
"$PY" -m pip install -q --upgrade pip setuptools wheel

"$PY" - <<'PY'
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

py = os.environ["PY"]
receipt = {
    "kind": "venv_receipt",
    "python_version": subprocess.check_output([py, "-V"], text=True).strip(),
    "pip_version": subprocess.check_output([py, "-m", "pip", "--version"], text=True).strip(),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
Path(os.environ["OUT_DIR"]).joinpath("venv_receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

echo
echo "[3] Install pinned dependencies"
set +e
"$PY" -m pip install -q --index-url https://download.pytorch.org/whl/cu121 "torch==2.2.0"
TORCH_RC=$?
set -e
[ "$TORCH_RC" -eq 0 ] || fail "torch==2.2.0 install failed"

"$PY" -m pip install -q \
  "numpy==1.26.4" "transformers==4.39.3" "accelerate==0.29.3" "datasets==2.18.0" \
  "peft==0.10.0" "trl==0.8.6" "bitsandbytes==0.43.1" "huggingface_hub==0.23.4" \
  "safetensors==0.4.3" "sentencepiece==0.2.0" "tokenizers==0.15.2" \
  "pyyaml==6.0.1" "wrapt==1.16.0" "jsonschema==4.23.0" "pytest==8.2.1"

"$PY" - <<'PY'
import accelerate  # noqa: F401
import datasets  # noqa: F401
import huggingface_hub  # noqa: F401
import numpy  # noqa: F401
import peft  # noqa: F401
import safetensors  # noqa: F401
import sentencepiece  # noqa: F401
import tokenizers  # noqa: F401
import torch
import transformers  # noqa: F401
import trl  # noqa: F401
print("IMPORTS_OK")
print("TORCH_CUDA_AVAILABLE", torch.cuda.is_available())
PY

"$PY" -m pip check >/dev/null 2>&1 || fail "pip check failed"
"$PY" -m pip freeze > "$OUT_DIR/pip_freeze.txt"

"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

out_dir = Path(os.environ["OUT_DIR"])
receipt = {
    "kind": "deps_receipt",
    "pip_check_ok": True,
    "pip_freeze": out_dir.joinpath("pip_freeze.txt").read_text(encoding="utf-8").splitlines(),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("deps_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo
echo "[3.1] Audit gate"
CLEANROOM_DIR="$REPO_DIR/KT_PROD_CLEANROOM"
SRC_DIR="$CLEANROOM_DIR/04_PROD_TEMPLE_V2/src"
export CLEANROOM_DIR
export PYTHONPATH="$SRC_DIR:$CLEANROOM_DIR"

"$PY" - <<'PY'
from core.runtime_registry import load_runtime_registry
reg = load_runtime_registry()
print("AUDIT_IMPORTS_AND_REGISTRY: PASS")
print("allowed_export_roots:", list(reg.policy_c.sweep.allowed_export_roots))
PY

PYTEST_STATUS="skipped"
if [ "$KT_AUDIT_LEVEL" = "full" ] && [ -d "$CLEANROOM_DIR/tests" ]; then
  set +e
  "$PY" -m pytest -q "$CLEANROOM_DIR/tests" | tee "$OUT_DIR/pytest_audit.log"
  TEST_RC=${PIPESTATUS[0]}
  set -e
  [ "$TEST_RC" -eq 0 ] || fail "audit pytest failed"
  PYTEST_STATUS="passed"
elif [ "$KT_AUDIT_LEVEL" = "quick" ]; then
  set +e
  "$PY" -m pytest -q "$CLEANROOM_DIR/tests/test_resolver.py" | tee "$OUT_DIR/pytest_audit.log"
  TEST_RC=${PIPESTATUS[0]}
  set -e
  [ "$TEST_RC" -eq 0 ] || fail "quick audit pytest failed"
  PYTEST_STATUS="passed_quick"
fi
export PYTEST_STATUS

"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from core.runtime_registry import load_runtime_registry

reg = load_runtime_registry()
receipt = {
    "kind": "audit_receipt",
    "audit_level": os.environ.get("KT_AUDIT_LEVEL", "full"),
    "allowed_export_roots": list(reg.policy_c.sweep.allowed_export_roots),
    "pytest_results": os.environ.get("PYTEST_STATUS", "unknown"),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
Path(os.environ["OUT_DIR"]).joinpath("audit_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo
echo "[4] HF snapshot"
export HF_MODEL_REPO HF_MODEL_REVISION HF_TOKEN_SECRET_NAME HF_CACHE_DIR OUT_DIR
"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from huggingface_hub import snapshot_download

token = os.environ.get("HF_TOKEN")
if not token:
    try:
        from kaggle_secrets import UserSecretsClient
        token = UserSecretsClient().get_secret(os.environ.get("HF_TOKEN_SECRET_NAME", "HF_TOKEN"))
    except Exception:
        token = None

path = snapshot_download(
    repo_id=os.environ["HF_MODEL_REPO"],
    revision=os.environ["HF_MODEL_REVISION"],
    cache_dir=os.environ["HF_CACHE_DIR"],
    token=token or None,
)
out_dir = Path(os.environ["OUT_DIR"])
out_dir.joinpath("base_model_path.txt").write_text(path + "\n", encoding="utf-8")
receipt = {
    "kind": "base_model_receipt",
    "snapshot_path": path,
    "model_repo": os.environ["HF_MODEL_REPO"],
    "model_revision": os.environ["HF_MODEL_REVISION"],
    "token_present": bool(token),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("base_model_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

BASE_MODEL_PATH="$(tail -n 1 "$OUT_DIR/base_model_path.txt")"
[ -d "$BASE_MODEL_PATH" ] || fail "base model snapshot missing: $BASE_MODEL_PATH"
export BASE_MODEL_PATH

echo
echo "[5] Allowlist check"
export POLICY_C_EXPORT_REL="${POLICY_C_EXPORT_REL:-exports/policy_c/$RUN_ID/sweep_a}"
export POLICY_C_EXPORT_ABS="$CLEANROOM_DIR/$POLICY_C_EXPORT_REL"
mkdir -p "$POLICY_C_EXPORT_ABS"
cd "$CLEANROOM_DIR"

"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.runtime_registry import load_runtime_registry
from policy_c.static_safety_check import assert_export_root_allowed

out_dir = Path(os.environ["OUT_DIR"])
export_rel = Path(os.environ["POLICY_C_EXPORT_REL"])
export_abs = Path(os.environ["POLICY_C_EXPORT_ABS"]).resolve()
reg = load_runtime_registry()
allowed = list(reg.policy_c.sweep.allowed_export_roots)
assert_export_root_allowed(export_abs, allowed)
receipt = {
    "kind": "allowlist_receipt",
    "export_root_rel": export_rel.as_posix(),
    "export_root_abs": export_abs.as_posix(),
    "allowed_export_roots": allowed,
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("allowlist_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("ALLOWLIST_CHECK: PASS")
PY

echo
echo "[5.1] Plan resolution + sweep + dataset export"
"$PY" - <<'PY'
import copy
import dataclasses
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from core.runtime_registry import load_runtime_registry
from policy_c.static_safety_check import assert_export_root_allowed
import policy_c.dataset_export as dataset_export
import policy_c.sweep_runner as sr

CLEANROOM_ROOT = Path(os.environ["CLEANROOM_DIR"]).resolve()
OUT_DIR = Path(os.environ["OUT_DIR"]).resolve()
OUT_REL = Path(os.environ["POLICY_C_EXPORT_REL"])
OUT_ABS = Path(os.environ["POLICY_C_EXPORT_ABS"]).resolve()
OVERRIDE_ENV = os.environ.get("POLICY_C_PLAN_REL") or os.environ.get("POLICY_C_PLAN_PATH")
RUN_ID = os.environ["RUN_ID"]
SEED_BASE = int(os.environ.get("SEED_BASE", "0"))


def fail_closed(message: str) -> None:
    print(f"FAIL_CLOSED: {message}", file=sys.stderr)
    raise SystemExit(2)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_rel_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def safe_under_cleanroom(path: Path, require_exists: bool = True) -> Path:
    candidate = path if path.is_absolute() else (CLEANROOM_ROOT / path)
    candidate = candidate.resolve()
    if not is_rel_to(candidate, CLEANROOM_ROOT):
        fail_closed(f"path escapes cleanroom: {candidate.as_posix()}")
    if require_exists and not candidate.is_file():
        fail_closed(f"not a file: {candidate.as_posix()}")
    return candidate


def load_any(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    ext = path.suffix.lower()
    if ext == ".json":
        return json.loads(text)
    if ext in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    fail_closed(f"unsupported plan suffix: {path.as_posix()}")


def looks_like_schema(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    schemaish = any(k in obj for k in ("$schema", "$id", "$ref", "definitions", "properties", "allOf", "oneOf", "anyOf"))
    planish = any(k in obj for k in ("runs", "grid"))
    return bool(schemaish and not planish)


def discover_validator() -> Tuple[str, Any]:
    candidates = [
        "validate_sweep_plan",
        "_validate_sweep_plan",
        "validate_plan",
        "_validate_plan",
        "assert_valid_sweep_plan",
        "_assert_valid_sweep_plan",
    ]
    for name in candidates:
        fn = getattr(sr, name, None)
        if callable(fn):
            return name, fn
    for name in dir(sr):
        if ("validate" in name or "assert" in name) and "plan" in name:
            fn = getattr(sr, name, None)
            if callable(fn):
                return name, fn
    fail_closed("no sweep plan validator found")


VALIDATOR_NAME, VALIDATOR_FN = discover_validator()
print("SWEEP_PLAN_VALIDATOR", VALIDATOR_NAME)


def validate_obj(plan_obj: Any) -> Tuple[bool, str]:
    if looks_like_schema(plan_obj):
        return False, "RejectedAsSchema"
    try:
        VALIDATOR_FN(plan_obj)
        return True, "OK"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def pressure_tensor(intensity: float) -> Dict[str, Any]:
    return {
        "schema_id": "kt.policy_c.pressure_tensor.v1",
        "axes": {
            "time": {"intensity": intensity, "enabled": True},
            "universe": {"intensity": 0.0, "enabled": True},
            "language": {"intensity": 0.0, "enabled": True},
            "hop": {"intensity": 0.0, "enabled": True},
            "step": {"intensity": 0.0, "enabled": True},
            "paradox": {"intensity": 0.0, "enabled": True},
            "puzzle": {"intensity": 0.0, "enabled": True},
        },
        "projection": {
            "rule": "sum",
            "weights": {
                "time": 0.0,
                "universe": 0.0,
                "language": 0.0,
                "hop": 0.0,
                "step": 0.0,
                "paradox": 0.0,
                "puzzle": 0.0,
            },
            "clamp_min": 0.0,
            "clamp_max": 1.0,
        },
        "invariants": {"reversible": True, "isolated": True, "no_cross_axis_bleed": True},
    }


def normalize_for_execution(plan_obj: Any) -> Dict[str, Any]:
    plan = copy.deepcopy(plan_obj) if isinstance(plan_obj, dict) else {}
    plan["schema_id"] = "kt.policy_c.sweep_plan.v1"
    plan.setdefault("sweep_id", f"autogen_{RUN_ID}")
    plan.setdefault("baseline_epoch_id", None)
    plan.setdefault("seed", SEED_BASE)
    plan.setdefault("max_runs", 1)
    export = plan.get("export")
    if not isinstance(export, dict):
        export = {}
    export["export_root"] = OUT_ABS.as_posix()
    plan["export"] = export
    if "runs" in plan and "grid" in plan:
        plan.pop("grid", None)
    if "runs" not in plan and "grid" not in plan:
        plan["runs"] = [{"run_id": "run_base", "epoch_plan": {"epoch_id": "epoch_base", "pressure_tensor": pressure_tensor(0.0)}}]
        plan["baseline_epoch_id"] = "run_base"
    if "runs" in plan:
        runs = plan.get("runs")
        if not isinstance(runs, list) or not runs:
            runs = [{"run_id": "run_base", "epoch_plan": {"epoch_id": "epoch_base", "pressure_tensor": pressure_tensor(0.0)}}]
        fixed = []
        for idx, run in enumerate(runs, start=1):
            run = copy.deepcopy(run) if isinstance(run, dict) else {}
            run.setdefault("run_id", f"run_{idx:03d}")
            if "epoch_plan" not in run and "epoch_plan_path" not in run:
                run["epoch_plan"] = {"epoch_id": f"epoch_{idx:03d}", "pressure_tensor": pressure_tensor(0.0)}
            fixed.append(run)
        plan["runs"] = fixed
        if not isinstance(plan.get("baseline_epoch_id"), str):
            plan["baseline_epoch_id"] = fixed[0]["run_id"]
        plan["max_runs"] = max(int(plan.get("max_runs", 1)), len(fixed))
    if "grid" in plan:
        grid = plan.get("grid")
        if not isinstance(grid, dict):
            grid = {}
        if not isinstance(grid.get("parameters"), dict) or not grid.get("parameters"):
            grid["parameters"] = {"time": [0.0]}
        if "epoch_plan" not in grid and "epoch_plan_path" not in grid:
            grid["epoch_plan"] = {"epoch_id": "epoch_grid_base", "pressure_tensor": pressure_tensor(0.0)}
        plan["grid"] = grid
    return plan


def iter_registry_hint_paths() -> List[Path]:
    reg = load_runtime_registry()
    payload = dataclasses.asdict(reg) if dataclasses.is_dataclass(reg) else {}
    out: List[Path] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
            return
        if isinstance(node, (list, tuple)):
            for v in node:
                walk(v)
            return
        if isinstance(node, str) and node.lower().endswith((".json", ".yaml", ".yml")):
            try:
                out.append(safe_under_cleanroom(Path(node)))
            except Exception:
                pass

    walk(payload)
    return sorted(set(out), key=lambda p: p.as_posix())


def iter_filesystem_candidates() -> List[Path]:
    roots = [CLEANROOM_ROOT / "policy_c", CLEANROOM_ROOT / "tools", CLEANROOM_ROOT / "tools" / "policy_c", CLEANROOM_ROOT]
    out: List[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            name = path.name.lower()
            if "schema" in name:
                continue
            if ("sweep" in name and "plan" in name) or ("sweep_plan" in name) or ("policy_c" in name and "plan" in name):
                try:
                    out.append(safe_under_cleanroom(path))
                except Exception:
                    pass
    return sorted(set(out), key=lambda p: p.as_posix())


def find_schema_path() -> Path:
    preferred = CLEANROOM_ROOT / "policy_c" / "policy_c_sweep_plan_schema_v1.json"
    if preferred.is_file():
        return preferred.resolve()
    for path in (CLEANROOM_ROOT / "policy_c").rglob("*sweep*plan*schema*.json"):
        if path.is_file():
            return path.resolve()
    for path in CLEANROOM_ROOT.rglob("*sweep*plan*schema*.json"):
        if path.is_file():
            return path.resolve()
    fail_closed("could not locate sweep plan schema for autogen")


def autogen_from_schema() -> Path:
    schema = json.loads(find_schema_path().read_text(encoding="utf-8"))
    candidates: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(schema, dict):
        candidates.append(("schema-root", schema))
        props = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
        candidates.append(("runs", {"runs": [{}], "properties": props}))
        candidates.append(("grid", {"grid": {"parameters": {"time": [0.0]}}, "properties": props}))
    errors: List[str] = []
    for tag, candidate in candidates:
        normalized = normalize_for_execution(candidate)
        ok, msg = validate_obj(normalized)
        if ok:
            out_path = OUT_ABS / "policy_c_sweep_plan.autogen.json"
            out_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print("AUTOGEN_PLAN_OK_VARIANT", tag)
            return out_path.resolve()
        errors.append(f"{tag}: {msg}")
    fail_closed("autogen sweep plan failed validation for all variants")


def resolve_plan() -> Tuple[Path, str]:
    if OVERRIDE_ENV:
        override_path = safe_under_cleanroom(Path(OVERRIDE_ENV))
        try:
            raw = load_any(override_path)
        except Exception as exc:
            fail_closed(f"override plan invalid: {override_path.as_posix()} :: {type(exc).__name__}: {exc}")
        normalized = normalize_for_execution(raw)
        ok, msg = validate_obj(normalized)
        if not ok:
            fail_closed(f"override plan invalid: {override_path.as_posix()} :: {msg}")
        out_path = OUT_ABS / "policy_c_sweep_plan.override.json"
        out_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out_path.resolve(), "override"

    ordered = []
    seen = set()
    for path in iter_registry_hint_paths() + iter_filesystem_candidates():
        key = path.as_posix()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    print("SWEEP_PLAN_CANDIDATES_COUNT", len(ordered))

    valid: List[Tuple[Path, Dict[str, Any]]] = []
    for path in ordered:
        try:
            obj = load_any(path)
        except Exception as exc:
            print(f"reject: {path.as_posix()} :: {type(exc).__name__}: {exc}")
            continue
        if looks_like_schema(obj):
            print(f"reject: {path.as_posix()} :: RejectedAsSchema")
            continue
        ok, msg = validate_obj(obj)
        if ok:
            print(f"VALID: {path.as_posix()} :: {msg}")
            valid.append((path, obj))
        else:
            print(f"reject: {path.as_posix()} :: {msg}")

    if len(valid) > 1:
        fail_closed("multiple valid sweep plans found (ambiguous). Set POLICY_C_PLAN_REL to disambiguate: " + ", ".join(p.as_posix() for p, _ in valid))
    if len(valid) == 1:
        _, obj = valid[0]
        normalized = normalize_for_execution(obj)
        ok, msg = validate_obj(normalized)
        if not ok:
            fail_closed(f"discovered plan invalid: {msg}")
        out_path = OUT_ABS / "policy_c_sweep_plan.discovered.json"
        out_path.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out_path.resolve(), "discovered"
    print("NO_VALID_PLAN_FOUND: attempting autogen")
    return autogen_from_schema(), "autogen"


OUT_ABS.mkdir(parents=True, exist_ok=True)
if not is_rel_to(OUT_ABS, CLEANROOM_ROOT):
    fail_closed(f"export root escapes cleanroom: {OUT_ABS.as_posix()}")

reg = load_runtime_registry()
assert_export_root_allowed(OUT_ABS, list(reg.policy_c.sweep.allowed_export_roots))
plan_path, method = resolve_plan()
plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()

receipt = {
    "kind": "policy_c_sweep_plan_resolution_receipt",
    "method": method,
    "resolved_plan_path": plan_path.as_posix(),
    "resolved_plan_path_rel_cleanroom": plan_path.relative_to(CLEANROOM_ROOT).as_posix() if is_rel_to(plan_path, CLEANROOM_ROOT) else None,
    "plan_sha256": plan_sha,
    "validator": VALIDATOR_NAME,
    "override_env": OVERRIDE_ENV,
    "export_root_rel": OUT_REL.as_posix(),
    "export_root_abs": OUT_ABS.as_posix(),
    "timestamp": now_utc(),
}
OUT_DIR.joinpath("policy_c_sweep_plan_resolution_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("SWEEP_PLAN_RESOLUTION_OK")
print("RESOLVED_SWEEP_PLAN_PATH", plan_path.as_posix())
print("RESOLVED_SWEEP_PLAN_SHA256", plan_sha)

try:
    sr.run_sweep(plan_path=plan_path, out_root=OUT_ABS)
except Exception as exc:
    fail_closed(f"sweep run failed: {type(exc).__name__}: {exc}")

sweep_result = OUT_ABS / "policy_c_sweep_result.json"
if not sweep_result.exists():
    fail_closed("sweep result missing after run_sweep")

try:
    dataset_export.export_dataset(sweep_result_path=sweep_result, out_root=OUT_ABS)
except Exception as exc:
    fail_closed(f"dataset export failed: {type(exc).__name__}: {exc}")

if not list(OUT_ABS.rglob("*.jsonl")) and not list(OUT_ABS.rglob("*.jsonl.gz")):
    fail_closed("no dataset files produced by sweep")
PY

echo
echo "[5.2] RAW dataset resolution"
RAW_DATASET="$(
  find "$POLICY_C_EXPORT_ABS" -type f \( -name '*.jsonl' -o -name '*.jsonl.gz' \) -printf '%s\t%p\n' \
  | sort -nr \
  | head -n 1 \
  | cut -f2-
)"
[ -n "${RAW_DATASET:-}" ] || fail "no dataset files produced by sweep"
[ -f "$RAW_DATASET" ] || fail "raw dataset missing: $RAW_DATASET"
if [[ "$RAW_DATASET" == *.jsonl.gz ]]; then
  gzip -dc "$RAW_DATASET" > "$OUT_DIR/dataset_raw.jsonl" || fail "failed to decompress raw dataset"
else
  cp -f "$RAW_DATASET" "$OUT_DIR/dataset_raw.jsonl" || fail "failed to copy raw dataset"
fi
[ -s "$OUT_DIR/dataset_raw.jsonl" ] || fail "dataset_raw.jsonl is empty"
mkdir -p "$OUT_DIR/policy_c_export"
cp -a "$POLICY_C_EXPORT_ABS/." "$OUT_DIR/policy_c_export/" || fail "failed to copy export tree"

export RAW_DATASET_PATH="$OUT_DIR/dataset_raw.jsonl"
"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

raw = Path(os.environ["RAW_DATASET_PATH"]).resolve()
receipt = {
    "kind": "policy_c_export_receipt",
    "raw_dataset_path": raw.as_posix(),
    "size_bytes": raw.stat().st_size,
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
Path(os.environ["OUT_DIR"]).joinpath("policy_c_export_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo
echo "[6] Dataset coercion"
"$PY" - <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def fail_closed(message: str) -> None:
    print(f"FAIL_CLOSED: {message}", file=sys.stderr)
    raise SystemExit(2)


def extract_text(obj):
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        for key in ("text", "prompt", "input", "output", "completion"):
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


out_dir = Path(os.environ["OUT_DIR"])
raw = out_dir / "dataset_raw.jsonl"
coerced = out_dir / "dataset_coerced.jsonl"
if not raw.exists():
    fail_closed("dataset_raw.jsonl missing")

count = 0
with raw.open("r", encoding="utf-8") as src, coerced.open("w", encoding="utf-8") as dst:
    for line in src:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception:
            parsed = line
        row = {"text": extract_text(parsed)}
        if set(row.keys()) != {"text"} or not isinstance(row["text"], str) or not row["text"].strip():
            fail_closed("dataset coercion schema violation")
        dst.write(json.dumps(row, ensure_ascii=False) + "\n")
        count += 1

if count == 0:
    fail_closed("coercion produced 0 lines")

sha = hashlib.sha256(coerced.read_bytes()).hexdigest()
report = {
    "kind": "dataset_coercion_report",
    "gate_D2": "PASS",
    "line_count": count,
    "sha256": sha,
    "dataset_raw_path": raw.as_posix(),
    "dataset_coerced_path": coerced.as_posix(),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("dataset_coercion_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("COERCION_DONE", json.dumps({"line_count": count, "sha256": sha}, sort_keys=True))
PY

echo
echo "[7] Cohort manufacture"
"$PY" - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

out_dir = Path(os.environ["OUT_DIR"])
cleanroom_dir = Path(os.environ["CLEANROOM_DIR"])
seed = str(os.environ.get("SEED_BASE", "0"))
base_model = os.environ.get("MRT1_BASE_MODEL_ID", "mistral-7b")
version = os.environ.get("ADAPTER_VERSION", "1")
adapter_ids = []
adapter_mode = "hashed_fallback"

role_weights = cleanroom_dir / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json"
if role_weights.exists():
    try:
        weights = json.loads(role_weights.read_text(encoding="utf-8"))
        roles = weights.get("roles")
        if isinstance(roles, list):
            role_ids = []
            for entry in roles:
                if isinstance(entry, dict):
                    role_id = entry.get("role_id")
                    if isinstance(role_id, str) and role_id.strip():
                        role_ids.append(role_id.strip().upper())
            ordered = sorted({role_id for role_id in role_ids if role_id != "ARBITER"})
            if len(ordered) >= 13:
                adapter_ids = [f"lobe.{role_id.lower()}.v1" for role_id in ordered[:13]]
                adapter_mode = "doctrine_lobes"
    except Exception:
        adapter_ids = []

if not adapter_ids:
    prefix = hashlib.sha256(f"{seed}|{base_model}|{version}".encode("utf-8")).hexdigest()[:10]
    adapter_ids = [f"adapter_{i:02d}_{prefix}" for i in range(1, 14)]

out_dir.joinpath("mrt1_adapter_ids.txt").write_text("\n".join(adapter_ids) + "\n", encoding="utf-8")
out_dir.joinpath("cohort0_adapter_set.json").write_text(
    json.dumps(
        {
            "schema_id": "kt.cohort0_adapter_set.v1",
            "adapter_count": 13,
            "adapter_mode": adapter_mode,
            "seed_base": seed,
            "base_model_id": base_model,
            "adapter_version": version,
            "adapter_ids": adapter_ids,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
receipt = {
    "kind": "cohort_receipt",
    "adapter_count": 13,
    "adapter_mode": adapter_mode,
    "adapter_ids_sha256": hashlib.sha256("\n".join(adapter_ids).encode("utf-8")).hexdigest(),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("cohort_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("COHORT_MANUFACTURE_OK", 13)
PY

echo
echo "[8] MRT-1 training loop"
"$PY" - <<'PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def fail_closed(message: str) -> None:
    print(f"FAIL_CLOSED: {message}", file=sys.stderr)
    raise SystemExit(2)


def bool_env(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def tail_text(path: Path, lines: int = 60) -> str:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return "<log_unavailable>"
    chunk = raw[-lines:]
    compact = " | ".join(line.strip() for line in chunk if line.strip())
    return compact[:4000] if compact else "<empty_log>"


out_dir = Path(os.environ["OUT_DIR"]).resolve()
cleanroom_dir = Path(os.environ["CLEANROOM_DIR"]).resolve()
repo_dir = cleanroom_dir.parent
dataset_path = out_dir / "dataset_coerced.jsonl"
coercion = json.loads((out_dir / "dataset_coercion_report.json").read_text(encoding="utf-8"))
expected_sha = coercion["sha256"]
actual_sha = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
if actual_sha != expected_sha:
    fail_closed(f"dataset hash mismatch before training: expected={expected_sha} actual={actual_sha}")

adapter_ids = [line.strip() for line in (out_dir / "mrt1_adapter_ids.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
if len(adapter_ids) != 13:
    fail_closed(f"adapter count must be 13, got {len(adapter_ids)}")
max_adapters = int(os.environ.get("MRT1_MAX_ADAPTERS", "13"))
if max_adapters <= 0:
    fail_closed("MRT1_MAX_ADAPTERS must be positive")
selected = adapter_ids[:max_adapters]
if not selected:
    fail_closed("no adapters selected for training")

py = os.environ["PY"]
base_model_path = os.environ["BASE_MODEL_PATH"]
stdout_dir = out_dir / "mrt1_train_stdout"
runs_dir = out_dir / "mrt1_runs"
promoted_dir = out_dir / "mrt1_promotion_receipts"
stdout_dir.mkdir(parents=True, exist_ok=True)
runs_dir.mkdir(parents=True, exist_ok=True)
promoted_dir.mkdir(parents=True, exist_ok=True)

help_probe = subprocess.run(
    [py, "-m", "tools.training.phase2_train", "-h"],
    capture_output=True,
    text=True,
)
help_text = (help_probe.stdout or "") + "\n" + (help_probe.stderr or "")
strict_mode = "--work-order" in help_text and "--base-model-id" in help_text and "--lr" in help_text
legacy_mode = "--output-dir" in help_text and "--learning-rate" in help_text
if not strict_mode and not legacy_mode:
    fail_closed("unable to determine phase2_train CLI mode from help output")
print("TRAINER_MODE", "strict" if strict_mode else "legacy")

summary_rows = []
for adapter in selected:
    log_path = stdout_dir / f"{adapter}.log"
    if strict_mode:
        work_order_path = cleanroom_dir / "kt.phase2_work_order.v1.json"
        if not work_order_path.exists():
            fail_closed(f"training failed for {adapter} :: missing work order {work_order_path.as_posix()}")

        strict_shadow_rel = f"KT_PROD_CLEANROOM/exports/adapters_mrt1_shadow/_runs/{os.environ['RUN_ID']}"
        strict_promoted_rel = "KT_PROD_CLEANROOM/exports/adapters_mrt1"
        strict_shadow_abs = (repo_dir / strict_shadow_rel).resolve()
        strict_shadow_abs.mkdir(parents=True, exist_ok=True)

        before_receipts = {path.resolve() for path in strict_shadow_abs.rglob("train_receipt.json")}
        cmd = [
            py,
            "-m",
            "tools.training.phase2_train",
            "--work-order",
            str(work_order_path),
            "--adapter-id",
            adapter,
            "--adapter-version",
            os.environ.get("ADAPTER_VERSION", "1"),
            "--base-model-id",
            os.environ.get("MRT1_BASE_MODEL_ID", "mistral-7b"),
            "--base-model-path",
            base_model_path,
            "--dataset",
            str(dataset_path),
            "--seed",
            os.environ.get("SEED_BASE", "0"),
            "--device",
            os.environ.get("MRT1_DEVICE", "auto"),
            "--export-shadow-root",
            strict_shadow_rel,
            "--export-promoted-root",
            strict_promoted_rel,
            "--max-steps",
            os.environ.get("MRT1_MAX_STEPS", "10"),
            "--batch-size",
            os.environ.get("MRT1_BATCH_SIZE", "1"),
            "--lr",
            os.environ.get("MRT1_LR", "1e-4"),
            "--max-seq-len",
            os.environ.get("MRT1_MAX_SEQ_LEN", "256"),
            "--max-samples",
            os.environ.get("MRT1_MAX_SAMPLES", "0"),
            "--bnb-4bit-quant-type",
            os.environ.get("MRT1_BNB_4BIT_QUANT_TYPE", "nf4"),
            "--bnb-4bit-compute-dtype",
            os.environ.get("MRT1_BNB_4BIT_COMPUTE_DTYPE", "float16"),
        ]
        if bool_env("MRT1_LOAD_IN_4BIT", "1"):
            cmd.append("--load-in-4bit")
        if not bool_env("MRT1_GRADIENT_CHECKPOINTING", "1"):
            cmd.append("--no-gradient-checkpointing")
        if not bool_env("MRT1_BNB_4BIT_USE_DOUBLE_QUANT", "1"):
            cmd.append("--no-bnb-4bit-use-double-quant")

        train_tmp = out_dir / "_train_tmp" / adapter
        train_tmp.mkdir(parents=True, exist_ok=True)
        io_guard_receipt = out_dir / "mrt1_io_guard" / f"io_guard_receipt.{adapter}.json"
        io_guard_receipt.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["KT_LIVE"] = "0"
        env["KT_IO_GUARD"] = "1"
        env["KT_IO_GUARD_DENY_NETWORK"] = "1"
        env["KT_IO_GUARD_RECEIPT_PATH"] = str(io_guard_receipt)
        env["TMPDIR"] = str(train_tmp)
        env["HF_HOME"] = str(train_tmp / "hf_home")
        env["HF_DATASETS_CACHE"] = str(train_tmp / "hf_datasets_cache")
        env["TRANSFORMERS_CACHE"] = str(train_tmp / "hf_transformers_cache")
        env["TORCH_HOME"] = str(train_tmp / "torch_home")
        allowed_roots = [
            str((repo_dir / "KT_PROD_CLEANROOM" / "exports" / "adapters_mrt1_shadow").resolve()),
            str((repo_dir / "KT_PROD_CLEANROOM" / "exports" / "adapters_mrt1").resolve()),
            str(out_dir.resolve()),
            str(train_tmp.resolve()),
            "/tmp",
        ]
        env["KT_IO_GUARD_ALLOWED_WRITE_ROOTS"] = json.dumps(allowed_roots)

        with log_path.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, text=True, env=env, cwd=str(repo_dir))
        if proc.returncode != 0:
            fail_closed(f"training failed for {adapter} :: exit_code={proc.returncode} :: log_tail={tail_text(log_path)}")

        after_receipts = {path.resolve() for path in strict_shadow_abs.rglob("train_receipt.json")}
        new_receipts = sorted([path for path in after_receipts if path not in before_receipts], key=lambda p: p.stat().st_mtime)
        if not new_receipts:
            adapter_receipts = sorted(
                [path for path in after_receipts if f"/{adapter}/" in path.as_posix()],
                key=lambda p: p.stat().st_mtime,
            )
            if adapter_receipts:
                new_receipts = [adapter_receipts[-1]]
        if not new_receipts:
            fail_closed(f"training failed for {adapter} :: missing new train_receipt.json :: log_tail={tail_text(log_path)}")
        receipt_path = new_receipts[-1]
        run_dir = receipt_path.parent
    else:
        run_dir = runs_dir / adapter
        run_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            py,
            "-m",
            "tools.training.phase2_train",
            "--base-model",
            base_model_path,
            "--dataset",
            str(dataset_path),
            "--output-dir",
            str(run_dir),
            "--load-in-4bit",
            os.environ.get("MRT1_LOAD_IN_4BIT", "1"),
            "--batch-size",
            os.environ.get("MRT1_BATCH_SIZE", "1"),
            "--learning-rate",
            os.environ.get("MRT1_LR", "1e-4"),
            "--num-epochs",
            os.environ.get("MRT1_NUM_EPOCHS", "1"),
            "--max-seq-len",
            os.environ.get("MRT1_MAX_SEQ_LEN", "256"),
            "--gradient-checkpointing",
            os.environ.get("MRT1_GRADIENT_CHECKPOINTING", "1"),
            "--warmup-steps",
            os.environ.get("MRT1_WARMUP_STEPS", "10"),
        ]
        with log_path.open("w", encoding="utf-8") as handle:
            proc = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0:
            fail_closed(f"training failed for {adapter} :: exit_code={proc.returncode} :: log_tail={tail_text(log_path)}")
        receipt_path = run_dir / "train_receipt.json"
        if not receipt_path.exists():
            fail_closed(f"training failed for {adapter} :: missing train_receipt.json :: log_tail={tail_text(log_path)}")

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("status") != "PASS":
        fail_closed(f"training failed for {adapter} :: status={receipt.get('status')}")
    promoted_receipt = promoted_dir / f"{adapter}_train_receipt.json"
    shutil.copy2(receipt_path, promoted_receipt)
    summary_rows.append(
        {
            "adapter_id": adapter,
            "status": "PASS",
            "run_dir": run_dir.as_posix(),
            "train_receipt": promoted_receipt.as_posix(),
            "log_path": log_path.as_posix(),
        }
    )
    print(f"TRAIN_PASS {adapter}")

summary = {
    "kind": "training_receipt_summary",
    "requested_max_adapters": max_adapters,
    "trained_count": len(summary_rows),
    "dataset_sha256": expected_sha,
    "adapters": summary_rows,
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("training_receipt_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("TRAIN_PASS_all", len(summary_rows))
PY

echo
echo "[9] Runtime snapshot"
"$PY" - <<'PY'
import dataclasses
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.runtime_registry import load_runtime_registry


def to_jsonable(value):
    if dataclasses.is_dataclass(value):
        return {field: to_jsonable(getattr(value, field)) for field in value.__dataclass_fields__}
    if isinstance(value, tuple):
        return [to_jsonable(v) for v in value]
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    return value


out_dir = Path(os.environ["OUT_DIR"])
payload = {
    "kind": "runtime_registry_snapshot",
    "snapshot": to_jsonable(load_runtime_registry()),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("runtime_registry.mrt1.snapshot.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("RUNTIME_SNAPSHOT_WRITTEN")
PY

echo
echo "[9.1] Run manifest"
"$PY" - <<'PY'
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft7Validator

out_dir = Path(os.environ["OUT_DIR"])
schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "KT MRT1 Run Manifest",
    "type": "object",
    "required": [
        "run_id",
        "pinned_sha_requested",
        "pinned_sha_actual",
        "python_version",
        "pip_freeze",
        "dataset_coerced_sha",
        "policy_c_plan_resolution_receipt",
        "timestamp",
    ],
    "properties": {
        "run_id": {"type": "string"},
        "pinned_sha_requested": {"type": "string"},
        "pinned_sha_actual": {"type": "string"},
        "python_version": {"type": "string"},
        "pip_freeze": {"type": "array", "items": {"type": "string"}},
        "dataset_coerced_sha": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "policy_c_plan_resolution_receipt": {
            "type": "object",
            "required": ["kind", "method", "resolved_plan_path", "plan_sha256", "validator", "export_root_rel"],
            "properties": {
                "kind": {"type": "string"},
                "method": {"type": "string"},
                "resolved_plan_path": {"type": "string"},
                "resolved_plan_path_rel_cleanroom": {"type": ["string", "null"]},
                "plan_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                "validator": {"type": "string"},
                "override_env": {"type": ["string", "null"]},
                "export_root_rel": {"type": "string"},
                "export_root_abs": {"type": "string"},
            },
        },
        "timestamp": {"type": "string", "format": "date-time"},
    },
}
out_dir.joinpath("run_manifest.schema.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")

dataset_sha = json.loads(out_dir.joinpath("dataset_coercion_report.json").read_text(encoding="utf-8"))["sha256"]
if not re.fullmatch(r"[a-f0-9]{64}", dataset_sha):
    raise SystemExit("FAIL_CLOSED: invalid coerced dataset sha")

manifest = {
    "run_id": os.environ["RUN_ID"],
    "pinned_sha_requested": os.environ["PINNED_SHA"],
    "pinned_sha_actual": os.environ["PINNED_SHA_ACTUAL"],
    "python_version": subprocess.check_output([os.environ["PY"], "-V"], text=True).strip(),
    "pip_freeze": out_dir.joinpath("pip_freeze.txt").read_text(encoding="utf-8").splitlines(),
    "dataset_coerced_sha": dataset_sha,
    "policy_c_plan_resolution_receipt": json.loads(out_dir.joinpath("policy_c_sweep_plan_resolution_receipt.json").read_text(encoding="utf-8")),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
errors = sorted(Draft7Validator(schema).iter_errors(manifest), key=lambda e: list(e.path))
if errors:
    raise SystemExit(f"FAIL_CLOSED: run manifest schema validation failed: {errors[0].message}")

out_dir.joinpath("run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("RUN_MANIFEST_WRITTEN")
PY

echo
echo "[10] Bundle"
TARBALL="${OUT_DIR}.tar.gz"
tar -czf "$TARBALL" -C "$OUT_ROOT" "$RUN_ID" || fail "tarball creation failed"
TARBALL_SHA="$(sha256_file "$TARBALL")"
printf '%s\n' "$TARBALL_SHA" > "${TARBALL}.sha256"
export TARBALL TARBALL_SHA

"$PY" - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

out_dir = Path(os.environ["OUT_DIR"])
receipt = {
    "kind": "final_receipt",
    "tarball": os.environ["TARBALL"],
    "sha256": os.environ["TARBALL_SHA"],
    "run_manifest_path": out_dir.joinpath("run_manifest.json").as_posix(),
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
out_dir.joinpath("final_receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "BUNDLE_DONE $TARBALL"
echo "ALL_STAGES_COMPLETE"
