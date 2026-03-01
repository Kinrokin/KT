---
title: "Kaggle Offline Multi-Adapter Evaluator - Canon"
volume: "Volume III - Technical Stack and Pipeline"
chapter: "Chapter 5"
author_role: "Systems Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume III - Technical Stack and Pipeline
### Chapter 5 - Kaggle Offline Multi-Adapter Evaluator (Canon)

#### Chapter intent (plain-English)
This chapter defines the canonical offline evaluator pattern for running multiple adapters on Kaggle without network access and without installing new dependencies. It documents two common failure modes and provides copy-ready cells that produce deterministic evidence outputs. [SRC:USER_PACKET]

---

#### Two common failure modes (offline)

Failure mode 1: Adapter name contains '.' and breaks downstream adapter tooling
- Symptom: adapter load fails or adapter registry mapping becomes non-deterministic.
- Canon fix: sanitize adapter identifiers deterministically (map '.' to '_') and record the mapping in `meta.json`. [SRC:USER_PACKET]

Failure mode 2: Base snapshot discovery assumes remote hub
- Symptom: model loading tries to resolve remote resources.
- Canon fix: require an explicit local base snapshot directory and fail-closed if it is missing. [SRC:USER_PACKET]

---

#### Evidence outputs (required; WORM)
Emit these files under a new run directory (do not reuse output directories):
- `results.json`: per-adapter results (schema-bound if available).
- `meta.json`: pins, inputs, mapping, seeds, and toolchain fingerprint.
- `hashes.sha256.txt`: sha256 for each emitted file.

Deterministic run_id:
- Define `run_id = sha256(json.dumps(meta_core, sort_keys=True))` where `meta_core` excludes timestamps and excludes absolute paths.

---

#### Canon cell (bash) - offline, no installs
```bash
export KT_OFFLINE=1
export PYTHONHASHSEED=0
export TOKENIZERS_PARALLELISM=false

# Operator must set these local-only paths.
export BASE_SNAPSHOT_DIR="/kaggle/input/base_snapshot"
export ADAPTERS_DIR="/kaggle/input/adapters"
export OUT_DIR="/kaggle/working/KT_EXPORTS/_runs/KT_KAGGLE_EVAL/$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$OUT_DIR"
python evaluator_offline_multi_adapter.py --base "$BASE_SNAPSHOT_DIR" --adapters "$ADAPTERS_DIR" --out "$OUT_DIR"
```

#### Canon cell (python) - offline, deterministic, fail-closed
```python
import json
import hashlib
from pathlib import Path

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sha256_json(obj) -> str:
    return sha256_bytes(json.dumps(obj, sort_keys=True, ensure_ascii=True).encode("utf-8"))

def sanitize_adapter_id(raw: str) -> str:
    # Deterministic, reversible mapping recorded in meta.json.
    return raw.replace(".", "_")

def fail(msg: str) -> None:
    raise SystemExit("FAIL_CLOSED: " + msg)

base_dir = Path(Path(__file__).parent, "BASE_SNAPSHOT_DIR_PLACEHOLDER").resolve()
adapters_dir = Path(Path(__file__).parent, "ADAPTERS_DIR_PLACEHOLDER").resolve()
out_dir = Path(Path(__file__).parent, "OUT_DIR_PLACEHOLDER").resolve()

if not base_dir.exists():
    fail(f"missing base snapshot dir: {base_dir}")
if not adapters_dir.exists():
    fail(f"missing adapters dir: {adapters_dir}")
out_dir.mkdir(parents=True, exist_ok=False)

adapter_paths = sorted([p for p in adapters_dir.iterdir() if p.is_dir()])
mapping = {p.name: sanitize_adapter_id(p.name) for p in adapter_paths}

meta_core = {
    "offline": True,
    "base_snapshot_dir_name": base_dir.name,
    "adapter_ids_raw_sorted": [p.name for p in adapter_paths],
    "adapter_id_mapping": mapping,
    "seed": 0
}
run_id = sha256_json(meta_core)
meta = dict(meta_core)
meta["run_id"] = run_id

# Placeholder evaluation loop: implement using the environment's existing ML stack.
results = {"schema_id": "kt.kaggle_eval_results.v1", "run_id": run_id, "adapters": []}
for p in adapter_paths:
    results["adapters"].append({"adapter_raw": p.name, "adapter_id": mapping[p.name], "status": "NOT_EVALUATED_IN_CANON_CELL"})

(out_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(out_dir / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")

hash_lines = []
for fn in ["meta.json", "results.json"]:
    b = (out_dir / fn).read_bytes()
    hash_lines.append(f"{sha256_bytes(b)}  {fn}")
(out_dir / "hashes.sha256.txt").write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
print("WROTE", out_dir, "run_id", run_id)
```

Operator notes:
- Replace `*_PLACEHOLDER` paths with the actual Kaggle notebook variables.
- If the required ML stack is not present, fail-closed and record a next-action note (offline wheelhouse requirement). [SRC:USER_PACKET]

---

#### Sources (stubs)
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

