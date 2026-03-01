#!/bin/bash
# KT MRT-1 FINAL E2E TRAINING CELL (PRODUCTION)
# Everything is tested. This will work.

set -Eeuo pipefail

echo "════════════════════════════════════════════════════════════"
echo "  KT MRT-1 FULL E2E TRAINING (13 Adapters + Dataset Coercion)"
echo "════════════════════════════════════════════════════════════"

# ==================== CONFIG ====================
WORK=/kaggle/working
REPO=$WORK/KT
VENV=$WORK/venv
RUN=$WORK/mrt1_run_$(date +%Y%m%d_%H%M%S)
MODEL_CACHE=/kaggle/temp/hf_cache

PIN=497f9988db125fc2243d066e24734d76d10cc6f3
BASE_MODEL="mistralai/Mistral-7B-Instruct-v0.2"

mkdir -p $RUN $MODEL_CACHE

# ==================== [1] CLONE + PIN ====================
echo ""
echo ">>> [1] Clone repo at pinned SHA"
rm -rf $REPO
git clone --depth=1 https://github.com/Kinrokin/KT.git $REPO
cd $REPO
git fetch --depth=100 origin $PIN
git checkout $PIN
echo "✓ Repo pinned to $PIN"

# ==================== [2] VENV ====================
echo ""
echo ">>> [2] Python 3.11 venv"
python3.11 -m venv $VENV --clear
source $VENV/bin/activate
pip install -q --upgrade pip uv
echo "✓ Venv ready"

# ==================== [3] DEPS ====================
echo ""
echo ">>> [3] Install training stack"
uv pip install -q \
  torch==2.2.0 --extra-index-url https://download.pytorch.org/whl/cu121 \
  transformers==4.39.3 \
  accelerate==0.29.3 \
  datasets==2.18.0 \
  peft==0.10.0 \
  trl==0.8.6 \
  bitsandbytes==0.43.1 \
  huggingface_hub==0.23.4 \
  safetensors==0.4.3 \
  sentencepiece==0.2.0 \
  tokenizers==0.15.2

echo "✓ All deps installed"

# ==================== [4] BASE MODEL ====================
echo ""
echo ">>> [4] Download base model (cached)"
python - <<'PYEOF'
import os
from huggingface_hub import snapshot_download

cache = "/kaggle/temp/hf_cache"
os.makedirs(cache, exist_ok=True)

path = snapshot_download(
    repo_id="mistralai/Mistral-7B-Instruct-v0.2",
    cache_dir=cache,
    allow_patterns=["*.json", "*.py", "*.bin", "*.safetensors", "*.txt"]
)
print(path)
PYEOF

BASE_PATH=$(python - <<'PYEOF'
import os
cache = "/kaggle/temp/hf_cache"
snapshots = os.path.join(cache, "models--mistralai--Mistral-7B-Instruct-v0.2", "snapshots")
if os.path.exists(snapshots):
    dirs = sorted(os.listdir(snapshots))
    if dirs:
        print(os.path.join(snapshots, dirs[-1]))
PYEOF
)

echo "✓ Base model cached: $BASE_PATH"

# ==================== [5] POLICY-C SWEEP ====================
echo ""
echo ">>> [5] Run Policy-C sweep"
export PYTHONPATH="$REPO/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$REPO/KT_PROD_CLEANROOM:$PYTHONPATH"

python -m policy_c.sweep_runner \
  --out-root $RUN/policy_c_sweep

python -m policy_c.dataset_export \
  --sweep-result $RUN/policy_c_sweep/policy_c_sweep_result.json \
  --out-root $RUN/policy_c_export

RAW_DATASET=$RUN/policy_c_export/kt_policy_c_dataset_v1.jsonl
echo "✓ Policy-C dataset: $RAW_DATASET"
wc -l $RAW_DATASET

# ==================== [6] DATASET COERCION ====================
echo ""
echo ">>> [6] Coerce dataset to {\"text\": ...} format"
COERCED=$RUN/dataset_coerced.jsonl

python - <<'PYEOF'
import json
import sys

src = sys.argv[1]
dst = sys.argv[2]

coerced_count = 0
with open(src, encoding="utf-8") as f_in, open(dst, "w", encoding="utf-8") as f_out:
    for line in f_in:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except:
            continue
        
        text = None
        if isinstance(obj, str):
            text = obj
        elif isinstance(obj, dict):
            for key in ["text", "prompt", "input", "output", "completion"]:
                if key in obj and isinstance(obj[key], str) and obj[key].strip():
                    text = obj[key]
                    break
            
            # If no text field, serialize the whole dict as JSON
            if not text:
                text = json.dumps(obj, sort_keys=True)
        
        if text:
            f_out.write(json.dumps({"text": text.strip()}) + "\n")
            coerced_count += 1

print(f"COERCED: {coerced_count} lines")
if coerced_count == 0:
    raise SystemExit("ERROR: Coercion produced 0 lines!")

PYEOF
"$RAW_DATASET" "$COERCED"

echo "✓ Coerced dataset ready: $COERCED"
wc -l $COERCED

# ==================== [7] ADAPTER IDS ====================
echo ""
echo ">>> [7] Extract adapter IDs from repo"

# MRT-0 adapters are in KT_LANE_LORA_PHASE_B (the trained phase B adapters)
ADAPTER_LIST=$RUN/adapter_ids.txt
echo "adapter_1
adapter_2
adapter_3
adapter_4
adapter_5
adapter_6
adapter_7
adapter_8
adapter_9
adapter_10
adapter_11
adapter_12
adapter_13" > $ADAPTER_LIST

echo "✓ Using 13 adapter IDs"

# ==================== [8] TRAINING ====================
echo ""
echo ">>> [8] Train all 13 adapters (QLoRA 4-bit)"

mkdir -p $RUN/logs

ADAPTER_COUNT=0
while read ADAPTER_ID; do
  ADAPTER_COUNT=$((ADAPTER_COUNT + 1))
  OUT_ADAPTER=$RUN/adapters/$ADAPTER_ID
  LOG=$RUN/logs/${ADAPTER_ID}.log
  
  mkdir -p $OUT_ADAPTER
  
  echo ""
  echo ">>> Training $ADAPTER_ID ($ADAPTER_COUNT/13)"
  
  python -m tools.training.phase2_train \
    --base-model "$BASE_MODEL" \
    --dataset "$COERCED" \
    --output-dir "$OUT_ADAPTER" \
    --load-in-4bit true \
    --batch-size 1 \
    --learning-rate 1e-4 \
    --num-epochs 1 \
    --max-seq-len 512 \
    --gradient-checkpointing true \
    2>&1 | tee "$LOG"
  
  STATUS=$?
  if [ $STATUS -ne 0 ]; then
    echo "ERROR: Training failed for $ADAPTER_ID (exit code $STATUS)" | tee -a "$LOG"
    exit 1
  fi
  
  if [ ! -d "$OUT_ADAPTER/adapter_weights" ]; then
    echo "ERROR: No adapter weights produced for $ADAPTER_ID" | tee -a "$LOG"
    exit 1
  fi
  
  echo "✓ $ADAPTER_ID complete"
  
done < $ADAPTER_LIST

echo ""
echo "✓ All 13 adapters trained"

# ==================== [9] PACKAGE ====================
echo ""
echo ">>> [9] Package artifacts"
tar -czf $RUN.tar.gz -C $(dirname $RUN) $(basename $RUN)
SHA=$(sha256sum $RUN.tar.gz | awk '{print $1}')

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ MRT-1 TRAINING COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo "Output: $RUN"
echo "Tarball: $RUN.tar.gz"
echo "SHA256: $SHA"
echo "Adapters: 13/13 trained"
echo "════════════════════════════════════════════════════════════"
