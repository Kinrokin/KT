# FL4 Freeze Audit Runbook (Linux Canonical)

Status: **OPERATIONS / READ-ONLY**

Purpose: Produce a **reproducible, platform-bound, transcripted, artifact-complete** FL4 evidence pack without changing code, law, or contracts.

This runbook is **verification only**. It is not a development checklist.

Pinning rule: This runbook must be listed in `KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json` so it cannot drift without a lawful repin + amendment.

---

## 0) Hard Constraints (Stop-The-World Rules)

Before running this audit, these are frozen:

- No edits to:
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/hypotheses.py`
  - evaluation logic / probe logic
  - determinism canary logic
  - derivation tool logic
  - law bundle / determinism contract / amendment artifacts
- No “quick fixes” mid-run.
- If the run fails: stop, capture evidence, and open an explicit change request (law amendment + PR) **before** attempting another seal.

---

## 1) Canonical Environment (Linux)

This freeze audit is valid only on the canonical platform class (Linux x86_64) as declared by `FL4_SUPPORTED_PLATFORMS.json`.

Required environment variables:

```bash
export PYTHONPATH="$PWD/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$PWD/KT_PROD_CLEANROOM"
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export TOKENIZERS_PARALLELISM=false
export PYTHONHASHSEED=0
```

---

## 2) Mandatory Redundant Checks (Fail-Closed)

These checks are redundant by design. A seal ritual must not depend on a single verifier.

### 2.1 Commit anchor (must be recorded)

```bash
git rev-parse HEAD
```

### 2.2 LAW_BUNDLE hash integrity (explicit)

Fail if recomputed hash differs from the pinned `LAW_BUNDLE_FL3.sha256`.

```bash
python - <<'PY'
from pathlib import Path
import json

repo_root = Path(".").resolve()

from tools.verification.fl3_meta_evaluator import compute_law_bundle_hash, load_law_bundle

bundle = load_law_bundle(repo_root=repo_root)
computed = compute_law_bundle_hash(repo_root=repo_root, bundle=bundle)
pinned = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "LAW_BUNDLE_FL3.sha256").read_text(encoding="utf-8").strip()

print("LAW_BUNDLE computed:", computed)
print("LAW_BUNDLE pinned  :", pinned)
if computed != pinned:
    raise SystemExit("FAIL: LAW_BUNDLE hash mismatch (fail-closed)")
print("PASS: LAW_BUNDLE hash matches")
PY
```

---

## 3) Canonical Command (Single Preflight Run)

### Preconditions

- Repo must be clean:

```bash
test -z "$(git status --porcelain)" || (echo "FAIL: dirty git tree" && git status --porcelain && exit 2)
```

### Execute and record platform fingerprint into the evidence transcript

Run preflight, then append platform fingerprint and runbook hash into the *pack-local* `command_transcript.txt`.

### Execute

```bash
python -m tools.verification.preflight_fl4 \
  --registry-path KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json
```

Append fingerprint + runbook hash to the latest pack transcript:

```bash
python - <<'PY'
from pathlib import Path
import subprocess
import hashlib

repo_root = Path(".").resolve()
root = repo_root / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_runs" / "FL4_SEAL"
packs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
if not packs:
    raise SystemExit("FAIL: no FL4_SEAL packs found")
pack = packs[-1]
transcript = pack / "command_transcript.txt"
if not transcript.exists():
    raise SystemExit("FAIL: pack missing command_transcript.txt (fail-closed)")

runbook = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FREEZE_AUDIT_FL4_RUNBOOK.md"
rb = runbook.read_bytes()
runbook_sha = hashlib.sha256(rb).hexdigest()

def sh(cmd):
    return subprocess.check_output(cmd, text=True).strip()

lines = []
lines.append("")
lines.append("=== PLATFORM_FINGERPRINT ===")
lines.append(f"git_sha: {sh(['git','rev-parse','HEAD'])}")
lines.append(f"uname: {sh(['uname','-a'])}")
lines.append(f"python: {sh(['python','--version'])}")
lines.append(f"runbook_path: {runbook.relative_to(repo_root).as_posix()}")
lines.append(f"runbook_sha256: {runbook_sha}")
lines.append("=== END_PLATFORM_FINGERPRINT ===")
transcript.write_text(transcript.read_text(encoding="utf-8") + "\n".join(lines) + "\n", encoding="utf-8")
print("WROTE", transcript.as_posix())
PY
```

### Output Location (evidence pack)

The preflight writes:

`KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL/<timestamp>/`

---

## 4) Evidence Pack Required Contents (Must Exist)

Minimum required files inside the created evidence directory:

- `command_transcript.txt`
- `determinism_contract.json`
- `supported_platforms.json`
- `law_bundle_hash.txt`
- `law_bundle.json`
- `canary_artifact.json`
- `meta_evaluator_receipt.json`
- `red_assault_report.json`
- `rollback_drill_report.json`
- `growth_e2e_gate_report.json`
- `preflight_summary.json`
- `job_dir/hash_manifest.json`
- `job_dir/job_dir_manifest.json`
- `job_dir/eval_report.json`
- `job_dir/promotion.json`

If any are missing, the audit fails.

---

## 5) Two-Run Determinism Check (Back-to-Back)

The seal is not valid unless **two consecutive** preflight runs produce identical hashes for:

- job_dir hash manifest root hash
- canary artifact hash manifest root hash
and also match on:

- `preflight_summary.json.git_sha`
- `law_bundle_hash.txt`

### Procedure

1) Run preflight once (creates pack A).
2) Run preflight a second time (creates pack B).

### Comparison (Python; no jq dependency)

From repo root:

```bash
python - <<'PY'
import json
from pathlib import Path

root = Path("KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL")
packs = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.name)
if len(packs) < 2:
    raise SystemExit("FAIL: need two FL4_SEAL packs to compare")

a, b = packs[-2], packs[-1]

def readj(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))

ha = readj(a / "job_dir" / "hash_manifest.json")
hb = readj(b / "job_dir" / "hash_manifest.json")
ca = readj(a / "canary_artifact.json")
cb = readj(b / "canary_artifact.json")
sa = readj(a / "preflight_summary.json")
sb = readj(b / "preflight_summary.json")

la = (a / "law_bundle_hash.txt").read_text(encoding="utf-8").strip()
lb = (b / "law_bundle_hash.txt").read_text(encoding="utf-8").strip()

ra = str(ha.get("root_hash", ""))
rb = str(hb.get("root_hash", ""))
cta = str(ca.get("hash_manifest_root_hash", ""))
ctb = str(cb.get("hash_manifest_root_hash", ""))

print("PACK_A", a.as_posix())
print("PACK_B", b.as_posix())
print("job_dir.hash_manifest.root_hash A", ra)
print("job_dir.hash_manifest.root_hash B", rb)
print("canary.hash_manifest_root_hash A", cta)
print("canary.hash_manifest_root_hash B", ctb)
print("preflight.git_sha A", str(sa.get("git_sha", "")))
print("preflight.git_sha B", str(sb.get("git_sha", "")))
print("law_bundle_hash.txt A", la)
print("law_bundle_hash.txt B", lb)

if not (len(ra) == len(rb) == 64 and len(cta) == len(ctb) == 64):
    raise SystemExit("FAIL: missing/invalid hashes in evidence packs")
if str(sa.get("git_sha", "")) != str(sb.get("git_sha", "")):
    raise SystemExit("FAIL: git_sha differs across the two runs (fail-closed)")
if la != lb:
    raise SystemExit("FAIL: LAW_BUNDLE hash differs across the two runs (fail-closed)")
if ra != rb or cta != ctb:
    raise SystemExit("FAIL: determinism divergence detected (fail-closed)")

print("PASS: determinism hashes match across two consecutive runs")
PY
```

---

## 6) CI Canonical Proof (Recommended)

Run the Linux preflight on CI and treat the CI logs as canonical transcript.

Workflow:

- `.github/workflows/ci_fl4_preflight.yml`

Acceptance:

- CI job completes successfully
- CI environment matches supported platform constraints (Python 3.10 on Linux)

---

## 7) Kaggle Canonical Proof (Alternative)

Kaggle is acceptable as long as you:

- pin to a commit SHA
- keep `git status --porcelain` clean
- run `preflight_fl4` twice
- archive the two evidence packs

Minimum packaging (tarball):

```bash
tar -czf KT_FL4_FREEZE_AUDIT_PROOF.tar.gz KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL
sha256sum KT_FL4_FREEZE_AUDIT_PROOF.tar.gz
```

Do not add tarballs to the law bundle.

---

## 8) Freeze Declaration (When You’re Allowed to Say “Sealed”)

You may declare “FL4 sealed baseline” only when all are true:

- Repo clean (no diffs, no untracked)
- Preflight run succeeds
- Evidence pack contains all required files
- Two-run determinism check passes
- CI preflight passes (recommended)

If any condition is false: do not seal.
