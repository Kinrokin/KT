# KTG3 Targeted Repair Runtime Packet V2

This packet replaces the prior G3 runtime-intent packet with a Kaggle-executable
targeted repair runtime.

It trains PEFT repair adapters from the G3 repair fuel, runs no-regression and
scar/delta distinctness checks, emits required runtime receipts, builds a small
assessment ZIP, and fails closed if required runtime evidence or HF final-only
upload is missing.

Build head: `a838c7867be299b070bb798f4e21575dc261efcc`

Claim ceiling: unchanged. This packet does not authorize commercial launch,
external audit acceptance, external validation acceptance, S-tier, beyond-SOTA,
category leadership, frontier parity, 7B amplification, router superiority,
multi-lobe superiority, or production readiness.

Required Kaggle knobs:

- `HF_TOKEN`: required for clean pass unless `KT_REQUIRE_HF_UPLOAD=0`.
- `KT_HF_REPO_ID`: required for clean pass unless `KT_REQUIRE_HF_UPLOAD=0`.
- `KT_BASE_MODEL`: defaults to `Qwen/Qwen2.5-0.5B-Instruct`; override for a larger run.
- `KT_REQUESTED_HEAD`: optional, but if set it must match actual runtime head.

The runner emits `*_ASSESSMENT_ONLY.zip` and all required G3 runtime receipts.
