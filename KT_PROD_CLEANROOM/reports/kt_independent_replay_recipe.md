# WS20 Independent Replay Recipe

Scope: verify the sealed detached verifier package in two clean environments without relying on the original repo checkout.

Prerequisites
- `KT_HMAC_KEY_SIGNER_A` and `KT_HMAC_KEY_SIGNER_B` must already be set to the WS17/WS19 trust-root values.
- Python must be available on PATH.

Source package
- Copy from `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package`.

PowerShell recipe
```powershell
$envA = Resolve-Path 'KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS20_external_reproduction_proof/env_a/package'
$envB = 'C:/Users/rober/AppData/Local/Temp/KT_WS20_external_env_b_k251mqjs/package'
Remove-Item $envA -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $envB -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $envA | Out-Null
New-Item -ItemType Directory -Force -Path $envB | Out-Null
Copy-Item -Recurse -Force 'KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package\*' $envA
Copy-Item -Recurse -Force 'KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/package\*' $envB
Push-Location (Join-Path $envA 'KT_PROD_CLEANROOM')
python -m tools.operator.public_verifier_detached_runtime --report-output reports\external_env_a_report.json --receipt-output reports\external_env_a_receipt.json
Pop-Location
Push-Location (Join-Path $envB 'KT_PROD_CLEANROOM')
python -m tools.operator.public_verifier_detached_runtime --report-output reports\external_env_b_report.json --receipt-output reports\external_env_b_receipt.json
Pop-Location
```

Success criteria
- Both detached runtime receipts report `status: PASS`.
- Both detached public verifier reports match the repo-local parity field set from WS19.
- The environments stay detached from any repo checkout.

Stronger claim not made
- WS20 proves only same-host independent clean-environment verification of the sealed detached verifier package. It does not claim cross-host or third-party reproduction, full artifact reconstruction beyond attested-subject verification, public horizon opening, or any WS21 public-release claim.
