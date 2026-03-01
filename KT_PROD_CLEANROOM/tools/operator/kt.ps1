$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Thin wrapper for the KT operator CLI.
# - No installs
# - No network
# - Uses local repo code only
# - Does not print secrets (CLI logs key presence/length only)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\\..\\..")
$templeSrc = Join-Path $repoRoot "KT_PROD_CLEANROOM\\04_PROD_TEMPLE_V2\\src"
$ktRoot = Join-Path $repoRoot "KT_PROD_CLEANROOM"

$env:PYTHONPATH = "$templeSrc;$ktRoot"

Push-Location $repoRoot
try {
  python -m tools.operator.kt_cli @args
} finally {
  Pop-Location
}

