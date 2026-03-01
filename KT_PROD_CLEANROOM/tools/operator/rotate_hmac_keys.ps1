param(
  [switch]$PersistUser = $false,
  [switch]$Quiet = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-RandomHex {
  param([Parameter(Mandatory=$true)][int]$Bytes)
  $buf = New-Object byte[] $Bytes
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($buf)
  } finally {
    $rng.Dispose()
  }
  return ($buf | ForEach-Object { $_.ToString("x2") }) -join ""
}

# Generate 32-byte keys (64 hex chars). Do NOT print the values.
$A = New-RandomHex -Bytes 32
$B = New-RandomHex -Bytes 32

# Session-only by default (recommended).
$env:KT_HMAC_KEY_SIGNER_A = $A
$env:KT_HMAC_KEY_SIGNER_B = $B

if ($PersistUser) {
  # Persist without echoing values or placing them in a command line.
  [Environment]::SetEnvironmentVariable("KT_HMAC_KEY_SIGNER_A", $A, "User")
  [Environment]::SetEnvironmentVariable("KT_HMAC_KEY_SIGNER_B", $B, "User")
}

if (-not $Quiet) {
  # Presence/length only (safe).
  python -c "import os; print({k:{'present':bool(os.getenv(k)),'length':len(os.getenv(k) or '')} for k in ['KT_HMAC_KEY_SIGNER_A','KT_HMAC_KEY_SIGNER_B']})"

  # Fingerprints are safe to print (non-reversible) and are required to reseal/update HMAC-pinned artifacts.
  python -c "import os,hashlib; print({k:hashlib.sha256((os.getenv(k) or '').encode('utf-8')).hexdigest() for k in ['KT_HMAC_KEY_SIGNER_A','KT_HMAC_KEY_SIGNER_B']})"
}
