# Run KT In 30 Minutes

This guide is the shortest lawful path for an operator to understand KT's bounded `E1` posture, run the verifier surfaces, and understand the proof boundary.

## What You Will Prove

- KT can produce governed, replayable, verifier-backed artifacts on the same host.
- KT is currently bounded at `E1_SAME_HOST_DETACHED_REPLAY`.

## What You Will Not Prove

- `E2`, `E3`, or `E4`
- Cross-host reproducibility
- Hostile or outsider verification
- Comparative superiority

## Time Budget

- Read posture: 5 minutes
- Run verifier: 5 to 10 minutes
- Review packet and boundary: 5 minutes

## Step 1: Read The Boundary

- Review `KT_PROD_CLEANROOM/docs/commercial/E1_BOUNDED_TRUST_WEDGE.md`
- Review `KT_PROD_CLEANROOM/reports/commercial_truth_packet.json`
- Review `KT_PROD_CLEANROOM/reports/public_verifier_kit.json`

## Step 2: Run The Verifier

From `KT_PROD_CLEANROOM`:

```powershell
python -m tools.operator.public_verifier
python -m tools.operator.public_verifier_detached_validate
```

## Step 3: Read The PASS/FAIL Surfaces

- `KT_PROD_CLEANROOM/reports/public_verifier_manifest.json`
- `KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json`
- `KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json`

## Step 4: Restate The Boundary

If the verifier passes, the lawful conclusion is:

"KT produced a bounded `E1` proof packet that can be replayed and verified on the same host."

Do not widen that statement.

## Step 5: If You Need Cross-Host Proof Later

Use the staged reentry kit:

- `KT_PROD_CLEANROOM/reports/c006_second_host_kit.json`
- `KT_PROD_CLEANROOM/docs/operator/C006_SECOND_HOST_RUNBOOK.md`
