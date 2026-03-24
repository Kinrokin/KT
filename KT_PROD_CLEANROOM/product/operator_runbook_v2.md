# KT Bounded Operator Runbook v2

This runbook is the buyer-simple handoff for the bounded `E1` product wedge.

## Goal

Reach first PASS/FAIL in 15 minutes or less on the same host.

## Step 1: Read The Boundary

- `KT_PROD_CLEANROOM/product/one_page_product_truth_surface.md`
- `KT_PROD_CLEANROOM/product/support_boundary.json`

## Step 2: Run The Wrapper

From `KT_PROD_CLEANROOM`:

```powershell
python -m tools.operator.public_verifier
python -m tools.operator.public_verifier_detached_validate
```

## Step 3: Read The PASS/FAIL Surfaces

- `KT_PROD_CLEANROOM/reports/public_verifier_manifest.json`
- `KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json`
- `KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json`

## Step 4: Handoff The Bounded Packet

Give the operator:

- `KT_PROD_CLEANROOM/reports/commercial_truth_packet.json`
- `KT_PROD_CLEANROOM/reports/public_verifier_kit.json`
- `KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json`

## Step 5: Restate The Limit

The lawful conclusion is:

"KT produced a bounded `E1` verifier-backed packet on the same host."

Do not claim `E2`, cross-host reproducibility, outsider verification, or enterprise readiness.

## Escalation

If the buyer asks for cross-host proof, stop the product flow and use the staged C006 kit.
