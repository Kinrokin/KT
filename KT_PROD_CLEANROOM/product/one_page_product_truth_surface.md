# KT Bounded Product Truth Surface

KT currently ships one buyer-safe surface: a governed, verifier-backed `E1` execution wedge.

## What You Can Do Today

- Run the bounded verifier wrapper on the same host.
- Get explicit PASS/FAIL receipts.
- Review a bounded audit packet and support boundary.

## What It Proves

- KT can produce governed, replayable, verifier-backed artifacts on the same host.
- KT can hand an operator a bounded packet, a verifier entrypoint, and a clear PASS/FAIL surface.

## What It Does Not Prove

- Do not claim `E2`, `E3`, or `E4`.
- Do not claim cross-host reproducibility.
- Do not claim hostile or outsider verification.
- Do not claim enterprise readiness.
- Do not claim comparative or category-leading superiority.

## Fast Operator Path

1. Read this page and `KT_PROD_CLEANROOM/product/support_boundary.json`.
2. Run the wrapper commands from `KT_PROD_CLEANROOM/product/client_wrapper_spec.json`.
3. Inspect the PASS/FAIL receipts and audit packet.

## If Cross-Host Proof Is Needed

Use the staged C006 kit:

- `KT_PROD_CLEANROOM/reports/c006_second_host_kit.json`
- `KT_PROD_CLEANROOM/docs/operator/C006_SECOND_HOST_RUNBOOK.md`
