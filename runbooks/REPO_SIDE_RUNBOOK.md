# Repo-Side Runbook

1. Apply packet to fresh branch from current main.
2. Emit truth pin and evidence index before mutation.
3. Patch schemas/scripts/tests/CI.
4. Run focused tests plus repo-native trust-zone and JSON gates.
5. Open PR; protected merge only.
6. Replay on main before generating compute packet.
7. Do not run Kaggle until repo-side gates pass.
