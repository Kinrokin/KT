# Mock Key Material

These keys are intentionally fake and exist only for local mock-mode execution.

## Replace for production

1. Generate or retrieve a real cosign key:
   ```bash
   cosign generate-key-pair
   export COSIGN_KEY=cosign.key
   export COSIGN_PASSWORD='<secure-password>'
   ```
2. Point production runs at Rekor:
   ```bash
   export REKOR_URL='https://rekor.sigstore.dev'
   ```
3. Replace the mock files:
   - `keys/mock_cosign_key.pem`
   - `keys/mock_rekor_key.pem`
4. Run:
   ```bash
   ./scripts/proof_bundle_publish.sh --prod --run-id run-20260424-152430-bb49da8 --seed 42
   ```

Never commit real private keys into the repository.
