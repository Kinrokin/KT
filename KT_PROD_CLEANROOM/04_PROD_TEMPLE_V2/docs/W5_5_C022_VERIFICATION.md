# W5.5 — C022 Provider Adapters (Council Leaf) — Verification

## Scope (strict)

C022 adds **optional provider adapter scaffolding** under the already-legal Council organ root:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/`

Constraints enforced:

- No new runtime import roots.
- No provider SDK imports.
- No network calls (tests + implementations).
- Fail-closed on unknown provider IDs and provider errors.
- DRY_RUN is explicit and produces **no fabricated content** (hash-only / empty).
- No secrets added to repo.

## Files (C022)

Created:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_schemas.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_interface.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_registry.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/live_provider_openai.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_adapters.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W5_5_C022_SYSTEM_AUDIT.md`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C022_EXECUTION_PATH_PROOF.md`

Modified (Council leaf only):

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/dry_run_provider.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/__init__.py`

## Provider posture (what is proven)

- Default state is **providers disabled** unless `KT_PROVIDERS_ENABLED` is explicitly set to `1|true|yes`.
- `ProviderRegistry.invoke(...)` returns:
  - `DISABLED` for any provider other than `dry_run` when disabled (fail-closed; no fabricated outputs).
  - `FAIL_CLOSED` on provider exceptions.
  - Raises `ValueError` for unknown provider IDs (fail-closed).
- `OpenAIProvider` is **scaffolding only**:
  - If `OPENAI_API_KEY` is missing: returns `FAIL_CLOSED` with `AUTH_MISSING`.
  - If `OPENAI_API_KEY` is present: returns `DISABLED` with `NOT_IMPLEMENTED`.
  - No network calls are performed under C022.

## Tests (executed)

Command:

- `python -m unittest -q KT_PROD_CLEANROOM.04_PROD_TEMPLE_V2.tests.test_provider_adapters`

Result: `PASS` (4 tests)

What tests prove:

- Deterministic `request_id` hashing.
- Schema rejects unknown fields.
- Dry-run invocation does not attempt network (socket patched).
- Unknown providers fail closed (exception or fail-closed response path).

## Constitutional Guard (executed)

Command:

- `python KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py --report KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C022.md`

Result: `PASS`

Report:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C022.md`

## Notes / explicit non-claims

- C022 does **not** enable live provider execution under the current V2 constitutional posture; it provides an audited, fail-closed leaf interface and registry for future explicit live-provider authorization.
- Council output contracts remain hash-only / DRY_RUN-safe; C022 introduces no fabricated content path.

