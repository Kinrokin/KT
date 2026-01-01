Purpose
-------
Provide tooling to reconcile LIVE_HASHED receipts with provider exports and to run verification tests.

What this verifier checks
-------------------------
- Matches receipts (receipts.jsonl) to provider export rows (CSV or JSON).
- Verifies request identity (request_id / request_id_hash), model, time-window overlap, and token usage totals.
- Produces a deterministic JSON report summarizing matches, mismatches, and verdict.

What this does NOT do
---------------------
- Make any live network calls.
- Access or print secret keys.

How to run tests
----------------
Prepare Python path and run pytest:

```bash
export PYTHONPATH=src
pytest tools/verification/tests
```

How to run reconciliation
-------------------------
Run the verifier against a receipts file and a provider export. The export may be CSV or JSON.

```bash
python tools/verification/reconcile_openai_exports.py \
  --receipts receipts.jsonl \
  --export export.csv > report.json
```

Pass / fail meaning
-------------------
PASS = receipts consistent with provider truth
FAIL = investigate before trusting receipts
