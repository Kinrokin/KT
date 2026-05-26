from __future__ import annotations

from g32_test_utils import read_jsonl, required_schema_fields


def test_signal_density_rows_have_required_contract_fields() -> None:
    required = required_schema_fields("schemas/kt.signal_density_row.schema.json")
    rows = read_jsonl("reports/g32_signal_density_matrix.jsonl")

    assert len(rows) == 198
    assert required
    assert required.issubset(rows[0])
    assert all(row["failure_class"] != "reasoning" for row in rows)
    assert all(row["counterfactual_owner"] in {"ADAPTER_OWNED", "ROUTE_OWNED", "HAT_OWNED", "VERIFIER_OWNED", "CORPUS_OWNED", "BENCHMARK_OWNED", "SUBSTRATE_OWNED", "IRREDUCIBLE", "UNKNOWN_BLOCKED"} for row in rows)
