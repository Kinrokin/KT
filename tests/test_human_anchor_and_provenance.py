from __future__ import annotations

from g32_test_utils import load_json


def test_human_anchor_and_provenance_are_measured_not_synthetic_only() -> None:
    anchor = load_json("reports/g32_human_anchor_manifest.json")
    provenance = load_json("reports/repair_corpus_provenance_scan.json")
    leakage = load_json("reports/benchmark_leakage_scan.json")
    poison = load_json("reports/poison_trigger_scan.json")

    assert anchor["human_anchor_ratio"] >= 0.20
    assert anchor["synthetic_only_repair_corpus"] is False
    assert provenance["all_rows_trace_to_g2_or_g3_failure"] is True
    assert leakage["scan_status"] == "MEASURED"
    assert poison["scan_status"] == "MEASURED"
