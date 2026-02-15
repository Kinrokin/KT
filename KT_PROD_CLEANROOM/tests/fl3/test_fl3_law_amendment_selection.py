from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_ = bootstrap_syspath()

from tools.verification.fl3_meta_evaluator import _select_strongest_law_amendment  # noqa: E402


def _amendment(mode: str, marker: str) -> dict:
    return {"schema_id": "kt.law_amendment.v2", "bundle_hash": "b" * 64, "attestation_mode": mode, "marker": marker}


def test_amendment_selection_prefers_hmac_over_simulated() -> None:
    # Simulated file sorts first; selection must still prefer HMAC.
    matches = [
        (Path("KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20200101T000000Z.json"), _amendment("SIMULATED", "sim")),
        (Path("KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_FL3_20990101T000000Z.json"), _amendment("HMAC", "hmac")),
    ]
    chosen = _select_strongest_law_amendment(matches=matches, canonical_lane=False)
    assert str(chosen.get("attestation_mode")).upper() == "HMAC"
    assert chosen.get("marker") == "hmac"


def test_amendment_selection_orders_hmac_pki_simulated() -> None:
    matches = [
        (Path("a_sim.json"), _amendment("SIMULATED", "sim")),
        (Path("b_pki.json"), _amendment("PKI", "pki")),
    ]
    chosen = _select_strongest_law_amendment(matches=matches, canonical_lane=False)
    assert str(chosen.get("attestation_mode")).upper() == "PKI"
    assert chosen.get("marker") == "pki"


def test_canonical_lane_ignores_simulated_when_stronger_exists() -> None:
    matches = [
        (Path("a_sim.json"), _amendment("SIMULATED", "sim")),
        (Path("b_hmac.json"), _amendment("HMAC", "hmac")),
    ]
    chosen = _select_strongest_law_amendment(matches=matches, canonical_lane=True)
    assert str(chosen.get("attestation_mode")).upper() == "HMAC"
    assert chosen.get("marker") == "hmac"


def test_selection_is_deterministic_among_ties_by_path() -> None:
    matches = [
        (Path("b_hmac.json"), _amendment("HMAC", "b")),
        (Path("a_hmac.json"), _amendment("HMAC", "a")),
    ]
    chosen = _select_strongest_law_amendment(matches=matches, canonical_lane=False)
    assert str(chosen.get("attestation_mode")).upper() == "HMAC"
    assert chosen.get("marker") == "a"
