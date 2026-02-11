from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath


def _read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(obj, dict)
    return obj


def test_fl4_behavioral_growth_certificate_is_deterministic_and_passes() -> None:
    bootstrap_syspath()

    from tools.verification.fl4_behavioral_growth import run_behavioral_growth

    # Run twice in separate dirs and require identical receipts (determinism).
    # This test is intentionally strict: no absolute paths, no timestamps.
    import tempfile

    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        out1 = Path(d1)
        out2 = Path(d2)

        s1 = run_behavioral_growth(out_dir=out1, seed=0, min_delta=0.4, max_p_value=0.01)
        s2 = run_behavioral_growth(out_dir=out2, seed=0, min_delta=0.4, max_p_value=0.01)

        assert s1["delta"] >= 0.4
        assert s1["p_value"] <= 0.01
        assert s2["delta"] >= 0.4
        assert s2["p_value"] <= 0.01

        required = [
            "H0.json",
            "E.json",
            "H1.json",
            "growth_protocol.json",
            "scores_H0.json",
            "scores_H1.json",
            "state_event.json",
            "growth_claim.json",
            "_tmp/state_ledger.jsonl",
        ]
        for name in required:
            assert (out1 / name).exists(), f"missing: {name}"
            assert (out1 / name).stat().st_size > 0, f"empty: {name}"

        assert (out1 / "_tmp" / "state_payloads").is_dir()
        assert any((out1 / "_tmp" / "state_payloads").glob("*.json")), "missing state payloads"

        # Determinism: protocol + claim must match byte-for-byte.
        assert (out1 / "growth_protocol.json").read_text(encoding="utf-8") == (out2 / "growth_protocol.json").read_text(encoding="utf-8")
        assert (out1 / "growth_claim.json").read_text(encoding="utf-8") == (out2 / "growth_claim.json").read_text(encoding="utf-8")

        # State ledger should contain both write and read events (no wall clock).
        ledger_lines = (out1 / "_tmp" / "state_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(ledger_lines) == 2
        r1 = json.loads(ledger_lines[0])
        r2 = json.loads(ledger_lines[1])
        assert r1["event_type"] == "GROWTH_STATE_WRITE"
        assert r2["event_type"] == "GROWTH_STATE_READ"
        assert isinstance(r1.get("event_hash"), str) and len(r1["event_hash"]) == 64
        assert isinstance(r2.get("event_hash"), str) and len(r2["event_hash"]) == 64

        state_event = _read_json(out1 / "state_event.json")
        payload_hash = state_event["event"]["payload_hash"]
        assert isinstance(payload_hash, str) and len(payload_hash) == 64
        assert (out1 / state_event["event"]["payload_path"]).exists()
