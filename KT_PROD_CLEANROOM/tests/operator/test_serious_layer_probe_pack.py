from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from tools.operator.serious_layer.common import Pins
from tools.operator.serious_layer.probe_pack import load_probe_pack_descriptor, probe_pack_descriptor_default_fintech
from tools.operator.serious_layer.red_assault_serious_v1 import run_serious_red_assault


def test_fintech_probe_pack_exec_does_not_leak_payload_text(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    pack = load_probe_pack_descriptor(probe_pack_descriptor_default_fintech(repo_root))

    sentinel = "SENTINEL_PAYLOAD_DO_NOT_LEAK_9b3f5f44"
    payloads_path = (tmp_path / "probe_payloads.jsonl").resolve()
    lines = []
    for i, pr in enumerate(pack.probes):
        payload = f"payload_for:{pr.probe_id}"
        if i == 0:
            payload += f":{sentinel}"
        lines.append(json.dumps({"probe_id": pr.probe_id, "payload": payload}, sort_keys=True))
    payloads_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out_dir = (tmp_path / f"out_{os.getpid()}").resolve()
    pins = Pins(
        sealed_tag="TEST",
        sealed_commit="TEST",
        law_bundle_hash="TEST",
        suite_registry_id="TEST",
        determinism_expected_root_hash="TEST",
        head_git_sha="TEST",
    )

    res = run_serious_red_assault(
        out_dir=out_dir,
        pins=pins,
        pressure="L2",
        attack_mix=[],
        seed=1337,
        case_budget=999,
        overlay_ids=["domain.fintech.v1"],
        probe_payloads=payloads_path,
        probe_engine="stub_unsafe",
    )
    assert res["status"] == "HOLD"
    assert int(res.get("executed_probe_count", 0)) > 0
    assert int(res.get("probe_failure_count", 0)) > 0
    assert (out_dir / "probe_results.jsonl").exists()

    needle = sentinel.encode("utf-8")
    for p in out_dir.rglob("*"):
        if p.is_file():
            assert needle not in p.read_bytes()

