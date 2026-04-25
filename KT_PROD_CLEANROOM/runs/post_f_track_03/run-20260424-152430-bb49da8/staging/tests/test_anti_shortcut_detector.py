from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_invariance_detector_passes_on_examples(tmp_path):
    out = tmp_path / "inv.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts/anti_shortcut_detector.py"),
        "--input", str(ROOT / "packet/residual_alpha_packet_spec.json"),
        "--json-out", str(out),
        "--mirror-threshold", "0.0",
        "--masked-threshold", "0.0",
    ])
    assert proc.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "mirror_invariance" in data and "masked_invariance" in data

def test_invariance_detector_can_fail(tmp_path):
    rows = [
        {"case_id":"CASE-0001","variant":"base","router_choice":"adapter_alpha","decision_label":"commit"},
        {"case_id":"CASE-0001","variant":"mirror","router_choice":"adapter_beta","decision_label":"reject"},
        {"case_id":"CASE-0001","variant":"masked","router_choice":"adapter_gamma","decision_label":"reject"},
    ]
    p = tmp_path / "rows.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    out = tmp_path / "inv.json"
    proc = subprocess.run([
        sys.executable, str(ROOT / "scripts/anti_shortcut_detector.py"),
        "--input", str(p),
        "--json-out", str(out),
        "--mirror-threshold", "0.9",
        "--masked-threshold", "0.9",
    ])
    assert proc.returncode == 60
