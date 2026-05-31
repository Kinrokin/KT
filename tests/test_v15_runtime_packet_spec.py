import json
import zipfile
from pathlib import Path

ROOT = Path.cwd()


def test_v15_runtime_packet_spec_is_exact_and_claim_bounded():
    receipt = json.loads((ROOT / "reports/v15_runtime_packet_readiness_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "READY_AS_PACKET_SPEC_RUNTIME_MEASUREMENT_NEXT"
    assert receipt["packet_path"] == "packets/ktg3full_v15_truth_route.zip"
    assert "formal_math_router_math_act_feature_bound" in receipt["required_arms"]
    assert "non_gsm8k_math_slice" in receipt["required_slices"]
    packet = ROOT / receipt["packet_path"]
    assert packet.exists()
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
    assert "KTG3FULL_V15_TRUTH_ROUTE_RUNNER.py" in names
    assert "PACKET_MANIFEST.json" in names
    manifest = json.loads((ROOT / "packets/ktg3full_v15_truth_route/PACKET_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["training_authorized"] is False
    assert manifest["adapter_promotion_authorized"] is False
    assert manifest["learned_router_superiority_claim_authorized"] is False
    assert manifest["structure_bound_routing_claim_authorized"] is False
