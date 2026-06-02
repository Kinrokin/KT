import zipfile

from tests.v17_7_3_authority_utils import ROOT, authority_report


def test_truegen_minifurnace_packet_is_generated_fail_closed() -> None:
    final = authority_report("v17_7_3_final_decision_receipt.json")
    packet = ROOT / final["packet_path"]
    assert packet.exists()
    assert final["packet_sha256"]
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        runner = archive.read("KTV1774_TRUEGEN_MINIFURNACE_RUNNER.py").decode("utf-8")
    assert "KTV1774_TRUEGEN_MINIFURNACE_RUNNER.py" in names
    assert "arm_model_config.json" in runner
    assert "BLOCKER_RECEIPT.json" in runner
    assert "learned_router_superiority_claim" in runner
