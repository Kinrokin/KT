import json
import zipfile
from pathlib import Path


def test_v2_publication_order_binds_evidence_before_assessment():
    receipt = json.loads(Path("reports/stop300_v2_publication_order_receipt.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        publisher = zf.read("runtime/hf_publisher.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS"
    assert receipt["order"][0] == "write all evidence"
    assert "runs/{run_id}/{repo_head}/{packet_sha}/" in publisher
