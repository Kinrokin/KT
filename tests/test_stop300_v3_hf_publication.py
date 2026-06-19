import json
import zipfile
from pathlib import Path


def test_v3_hf_publication_uses_real_api_sequence():
    receipt = json.loads(Path("reports/stop300_v3_publication_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        publisher = zf.read("runtime/hf_publisher.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_REAL_API_SEQUENCE_MOCKED_AND_BOUND"
    assert "HfApi" in publisher
    assert "upload_folder" in publisher
    assert "upload_file" in publisher
