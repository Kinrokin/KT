import json
import zipfile
from pathlib import Path


def test_v3_packet_identity_uses_external_final_sha_not_self_hash():
    receipt = json.loads(Path("reports/stop300_v3_packet_identity_contract.json").read_text(encoding="utf-8-sig"))
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        config = json.loads(zf.read("runtime/ktstop300_v3_config.json").decode("utf-8-sig"))
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
    assert receipt["status"] == "PASS_EXTERNAL_FINAL_SHA_AND_INTERNAL_MEMBER_MANIFEST_BOUND"
    assert config["external_authorized_packet_sha256"] == "__EXTERNAL_LAUNCHER_AUTHORITY__"
    assert config["internal_member_manifest_sha256"]
    assert "KT_AUTHORIZED_PACKET_SHA256" in bootstrap
