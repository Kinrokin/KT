import json
import zipfile
from pathlib import Path


def test_v4_packet_subject_binding_external_not_placeholder():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        config = json.loads(zf.read("runtime/ktstop300_v4_config.json").decode("utf-8-sig"))
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8-sig")
    assert config["packet_subject_merge_head"] == "EXTERNAL_LAUNCHER_AUTHORITY"
    assert "__BOUND_AFTER_PROTECTED_MERGE__" not in json.dumps(config)
    assert "KT_AUTHORIZED_PACKET_SUBJECT_HEAD" in bootstrap
    assert "KT_CURRENT_MAIN_HEAD" in bootstrap
