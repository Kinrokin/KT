import zipfile
from pathlib import Path


def test_v4_checkpoint_has_upload_restore_scope_hash_contract():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        src = zf.read("runtime/checkpoint_manager.py").decode("utf-8-sig")
    assert "publisher(path)" in src
    assert "scope_hash" in src
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in src
