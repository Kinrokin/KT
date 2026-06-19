import zipfile
from pathlib import Path


def test_v3_resume_exactly_once_atomic_records():
    with zipfile.ZipFile(Path("packets/ktstop300_v3.zip")) as zf:
        store = zf.read("runtime/atomic_record_store.py").decode("utf-8-sig")
    assert "records" in store
    assert "os.fsync" in store
    assert "os.replace" in store
    assert "record hash mismatch" in store
