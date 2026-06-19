import zipfile
from pathlib import Path


def test_v4_resume_uses_completed_set_not_runtime_rescan():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        src = zf.read("runtime/atomic_record_store.py").decode("utf-8-sig")
    assert "self.completed = self.completed_keys()" in src
    assert "self.completed.add(key)" in src
    assert "runtime_disk_scan_count = 0" in src
