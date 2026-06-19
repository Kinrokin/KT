import zipfile
from pathlib import Path


def test_v4_dependency_delta_contract_present():
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        src = zf.read("runtime/dependency_preflight.py").decode("utf-8-sig")
    assert "--no-deps" in src
    assert "new_conflicts" in src
    assert "dependency_conflict_before.json" in src
    assert "dependency_conflict_after.json" in src
