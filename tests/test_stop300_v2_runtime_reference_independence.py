import ast
import zipfile
from pathlib import Path


def test_v2_reference_court_does_not_import_runtime_fsm():
    with zipfile.ZipFile(Path("packets/ktstop300_v2.zip")) as zf:
        reference = zf.read("runtime/reference_court_v32.py").decode("utf-8-sig")
    tree = ast.parse(reference)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    assert not any("stop_fsm_v32" in item for item in imports)
