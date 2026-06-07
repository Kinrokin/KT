import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = [
    ROOT / "kt_system" / "eval" / "math_verifier_v3_honest.py",
    ROOT / "kt_system" / "eval" / "math_rescue_v3_honest.py",
]
ALLOWED = {"__future__", "dataclasses", "decimal", "fractions", "json", "math", "pathlib", "re", "typing"}
BLOCKED = {
    "sympy",
    "nltk",
    "spacy",
    "sklearn",
    "transformers",
    "torch",
    "peft",
    "training",
    "routers",
    "adapters",
    "scratchpad",
    "fep",
    "fademem",
    "gt_fep",
    "state_diff",
    "agent_diff",
    "tournament",
    "academy",
}


def imports_for(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return imports


def test_v3_runtime_sidecar_uses_only_allowed_standard_library_imports():
    all_imports = {path.name: imports_for(path) for path in RUNTIME_FILES}
    for path_name, imports in all_imports.items():
        for imported in imports:
            root = imported.split(".")[0]
            assert root in ALLOWED, (path_name, imported)
            assert not any(blocked in imported.lower() for blocked in BLOCKED), (path_name, imported)


def test_v3_runtime_sidecar_has_no_upstream_cognition_or_model_terms():
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in RUNTIME_FILES)
    for blocked in BLOCKED:
        assert blocked not in combined
    assert "from kt_system" not in combined
    assert "expected_answer_hash" not in combined
    assert "hash(" not in combined
