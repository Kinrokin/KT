from __future__ import annotations

from pathlib import Path

from tools.operator.package_import_canon import build_package_import_canon_receipt
from tools.operator.titanium_common import repo_root


def test_package_import_canon_passes_for_declared_canonical_paths() -> None:
    receipt = build_package_import_canon_receipt(root=repo_root())
    assert receipt["status"] == "PASS", receipt
    assert receipt["checks"][1]["status"] == "PASS", receipt
    assert receipt["checks"][2]["status"] == "PASS", receipt
    assert receipt["open_blockers_preserved"] == [], receipt


def test_package_import_canon_fail_closes_on_context_mismatch(monkeypatch) -> None:
    def fake_capture(*, root: Path, context_id: str, editable_context: dict[str, object] | None = None) -> dict[str, object]:
        base = {
            "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
            "canonical_spine": {"module": "core.spine", "callable": "run"},
            "entrypoint_module_file": "/x/kt/entrypoint.py",
            "runtime_registry_path": "/x/docs/RUNTIME_REGISTRY.json",
            "spine_module_file": "/x/core/spine.py",
            "state_vault_path": "/x/_runtime_artifacts/state_vault.jsonl",
            "context_pythonpath": "",
        }
        if context_id == "editable_install":
            base["state_vault_path"] = "/y/_runtime_artifacts/state_vault.jsonl"
        return base

    monkeypatch.setattr("tools.operator.package_import_canon._capture_context", fake_capture)
    receipt = build_package_import_canon_receipt(
        root=repo_root(),
        editable_context={"python_executable": "python", "cwd": Path("/tmp"), "pythonpath": ""},
    )
    assert receipt["status"] == "FAIL"
    assert any(row["field"] == "state_vault_path" for row in receipt["checks"][2]["mismatches"])


def test_package_import_canon_fail_closes_on_editable_pythonpath_leak(monkeypatch) -> None:
    def fake_capture(*, root: Path, context_id: str, editable_context: dict[str, object] | None = None) -> dict[str, object]:
        base = {
            "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
            "canonical_spine": {"module": "core.spine", "callable": "run"},
            "entrypoint_module_file": "/x/kt/entrypoint.py",
            "runtime_registry_path": "/x/docs/RUNTIME_REGISTRY.json",
            "spine_module_file": "/x/core/spine.py",
            "state_vault_path": "/x/_runtime_artifacts/state_vault.jsonl",
            "context_pythonpath": "",
        }
        if context_id == "editable_install":
            base["context_pythonpath"] = "/repo/injected"
        return base

    monkeypatch.setattr("tools.operator.package_import_canon._capture_context", fake_capture)
    receipt = build_package_import_canon_receipt(
        root=repo_root(),
        editable_context={"python_executable": "python", "cwd": Path("/tmp"), "pythonpath": ""},
    )
    assert receipt["status"] == "FAIL"
    assert receipt["checks"][1]["status"] == "FAIL"
    assert receipt["checks"][1]["observed_pythonpath"] == "/repo/injected"
