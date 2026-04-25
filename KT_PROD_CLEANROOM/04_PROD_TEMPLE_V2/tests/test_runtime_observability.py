from __future__ import annotations

import importlib
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from council.council_router import execute_fanout_request  # noqa: E402
from core.import_truth_guard import ImportTruthGuard  # noqa: E402
from core.invariants_gate import CONSTITUTION_VERSION_HASH, TRAINING_MARKERS  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
    }


@contextmanager
def _isolated_runtime_import_set():
    removed = {}
    for name in list(sys.modules):
        if not name:
            continue
        lowered = name.lower()
        if any(marker in lowered for marker in TRAINING_MARKERS):
            mod = sys.modules.pop(name, None)
            if mod is not None:
                removed[name] = mod
    try:
        yield
    finally:
        sys.modules.update(removed)


class TestRuntimeObservabilityWave1(unittest.TestCase):
    def test_spine_and_provider_paths_emit_runtime_telemetry(self) -> None:
        from core import runtime_registry as rr  # noqa: E402

        original_loader = rr.load_runtime_registry
        original_repo_root = rr._v2_repo_root
        registry = original_loader()

        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td).resolve()
            telemetry_path = temp_root / "runtime_telemetry.jsonl"
            os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path)
            rr._v2_repo_root = lambda: temp_root  # type: ignore[assignment]
            rr.load_runtime_registry = lambda: registry  # type: ignore[assignment]
            entry = importlib.import_module("kt.entrypoint")
            original_entry_loader = entry.load_runtime_registry
            entry.load_runtime_registry = lambda: registry  # type: ignore[assignment]
            try:
                with _isolated_runtime_import_set():
                    result = entry.invoke(_valid_context())
                    fanout = execute_fanout_request(
                        prompt="wave1 observability probe",
                        provider_ids=["dry_run", "gemini"],
                        model_id="model-1",
                        trace_id="wave1-observability-fanout",
                        export_root=temp_root / "exports" / "router_traces",
                    )
            finally:
                entry.load_runtime_registry = original_entry_loader  # type: ignore[assignment]
                rr.load_runtime_registry = original_loader  # type: ignore[assignment]
                rr._v2_repo_root = original_repo_root  # type: ignore[assignment]
                ImportTruthGuard.uninstall_for_tests()
                os.environ.pop("KT_RUNTIME_TELEMETRY_PATH", None)

            self.assertEqual(result["status"], "OK")
            self.assertEqual(len(fanout), 2)
            rows = [json.loads(line) for line in telemetry_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            surfaces = {row["surface_id"] for row in rows}
            self.assertIn("core.spine.run", surfaces)
            self.assertIn("council.providers.provider_registry.invoke", surfaces)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
