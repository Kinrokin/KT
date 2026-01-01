from __future__ import annotations

import importlib
import socket
import tempfile
import unittest
from pathlib import Path

import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from core.import_truth_guard import ImportTruthGuard  # noqa: E402
from core.invariants_gate import CONSTITUTION_VERSION_HASH  # noqa: E402
from core.runtime_registry import load_runtime_registry  # noqa: E402
from governance.audit import audit_governance_events  # noqa: E402
from memory.replay import validate_state_vault_chain  # noqa: E402
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
    }


class TestNoNetworkDryRunC010(unittest.TestCase):
    def test_entry_spine_dry_run_blocks_network(self) -> None:
        # Hard-block network by patching socket construction + create_connection.
        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]

        # Patch runtime registry loader to use a temp vault path (avoid writing inside repo).
        from core import runtime_registry as rr  # noqa: E402

        original_loader = rr.load_runtime_registry
        original_repo_root = rr._v2_repo_root
        registry = original_loader()

        with tempfile.TemporaryDirectory() as td:
            temp_repo_root = Path(td).resolve()

            rr._v2_repo_root = lambda: temp_repo_root  # type: ignore[assignment]
            rr.load_runtime_registry = lambda: registry  # type: ignore[assignment]
            try:
                entry = importlib.import_module("kt.entrypoint")
                result = entry.invoke(_valid_context())
            finally:
                rr.load_runtime_registry = original_loader  # type: ignore[assignment]
                rr._v2_repo_root = original_repo_root  # type: ignore[assignment]
                socket.socket = original_socket  # type: ignore[assignment]
                socket.create_connection = original_create_connection  # type: ignore[assignment]

            try:
                self.assertIsInstance(result, dict)
                self.assertEqual(result.get("status"), "OK")
                self.assertEqual(result.get("record_count"), 2)
                self.assertIsInstance(result.get("head_hash"), str)
                self.assertEqual(len(str(result.get("head_hash"))), 64)

                # Proof: vault replay + governance audit both pass (hash-only, deterministic).
                p = (temp_repo_root / Path(registry.state_vault.jsonl_path)).resolve()
                self.assertTrue(p.exists())
                validate_state_vault_chain(p)
                self.assertEqual(audit_governance_events(p), 1)

                # Proof: runtime surface allowlist enforced at import-time.
                with self.assertRaises(ImportError):
                    importlib.import_module("entrypoint")

                # Proof: organ import matrix enforced at import-time (synthetic internal importer).
                synthetic = {"__name__": "kt.synthetic_importer", "__package__": "kt"}
                with self.assertRaises(ImportError):
                    exec("import memory.state_vault", synthetic, synthetic)
            finally:
                ImportTruthGuard.uninstall_for_tests()


if __name__ == "__main__":
    raise SystemExit(unittest.main())
