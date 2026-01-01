from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from memory.replay import StateVaultReplayError, validate_state_vault_chain  # noqa: E402
from memory.state_vault import StateVault, StateVaultCorruptionError  # noqa: E402


def _read_lines(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestStateVaultC008(unittest.TestCase):
    def test_append_and_replay_passes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)

            r1 = vault.append(event_type="E1", organ_id="Spine")
            r2 = vault.append(event_type="E2", organ_id="Spine")

            self.assertEqual(len(_read_lines(path)), 2)

            replay = validate_state_vault_chain(path)
            self.assertEqual(replay.record_count, 2)
            self.assertEqual(replay.head_hash, r2.head_hash)
            self.assertNotEqual(r1.head_hash, r2.head_hash)

    def test_truncation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")
            vault.append(event_type="E2", organ_id="Spine")

            raw = path.read_bytes()
            path.write_bytes(raw[:-10])

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)

    def test_partial_write_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")

            with path.open("ab") as handle:
                handle.write(b"{\"partial\":")

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)

            with self.assertRaises(StateVaultCorruptionError):
                StateVault(path=path)

    def test_reordering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")
            vault.append(event_type="E2", organ_id="Spine")
            vault.append(event_type="E3", organ_id="Spine")

            lines = _read_lines(path)
            lines[0], lines[1] = lines[1], lines[0]
            _write_lines(path, lines)

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)

    def test_schema_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")

            obj: Dict[str, Any] = json.loads(_read_lines(path)[0])
            obj["schema_version_hash"] = "0" * 64
            _write_lines(path, [json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)])

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)

    def test_payload_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")

            obj: Dict[str, Any] = json.loads(_read_lines(path)[0])
            # Optional field (allowed) added without recomputing hashes => payload_hash mismatch.
            obj["energy_cost"] = 1.0
            _write_lines(path, [json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)])

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)

    def test_mid_file_corruption_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)
            vault.append(event_type="E1", organ_id="Spine")
            vault.append(event_type="E2", organ_id="Spine")
            vault.append(event_type="E3", organ_id="Spine")

            lines = _read_lines(path)
            obj: Dict[str, Any] = json.loads(lines[1])
            obj["event_type"] = "E2_TAMPER"
            lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            _write_lines(path, lines)

            with self.assertRaises(StateVaultReplayError):
                validate_state_vault_chain(path)


if __name__ == "__main__":
    raise SystemExit(unittest.main())

