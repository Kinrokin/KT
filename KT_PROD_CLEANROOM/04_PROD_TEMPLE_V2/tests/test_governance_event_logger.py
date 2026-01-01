from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from governance.audit import GovernanceAuditError, audit_governance_events  # noqa: E402
from governance.event_logger import GovernanceLogError, log_governance_event  # noqa: E402
from governance.events import GovernanceEventError, build_inputs_envelope, build_outputs_envelope  # noqa: E402
from memory.replay import validate_state_vault_chain  # noqa: E402
from memory.state_vault import StateVault  # noqa: E402


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestGovernanceEventLoggerC005(unittest.TestCase):
    def test_log_event_writes_hash_only_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)

            inputs = build_inputs_envelope(
                policy_id="p.policy",
                policy_version_hash="0" * 64,
                subject_hash="1" * 64,
                context_hash="2" * 64,
                rule_id="r.001",
            )
            outputs = build_outputs_envelope(decision="ALLOW", obligations_hash="3" * 64)

            log_governance_event(vault=vault, event_type="GOV_ALLOW", inputs_envelope=inputs, outputs_envelope=outputs)

            records = _read_jsonl(path)
            self.assertEqual(len(records), 1)

            rec = records[0]
            self.assertEqual(rec["organ_id"], "Governance")
            self.assertEqual(rec["event_type"], "GOV_ALLOW")

            # Hash-only payload surface.
            self.assertIn("inputs_hash", rec)
            self.assertIn("outputs_hash", rec)
            self.assertEqual(len(rec["inputs_hash"]), 64)
            self.assertEqual(len(rec["outputs_hash"]), 64)

            # Structural integrity holds.
            validate_state_vault_chain(path)
            self.assertEqual(audit_governance_events(path), 1)

    def test_unknown_event_type_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)

            inputs = build_inputs_envelope(
                policy_id="p.policy",
                policy_version_hash="0" * 64,
                subject_hash="1" * 64,
                context_hash="2" * 64,
            )
            outputs = build_outputs_envelope(decision="DENY")

            with self.assertRaises(GovernanceLogError):
                log_governance_event(vault=vault, event_type="GOV_UNKNOWN", inputs_envelope=inputs, outputs_envelope=outputs)

            self.assertFalse(path.exists())

    def test_oversize_policy_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)

            with self.assertRaises(GovernanceEventError):
                build_inputs_envelope(
                    policy_id=("x" * 200),
                    policy_version_hash="0" * 64,
                    subject_hash="1" * 64,
                    context_hash="2" * 64,
                )
            outputs = build_outputs_envelope(decision="ALLOW")

            self.assertFalse(path.exists())

    def test_audit_rejects_unknown_governance_event_type(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state_vault.jsonl"
            vault = StateVault(path=path)

            inputs = build_inputs_envelope(
                policy_id="p.policy",
                policy_version_hash="0" * 64,
                subject_hash="1" * 64,
                context_hash="2" * 64,
            )
            outputs = build_outputs_envelope(decision="ALLOW")
            log_governance_event(vault=vault, event_type="GOV_ALLOW", inputs_envelope=inputs, outputs_envelope=outputs)

            # Tamper governance event_type to an unknown value while keeping JSON valid.
            rec = _read_jsonl(path)[0]
            rec["event_type"] = "GOV_TAMPERED"
            path.write_text(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")

            with self.assertRaises(GovernanceAuditError):
                audit_governance_events(path)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
