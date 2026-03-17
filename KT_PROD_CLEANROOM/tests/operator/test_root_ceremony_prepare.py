from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.operator.root_ceremony_prepare import (
    WORKSTREAM_ID,
    build_root_ceremony_receipt,
    emit_ws10_preparation,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _seed_minimal_tree(root: Path, *, ws9_status: str = "PASS") -> None:
    kt_root = root / "KT_PROD_CLEANROOM"
    _write_json(
        kt_root / "reports/kt_current_head_truth_source.json",
        {
            "truth_subject_commit": "subject-sha",
            "evidence_head_commit": "evidence-sha",
        },
    )
    _write_json(
        kt_root / "reports/kt_authority_and_published_head_closure_receipt.json",
        {
            "status": ws9_status,
        },
    )
    _write_json(
        kt_root / "governance/closure_foundation/kt_tuf_root_policy.json",
        {
            "root_of_trust": {
                "trust_root_id": "bootstrap-root",
                "bootstrap_state": "BOOTSTRAP_THRESHOLD_1_OF_1",
                "threshold": 1,
            }
        },
    )
    _write_json(
        kt_root / "governance/signer_identity_policy.json",
        {
            "schema_id": "kt.governance.signer_identity_policy.v1",
        },
    )
    _write_json(
        kt_root / "governance/supply_chain_layout.json",
        {
            "schema_id": "kt.governance.supply_chain_layout.v1",
        },
    )


class RootCeremonyPrepareTests(unittest.TestCase):
    def test_emit_ws10_preparation_stays_prepared_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_minimal_tree(root)

            payloads = emit_ws10_preparation(root)

            receipt = payloads["KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json"]
            self.assertEqual(receipt["status"], "PREPARED_NOT_EXECUTED")
            self.assertEqual(receipt["pass_verdict"], "CEREMONY_READY_PENDING_OFFBOX_EXECUTION")
            self.assertEqual(receipt["next_lawful_workstream"], WORKSTREAM_ID)
            self.assertIn("OFFBOX_AIR_GAPPED_CEREMONY_NOT_PERFORMED", receipt["blocked_by"])

            topology = payloads["KT_PROD_CLEANROOM/governance/kt_signer_topology.json"]
            self.assertTrue(topology["semantic_boundary"]["identities_are_logical_only"])
            self.assertFalse(topology["semantic_boundary"]["quorum_witnessed"])

    def test_ws9_precondition_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_minimal_tree(root, ws9_status="FAIL")

            with self.assertRaises(RuntimeError):
                emit_ws10_preparation(root)

    def test_receipt_has_no_unexpected_touches_outside_ws10_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _seed_minimal_tree(root)

            receipt = build_root_ceremony_receipt(root)

            self.assertEqual(receipt["unexpected_touches"], [])
            self.assertEqual(receipt["protected_touch_violations"], [])


if __name__ == "__main__":
    unittest.main()
