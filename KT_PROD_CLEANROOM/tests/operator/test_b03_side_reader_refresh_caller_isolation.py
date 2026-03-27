from __future__ import annotations

import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_e1(root: Path):
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM"))
    sys.path.insert(0, str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"))
    from tools.operator import e1_bounded_campaign_validate as e1

    return e1


def _patch_write_scope(monkeypatch, e1) -> None:
    monkeypatch.setattr(e1, "_enforce_write_scope_pre", lambda _root: [])
    monkeypatch.setattr(
        e1,
        "_enforce_write_scope_post",
        lambda _root, *, prewrite_dirty, allowed_repo_writes: {
            "prewrite_dirty_paths": list(prewrite_dirty),
            "postwrite_dirty_paths": list(prewrite_dirty),
            "allowed_repo_writes": list(allowed_repo_writes),
            "unexpected_postwrite_paths": [],
            "undeclared_created_paths": [],
        },
    )


def _common_args(tmp_path: Path) -> list[str]:
    return [
        "--commercial-truth-output",
        str(tmp_path / "commercial_truth.json"),
        "--public-verifier-kit-output",
        str(tmp_path / "public_verifier_kit.json"),
        "--second-host-kit-output",
        str(tmp_path / "second_host_kit.json"),
        "--external-audit-output",
        str(tmp_path / "external_audit_packet.json"),
        "--receipt-output",
        str(tmp_path / "receipt.json"),
    ]


def test_side_reader_refresh_caller_isolation_passes_on_current_repo() -> None:
    root = _repo_root()
    e1 = _load_e1(root)

    result = e1.evaluate_side_reader_refresh_caller_isolation(root=root)

    assert result["status"] == "PASS"
    assert result["allowed_owner_ref"] == "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py"
    assert result["unexpected_owner_refs"] == []
    assert "allow_flag" in result["allowed_owner_token_hits"]
    assert "verification_only_flag" in result["allowed_owner_token_hits"]
    assert "caller_isolation_output_flag" in result["allowed_owner_token_hits"]


def test_side_reader_refresh_caller_isolation_fails_on_simulated_wrapper_plumbing() -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    allowed_owner_text = (root / e1.ALLOWED_SIDE_READER_REFRESH_OWNER_REL).read_text(encoding="utf-8")

    result = e1.evaluate_side_reader_refresh_caller_isolation(
        root=root,
        candidate_operator_refs=[
            e1.ALLOWED_SIDE_READER_REFRESH_OWNER_REL,
            "KT_PROD_CLEANROOM/tools/operator/fake_wrapper.py",
        ],
        text_overrides={
            e1.ALLOWED_SIDE_READER_REFRESH_OWNER_REL: allowed_owner_text,
            "KT_PROD_CLEANROOM/tools/operator/fake_wrapper.py": "\n".join(
                [
                    "parser.add_argument('--allow-side-reader-contract-receipt-refresh')",
                    "parser.add_argument('--verification-only-side-reader-receipt-refresh')",
                    "SIDE_READER_CONTRACT_RECEIPT_REL = 'KT_PROD_CLEANROOM/reports/comparator_side_reader_contract_adoption_receipt.json'",
                ]
            ),
        },
    )

    assert result["status"] == "FAIL"
    assert result["unexpected_owner_refs"][0]["operator_ref"] == "KT_PROD_CLEANROOM/tools/operator/fake_wrapper.py"
    assert "allow_flag" in result["unexpected_owner_refs"][0]["token_hits"]


def test_side_reader_refresh_caller_isolation_receipt_requires_explicit_dual_opt_in(tmp_path: Path, monkeypatch) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)

    try:
        e1.main(
            [
                *_common_args(tmp_path),
                "--side-reader-refresh-caller-isolation-receipt-output",
                str(tmp_path / "side_reader_refresh_caller_isolation_receipt.json"),
            ]
        )
    except RuntimeError as exc:
        assert "FAIL_CLOSED: side-reader refresh caller isolation receipt requires explicit dual-opt-in verification-only refresh" in str(exc)
    else:
        raise AssertionError("expected fail-closed caller-isolation receipt gating error")


def test_dual_opt_in_can_emit_t9_receipt_when_explicitly_requested(tmp_path: Path, monkeypatch, capsys) -> None:
    root = _repo_root()
    e1 = _load_e1(root)
    _patch_write_scope(monkeypatch, e1)
    t7_receipt = tmp_path / "comparator_side_reader_contract_adoption_receipt.json"
    t8_receipt = tmp_path / "side_reader_receipt_refresh_scope_receipt.json"
    t9_receipt = tmp_path / "side_reader_refresh_caller_isolation_receipt.json"

    result = e1.main(
        [
            *_common_args(tmp_path),
            "--allow-side-reader-contract-receipt-refresh",
            "--verification-only-side-reader-receipt-refresh",
            "--side-reader-contract-receipt-output",
            str(t7_receipt),
            "--side-reader-refresh-scope-receipt-output",
            str(t8_receipt),
            "--side-reader-refresh-caller-isolation-receipt-output",
            str(t9_receipt),
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["side_reader_receipt_refresh_enabled"] is True
    assert payload["side_reader_refresh_caller_isolation_status"] == "PASS"

    receipt = json.loads(t9_receipt.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T9_REFRESH_CALLER_ISOLATION_ARTIFACT_ONLY"
    assert receipt["caller_isolation"]["status"] == "PASS"
    checks = {check["check_id"]: check["pass"] for check in receipt["checks"]}
    assert checks["caller_isolation_passes"] is True
    assert checks["t7_contract_preserved"] is True
    assert checks["t8_contract_preserved"] is True
