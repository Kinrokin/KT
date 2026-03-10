from __future__ import annotations

import json
from pathlib import Path

from tools.operator.one_button_receipts import mint_one_button_receipts


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_safe_run(tmp_path: Path, *, safe_head: str, nested_head: str, verdict_head: str) -> Path:
    safe_run = tmp_path / "safe_run"
    program_run = safe_run / "program_run"
    delivery = program_run / "delivery"
    delivery.mkdir(parents=True, exist_ok=True)

    (safe_run / "verdict.txt").write_text(
        "KT_SAFE_RUN_PASS cmd=safe-run profile=v1 assurance_mode=production "
        "program_id=program.certify.canonical_hmac nested_run="
        f"{program_run.as_posix()}\n",
        encoding="utf-8",
    )
    (safe_run / "git_head.txt").write_text(f"{safe_head}\n", encoding="utf-8")
    _write_json(safe_run / "reports" / "operator_preflight.json", {"status": "PASS"})

    (program_run / "git_head.txt").write_text(f"{nested_head}\n", encoding="utf-8")
    (program_run / "verdict.txt").write_text(
        "KT_CERTIFY_PASS cmd=certify lane=canonical_hmac profile=v1 allow_dirty=0 "
        f"head={verdict_head} law=lawhash suite=suitehash sweep_sha256=sweephash\n",
        encoding="utf-8",
    )
    _write_json(delivery / "delivery_manifest.json", {"zip_path": "", "zip_sha256": ""})
    return safe_run


def _live_index(head_sha: str) -> dict:
    return {
        "generated_utc": "2026-03-10T15:00:00Z",
        "branch_ref": "main",
        "worktree": {"head_sha": head_sha},
        "checks": [{"check_id": "current_worktree_cleanroom_suite", "status": "PASS"}],
    }


def test_mint_one_button_receipts_passes_when_safe_run_lineage_matches_live_head(tmp_path: Path) -> None:
    safe_run = _seed_safe_run(tmp_path, safe_head="abc1234", nested_head="abc1234", verdict_head="abc1234")

    receipts = mint_one_button_receipts(safe_run_root=safe_run, live_validation_index=_live_index("abc1234"))

    assert receipts["preflight"]["status"] == "PASS"
    assert receipts["production"]["status"] == "PASS"
    assert receipts["preflight"]["head_lineage_match"] is True
    assert receipts["production"]["production_run"]["head_lineage_match"] is True


def test_mint_one_button_receipts_fails_when_nested_verdict_head_is_stale(tmp_path: Path) -> None:
    safe_run = _seed_safe_run(tmp_path, safe_head="abc1234", nested_head="abc1234", verdict_head="def4567")

    receipts = mint_one_button_receipts(safe_run_root=safe_run, live_validation_index=_live_index("abc1234"))

    assert receipts["preflight"]["status"] == "FAIL"
    assert receipts["production"]["status"] == "FAIL"
    assert receipts["preflight"]["head_lineage_match"] is False
    assert receipts["production"]["production_run"]["nested_verdict_head_sha"] == "def4567"
