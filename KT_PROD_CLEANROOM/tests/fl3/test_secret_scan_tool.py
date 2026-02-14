from __future__ import annotations

import base64
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.security.pack_guard_scan import build_secret_scan_report, scan_pack_and_write  # noqa: E402


def test_secret_scan_passes_on_hashes_only(tmp_path: Path) -> None:
    (tmp_path / "log.txt").write_text(("a" * 64) + "\n" + ("b" * 40) + "\nsha256:" + ("c" * 64) + "\n", encoding="utf-8")
    report = build_secret_scan_report(pack_root=tmp_path)
    assert report["status"] == "PASS"


def test_secret_scan_fails_on_openai_key_like_token(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("my key is sk-" + ("A" * 24) + "\n", encoding="utf-8")
    report, summary = scan_pack_and_write(pack_root=tmp_path, out_dir=tmp_path, run_id="RUN_X", lane_id="FL4_SEAL")
    assert report["status"] == "FAIL"
    assert summary["high_confidence_findings"] >= 1


def test_secret_scan_fails_on_base64_encoded_secret(tmp_path: Path) -> None:
    secret = ("sk-" + ("Z" * 24)).encode("utf-8")
    tok = base64.b64encode(secret).decode("ascii")
    (tmp_path / "encoded.txt").write_text("payload=" + tok + "\n", encoding="utf-8")
    report = build_secret_scan_report(pack_root=tmp_path)
    assert report["status"] == "FAIL"

