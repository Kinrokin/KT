from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath


def test_audits_json_files_are_valid_utf8_no_bom() -> None:
    repo_root = bootstrap_syspath()
    audits_dir = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS").resolve()
    assert audits_dir.is_dir(), f"Missing AUDITS directory: {audits_dir.as_posix()}"

    bad_bom: list[str] = []
    bad_parse: list[str] = []
    bad_type: list[str] = []

    for path in sorted(audits_dir.rglob("*.json"), key=lambda p: p.as_posix()):
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            bad_bom.append(path.as_posix())
            continue

        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            bad_parse.append(f"{path.as_posix()} :: {exc}")
            continue
        if not isinstance(obj, dict):
            bad_type.append(f"{path.as_posix()} :: {type(obj).__name__}")

    assert not bad_bom, f"UTF-8 BOM detected in AUDITS JSON files: {bad_bom}"
    assert not bad_parse, f"Invalid JSON detected in AUDITS JSON files: {bad_parse}"
    assert not bad_type, f"Non-object JSON detected in AUDITS JSON files: {bad_type}"

