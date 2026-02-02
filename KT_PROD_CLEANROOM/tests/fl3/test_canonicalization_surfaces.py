from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.training.fl3_factory.manifests import sha256_file  # noqa: E402
from tools.verification.fl3_canonical import canonical_json  # noqa: E402
from tools.verification.fl4_promote import build_promoted_index  # noqa: E402


def test_canonical_json_is_key_order_independent() -> None:
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}
    assert canonical_json(a) == canonical_json(b)


def test_hash_manifest_file_hash_normalizes_newlines(tmp_path: Path) -> None:
    lf = tmp_path / "lf.txt"
    crlf = tmp_path / "crlf.txt"
    lf.write_text("x\ny\n", encoding="utf-8", newline="\n")
    crlf.write_text("x\ny\n", encoding="utf-8", newline="\r\n")
    assert sha256_file(lf) == sha256_file(crlf)


def test_promoted_index_entries_sorted_deterministically() -> None:
    entries = [
        {"adapter_id": "b", "adapter_version": "2", "content_hash": "1" * 64, "promoted_manifest_ref": "x"},
        {"adapter_id": "a", "adapter_version": "1", "content_hash": "2" * 64, "promoted_manifest_ref": "y"},
    ]
    idx = build_promoted_index(entries=entries)
    got = [(e["adapter_id"], e["adapter_version"], e["content_hash"]) for e in idx["entries"]]
    assert got == sorted(got)


def test_canonical_json_numeric_surface_stable() -> None:
    text = canonical_json({"x": 0.6, "y": 1.0})
    assert text == "{\"x\":0.6,\"y\":1.0}"
