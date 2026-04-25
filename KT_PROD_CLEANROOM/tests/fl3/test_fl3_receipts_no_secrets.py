from __future__ import annotations

import re

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()


def test_receipts_do_not_contain_secret_markers() -> None:
    receipts_dir = (_REPO_ROOT / "KT_ARCHIVE" / "vault" / "receipts").resolve()
    if not receipts_dir.exists():
        pytest.skip("KT_ARCHIVE/vault/receipts is not present on the active canonical tree")

    # High-confidence secret markers only. Do NOT flag env var names, which legitimately appear in notes.
    patterns = {
        "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "pem_private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "openssh_private_key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        "openai_api_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "hf_token": re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    }

    hits: list[str] = []
    for p in sorted(receipts_dir.glob("*.json")):
        text = p.read_text(encoding="utf-8", errors="replace")
        for name, patt in patterns.items():
            if patt.search(text):
                hits.append(f"{p.as_posix()}::{name}")
                break

    assert not hits, "Secret-like markers found in receipts (fail-closed):\n" + "\n".join(hits)
