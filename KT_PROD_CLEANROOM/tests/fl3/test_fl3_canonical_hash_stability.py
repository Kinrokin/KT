from __future__ import annotations

import json

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.fl3_canonical import canonical_json, sha256_json  # noqa: E402


def test_fl3_canonical_json_is_stable_under_key_reordering() -> None:
    a = {"b": 1, "a": {"z": 2, "y": 3}}
    b = {"a": {"y": 3, "z": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)
    assert sha256_json(a) == sha256_json(b)


def test_fl3_sha256_json_matches_hash_of_canonical_json() -> None:
    obj = {"x": [3, 2, 1], "y": "z"}
    import hashlib

    expected = hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
    assert sha256_json(obj) == expected
