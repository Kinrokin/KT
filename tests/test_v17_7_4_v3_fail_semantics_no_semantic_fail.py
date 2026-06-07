import json
from pathlib import Path

from kt_system.eval.math_verifier_v3_honest import (
    ABSTAIN_UNVERIFIED_ACCEPT,
    FAIL_OBVIOUS_GARBAGE,
    fail_semantics_too_broad,
    verify_numeric_surface,
)


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_negative_and_large_numbers_abstain_without_manifest_bounds():
    assert verify_numeric_surface("Final answer: -5")["status"] == ABSTAIN_UNVERIFIED_ACCEPT
    assert verify_numeric_surface("Final answer: 1000000000000000000000000")["status"] == ABSTAIN_UNVERIFIED_ACCEPT


def test_manifest_bound_impossibility_is_the_only_semantic_like_fail():
    negative = verify_numeric_surface("Final answer: -5", {"nonnegative_answer_required": True})
    large = verify_numeric_surface("Final answer: 101", {"max_answer_value": 100})

    assert negative["status"] == FAIL_OBVIOUS_GARBAGE
    assert negative["reason"] == "BOUND_DOMAIN_IMPOSSIBLE"
    assert large["status"] == FAIL_OBVIOUS_GARBAGE
    assert large["reason"] == "BOUND_DOMAIN_IMPOSSIBLE"


def test_no_surface_abstains_unless_numeric_only_is_explicitly_manifest_bound():
    loose = verify_numeric_surface("Final answer: C", {"numeric_answer_required": False})
    strict = verify_numeric_surface("Final answer: C", {"numeric_only_answer_required": True})

    assert loose["status"] == ABSTAIN_UNVERIFIED_ACCEPT
    assert strict["status"] == FAIL_OBVIOUS_GARBAGE
    assert strict["reason"] == "NUMERIC_REQUIRED_BUT_NO_SURFACE"


def test_nonfinite_and_malformed_numeric_surface_fail_narrowly():
    nonfinite = verify_numeric_surface("Final answer: NaN")
    malformed = verify_numeric_surface("Final answer: 1..2")

    assert nonfinite["status"] == FAIL_OBVIOUS_GARBAGE
    assert nonfinite["reason"] == "NONFINITE_NUMBER"
    assert malformed["status"] == FAIL_OBVIOUS_GARBAGE
    assert malformed["reason"] == "MALFORMED_NUMERIC_SURFACE"
    assert fail_semantics_too_broad(malformed) is False


def test_v3_fail_status_too_broad_blocker_is_present_but_not_triggered():
    blocker = read_json("reports/v17_7_4_v3_fail_status_too_broad_blocker_receipt.json")
    semantics = read_json("reports/v17_7_4_v3_fail_semantics_receipt.json")

    assert blocker["blocker_id"] == "KT_BLOCKED__V3_FAIL_STATUS_TOO_BROAD"
    assert blocker["status"] == "NOT_TRIGGERED"
    assert blocker["active"] is False
    assert semantics["verifier_is_correctness_judge"] is False
    assert semantics["default_status"] == ABSTAIN_UNVERIFIED_ACCEPT
