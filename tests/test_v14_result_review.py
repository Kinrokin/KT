import json
from pathlib import Path

ROOT = Path.cwd()


def read_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_v14_measured_result_is_bound_without_promotion():
    receipt = read_json("reports/v14_result_review_receipt.json")
    assert receipt["schema_id"] == "kt.v14_result_review_receipt.v1"
    assert receipt["actual_head"] == "380ba22ecb4c380d90d267e414603c89168c2e76"
    assert receipt["assessment_sha256"] == "f7c98b9c39f629cab23b3c09df3ca44e51c58ca21a9f2f7307066d1e07e624eb"
    assert receipt["rows"] == 200
    assert receipt["v14_gate_pass"] is True
    assert receipt["claim_ceiling_preserved"] is True
    assert receipt["promotion_eligible"] is False
    assert receipt["scores"]["base_raw"]["correct"] == 111
    assert receipt["scores"]["formal_math_router_specialist"]["correct"] == 117
