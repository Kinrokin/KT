import json
from pathlib import Path

ROOT = Path.cwd()


def test_dataset_label_blind_routing_policy_forbids_benchmark_labels():
    policy = json.loads((ROOT / "admission/dataset_label_blind_routing_requirements.json").read_text(encoding="utf-8"))
    assert policy["blind_router_required"] is True
    forbidden = set(policy["forbidden_pre_generation_inputs"])
    assert {"dataset_name", "benchmark_name", "task_family_label", "category_label"} <= forbidden
    allowed = set(policy["allowed_pre_generation_inputs"])
    assert {"numeric_quantities", "operation_words", "question_structure"} <= allowed
    assert policy["structure_bound_route_status"] == "BLOCKED_UNTIL_BLIND_FEATURE_ROUTING_PROVES_IT"
