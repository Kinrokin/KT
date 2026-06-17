from __future__ import annotations

import json
import zipfile


def test_ktstop10_no_gold_fields_in_prompts_or_rows() -> None:
    with zipfile.ZipFile("packets/ktstop10_v1.zip") as zf:
        config = json.loads(zf.read("runtime/ktstop10_config.json"))
    prompt_text = "\n".join(arm["template_text"] for arm in config["prompt_arm_manifest"]["arms"])
    for forbidden in ["expected_answer", "expected_answer_hash", "row_id", "source_class", "measured_correctness"]:
        assert forbidden not in prompt_text
    assert all("expected_answer" not in row for row in config["rows"])
    assert config["expected_answers_are_scorer_side_only"] is True
    assert set(config["scorer_expected_answers"]) == {row["row_id"] for row in config["rows"]}
