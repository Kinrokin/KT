from __future__ import annotations

import json


def test_ktstop10_prompt_arm_manifest_has_only_a0_a1() -> None:
    manifest = json.loads(open("reports/ktstop10_prompt_arm_manifest.json", encoding="utf-8").read())
    arms = {arm["arm_id"]: arm for arm in manifest["arms"]}
    assert set(arms) == {"A0_CURRENT_PROMPT", "A1_STOP_AFTER_FINAL_ANSWER"}
    assert "After writing FINAL_ANSWER, stop immediately." in arms["A1_STOP_AFTER_FINAL_ANSWER"]["template_text"]
    assert "After writing FINAL_ANSWER, stop immediately." not in arms["A0_CURRENT_PROMPT"]["template_text"]
    assert all(arm["max_new_tokens"] == 512 for arm in arms.values())
