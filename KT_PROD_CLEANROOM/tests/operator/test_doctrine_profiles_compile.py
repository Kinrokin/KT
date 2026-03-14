from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.doctrine_profiles_compile import (  # noqa: E402
    COMPETITION_PROFILE_REL,
    DOCTRINE_MANIFEST_REL,
    OUTSIDER_PROFILE_REL,
    PUBLICATION_PROFILE_REL,
    build_step11_outputs,
)
from tools.operator.titanium_common import repo_root, semantically_equal_json  # noqa: E402


def test_step11_outputs_preserve_boundaries_and_required_profiles() -> None:
    outputs = build_step11_outputs(repo_root(), generated_utc="2026-03-14T00:00:00Z")
    json_outputs = outputs["json_outputs"]
    text_outputs = outputs["text_outputs"]

    outsider = json_outputs[OUTSIDER_PROFILE_REL]
    competition = json_outputs[COMPETITION_PROFILE_REL]
    publication = json_outputs[PUBLICATION_PROFILE_REL]
    manifest = json_outputs[DOCTRINE_MANIFEST_REL]

    assert outsider["current_status"] == "ADMISSIBLE_WITH_BOUNDARIES"
    assert "HEAD_IS_VERIFIED_SUBJECT" in outsider["forbidden_claims"]
    assert competition["current_status"] == "BLOCKED"
    assert "cross-environment controlled variation not run" in competition["explicit_gaps"]
    assert publication["current_status"] == "BLOCKED"
    assert "published-head self-convergence remains unresolved" in publication["explicit_gaps"]

    assert manifest["summary"]["artifact_count"] == 16
    assert manifest["summary"]["profile_count"] == 4
    assert manifest["summary"]["playbook_count"] == 4
    assert "Current heads may contain evidence for subject commits" in text_outputs["docs/generated/KT_Whitepaper_v1.md"]
    assert "generated doctrine may not amend law" in json_outputs["docs/generated/kt_doctrine_ratification_log.json"]["prohibitions"]


def test_step11_outputs_are_semantically_deterministic() -> None:
    first = build_step11_outputs(repo_root(), generated_utc="2026-03-14T00:00:00Z")
    second = build_step11_outputs(repo_root(), generated_utc="2026-03-14T00:00:00Z")

    assert first["text_outputs"] == second["text_outputs"]
    assert semantically_equal_json(first["json_outputs"], second["json_outputs"])
