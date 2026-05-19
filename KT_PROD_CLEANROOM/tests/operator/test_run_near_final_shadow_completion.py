from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.operator import context_budget_gate
from tools.operator import run_bounded_forward_streams
from tools.operator import run_near_final_shadow_completion as near_final


def _copy_required_inputs(tmp_path: Path) -> None:
    root = near_final.repo_root()
    required = {
        *context_budget_gate.CURRENT_CONTEXT_INPUTS,
        *context_budget_gate.ARCHIVE_INDEX_INPUTS,
        ".agentignore",
        "commercial/quickstart.md",
        "commercial/operator_runbook.md",
        "commercial/deployment_profiles.yaml",
        "commercial/support_sla.md",
        "commercial/data_governance_pack.md",
        "commercial/security_review_packet.md",
        "commercial/evidence_pack_manifest.json",
        "commercial/pilot_contract_rider.md",
        "commercial/pricing_and_license_options.md",
        "commercial/customer_safe_language_pack.md",
        "runtime/local_agent_runtime_profile.yaml",
        "runtime/contained_subagent_sandbox_policy.yaml",
        "runtime/no_canonical_write_sandbox_policy.yaml",
        "runtime/local_model_claim_boundary.yaml",
        "skills/skill_promotion_law.yaml",
        "governance/internal_state_vector.schema.json",
        "governance/authority_gain_policy.yaml",
        "context_packing/context_pack_policy.yaml",
        "context_packing/json_to_toon_adapter.py",
        "context_packing/toon_roundtrip_verifier.py",
        "context_packing/context_pack_benchmark.py",
    }
    for raw in sorted(required):
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_near_final_run_emits_target_and_preserves_blockers(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    summary = near_final.run(output_root=tmp_path)

    receipt = summary["readjudication_receipt"]
    assert receipt["selected_outcome"] == near_final.TARGET_OUTCOME
    assert receipt["near_final_shadow_complete"] is True
    assert receipt["external_audit_accepted"] is False
    assert receipt["commercial_claim_authorized"] is False
    assert receipt["seven_b_amplification_proven"] is False
    assert receipt["category_leadership_claim_authorized"] is False
    assert receipt["truth_engine_law_changed"] is False
    assert receipt["trust_zone_law_changed"] is False


def test_near_final_main_json_output_is_parseable_without_banner(tmp_path: Path, capsys) -> None:
    _copy_required_inputs(tmp_path)

    assert near_final.main(["--json"], output_root=tmp_path) == 0

    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert output.lstrip().startswith("{")
    assert parsed["target_outcome"] == near_final.TARGET_OUTCOME


def test_near_final_outputs_required_workstream_files(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    near_final.run(output_root=tmp_path)
    for raw in [
        *near_final.OUTPUTS.values(),
        *near_final.ADAPTIVE_OUTPUTS.values(),
        *near_final.CAPABILITY_OUTPUTS.values(),
        *near_final.TRAINING_OUTPUTS.values(),
        *near_final.BENCHMARK_OUTPUTS.values(),
        context_budget_gate.OUTPUT_RECEIPT,
    ]:
        assert (tmp_path / raw).is_file(), raw


def test_context_budget_receipt_is_reported_as_changed_output(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    summary = near_final.run(output_root=tmp_path)

    assert context_budget_gate.OUTPUT_RECEIPT in summary["changed_outputs"]


def test_highway_shadow_policy_observes_without_warning_action(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    near_final.run(output_root=tmp_path)

    shadow_policy = (tmp_path / near_final.OUTPUTS["highway_shadow_policy"]).read_text(encoding="utf-8-sig")
    warn_policy = (tmp_path / near_final.OUTPUTS["highway_warn_only_policy"]).read_text(encoding="utf-8-sig")
    shadow_receipt = _load(tmp_path / near_final.OUTPUTS["highway_shadow_receipt"])
    warn_receipt = _load(tmp_path / near_final.OUTPUTS["highway_warn_receipt"])
    assert "  - observe only" in shadow_policy
    assert "  - warn operator" not in shadow_policy
    assert shadow_receipt["can_warn"] is False
    assert "  - warn operator" in warn_policy
    assert warn_receipt["can_warn"] is True


def test_near_final_human_language_claim_scan_passes(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    near_final.run(output_root=tmp_path)
    for key in near_final.HUMAN_CLAIM_SCAN_KEYS:
        raw = near_final.OUTPUTS[key]
        text = (tmp_path / raw).read_text(encoding="utf-8-sig")
        assert run_bounded_forward_streams.scan_claim_text(text, source=raw) == []


def test_near_final_rejects_positive_overclaim_in_human_surface(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    near_final.run(output_root=tmp_path)
    target = tmp_path / near_final.OUTPUTS["bounded_pilot_onboarding"]
    target.write_text(target.read_text(encoding="utf-8-sig") + "\nKT is externally audited.\n", encoding="utf-8")
    scan = near_final._claim_scan(tmp_path, [near_final.OUTPUTS["bounded_pilot_onboarding"]])
    assert scan["passed"] is False
    assert scan["violations"]


def test_near_final_blocks_when_context_budget_missing(tmp_path: Path) -> None:
    _copy_required_inputs(tmp_path)
    (tmp_path / "governance/current_claim_ceiling.json").unlink()
    summary = near_final.run(output_root=tmp_path)
    receipt = summary["readjudication_receipt"]
    assert receipt["near_final_shadow_complete"] is False
    assert receipt["context_budget_gate_passed"] is False


def test_blocked_claims_header_is_negative_context() -> None:
    text = "Blocked claims:\n\n```text\nS-tier\nbeyond-SOTA\n7B amplification proven\n```"
    assert run_bounded_forward_streams.scan_claim_text(text, source="unit") == []
