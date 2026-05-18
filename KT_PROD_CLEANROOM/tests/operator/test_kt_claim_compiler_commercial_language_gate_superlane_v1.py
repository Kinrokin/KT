from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_claim_compiler_commercial_language_gate_superlane_v1 as gate


AUTHOR_HEAD = "a" * 40
MAIN_HEAD = "5589a58b502e6187bcfd67d6ad4e3679b0eebb79"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_file(source_root: Path, tmp_path: Path, raw: str) -> None:
    source = source_root / raw
    if source.is_file():
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _copy_inputs(tmp_path: Path) -> None:
    source_root = Path.cwd()
    for raw in gate.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = gate.AUTHOR_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(gate.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(gate.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(gate.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        gate,
        "validate_trust_zones",
        lambda *, root: {
            "schema_id": "trust",
            "status": trust_status,
            "failures": [] if trust_status == "PASS" else ["forced failure"],
            "checks": [{"status": trust_status}],
        },
    )


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    gate.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def gate_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("claim_compiler_gate")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / gate.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(gate.REASON_CODES) == len(set(gate.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(gate.OUTPUTS.values()))
def test_outputs_exist(gate_outputs: Path, raw: str) -> None:
    path = gate_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "Commercial activation claims authorized: false" in text


def test_gate_selects_validation_next(gate_outputs: Path) -> None:
    receipt = _payload(gate_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == gate.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "VALIDATE_KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_SUPERLANE_V1"
    assert receipt["claim_compiler_commercial_language_gate_packet_authored"] is True
    assert receipt["claim_compiler_commercial_language_gate_validated"] is False


def test_gate_preserves_no_claim_expansion(gate_outputs: Path) -> None:
    receipt = _payload(gate_outputs, "no_claim_expansion_receipt")
    assert receipt["no_claim_expansion"] is True
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False
    assert receipt["fp0_or_highway_promoted_to_authority"] is False


def test_committed_packet_artifacts_share_generation_timestamp() -> None:
    source_root = Path.cwd()
    contract = _load(source_root / gate.OUTPUTS["packet_contract"])
    expected_generated_utc = contract["generated_utc"]
    mismatches = []
    for role, raw in gate.OUTPUTS.items():
        if raw.endswith(".json"):
            payload = _load(source_root / raw)
            if "generated_utc" in payload and payload.get("generated_utc") != expected_generated_utc:
                mismatches.append((role, raw, payload.get("generated_utc")))
    assert mismatches == []


def test_allowed_and_forbidden_claims_are_bound(gate_outputs: Path) -> None:
    allowed = _payload(gate_outputs, "allowed_claims_current_state")
    forbidden = _payload(gate_outputs, "forbidden_claims_current_state")
    assert "R6 is open." in allowed["allowed_claims"]
    assert "Commercial activation claims are authorized." in forbidden["forbidden_claims"]
    assert "External audit is complete." in forbidden["forbidden_claims"]
    assert allowed["allowed_claims_authorize_commercial_activation_claims"] is False


def test_commercial_surface_scan_scope_is_explicit(gate_outputs: Path) -> None:
    scope = _payload(gate_outputs, "commercial_surface_scan_scope")
    assert "KT_PROD_CLEANROOM/docs/commercial/*.md" in scope["scan_scope"]
    assert all(row["status"] == "PASS" for row in scope["commercial_doc_checks"])


def test_recursive_scanner_scans_arrays_markdown_and_strings(gate_outputs: Path) -> None:
    scanner = _payload(gate_outputs, "recursive_claim_scanner_contract")
    assert {"json_objects", "json_arrays", "json_strings", "markdown_text"} <= set(scanner["scanned_shapes"])
    assert scanner["negative_contexts_allowed"] is True


def test_machine_routing_identifiers_are_exempt(gate_outputs: Path) -> None:
    contract = _payload(gate_outputs, "machine_routing_exemption_contract")
    assert "selected_outcome" in contract["exempt_fields"]
    assert "next_lawful_move" in contract["exempt_fields"]
    assert "prose fields remain scanned" in contract["exemption_scope"]


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.PREDECESSOR_INPUTS["h02_validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_predecessor_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.PREDECESSOR_INPUTS["h02_next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_PREDECESSOR_NEXT_MOVE_DRIFT"


def test_rejects_missing_claim_ceiling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    (tmp_path / gate.CLAIM_INPUTS["claim_ceiling_current_state"]).unlink()
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_SOURCE_MISSING"


def test_rejects_commercial_activation_claim_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_PREMATURE_AUTHORITY"


@pytest.mark.parametrize(
    ("unsafe_text", "code"),
    [
        ("Commercial activation claims are authorized.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
        ("External audit is complete.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
        ("7B amplification is proven.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
        ("Beyond-SOTA is proven.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
        ("S-tier is allowed.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
        ("KT is production-commercial live.", "RC_KT_CLAIM_GATE_BOUNDARY_BREACH"),
    ],
)
def test_rejects_unsafe_claim_text_in_arrays_and_nested_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_text: str,
    code: str,
) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.PREDECESSOR_INPUTS["h02_validation_receipt"]
    payload = _load(path)
    payload["public_copy"] = {"claims": [unsafe_text]}
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == code


def test_allows_forbidden_claims_in_negative_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["forbidden_claims"].append("External audit is complete.")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    outputs = gate.run(output_root=tmp_path)
    assert outputs["packet_receipt"]["claim_boundary_passed"] is True


def test_machine_routing_outcome_ids_do_not_fail_claim_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.PREDECESSOR_INPUTS["h02_validation_receipt"]
    payload = _load(path)
    payload["allowed_outcomes"] = ["KT_S_TIER_READJUDICATED__BOUNDED_GOVERNED_EXECUTION_S_TIER_CLAIM_ALLOWED"]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    outputs = gate.run(output_root=tmp_path)
    assert outputs["packet_receipt"]["claim_boundary_passed"] is True


def test_rejects_missing_commercial_doc_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["certification_pack"]
    path.write_text("Documentary-only commercial surface.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_COMMERCIAL_SURFACE_UNBOUNDED"


def test_rejects_claim_compiler_policy_without_invariant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["claim_compiler_policy"]
    payload = _load(path)
    payload["invariants"] = []
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_TRUST_ZONE_FAILED"
