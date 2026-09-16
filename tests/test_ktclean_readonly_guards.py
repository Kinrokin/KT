from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "KT_PROD_CLEANROOM/tools/growth/eval_harness_plus"))

import pytest

from scripts import check_artifact_authority_registry as authority
from scripts import check_no_bloat as bloat
from KT_PROD_CLEANROOM.tools.growth import analyze_autonomous_run, analyze_escalation
from KT_PROD_CLEANROOM.tools.growth.eval_harness_plus import eval_plus_runner
from scripts.artifact_authority_registry_writer import (
    DIGEST_SEMANTICS,
    bind_current_file_digests,
    existing_artifact_ids_for_paths,
    merge_registry_entries,
    rebind_authority_registry_file,
    _normalize_explicit_nonexecuting_rows,
    _repository_path,
)


ROOT = Path(__file__).resolve().parents[1]


def write_json(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def row(path, identity):
    return {"artifact_id": identity, "path": path, "role": "canonical_source",
            "primary_class": "CANONICAL_SOURCE", "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PENDING", "controls_execution": False,
            "claim_authority": "NONE", "sha256": None, "current_authority": False,
            "current_file_sha256": hashlib.sha256(b"pass\n").hexdigest()}


@pytest.fixture
def checkout(tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "source.py").write_bytes(b"pass\n")
    (tmp_path / "memory").mkdir()
    (tmp_path / "memory" / "DECISION_LOG.jsonl").write_bytes(b"{}\n")
    subprocess.run(["git", "add", "source.py", "memory/DECISION_LOG.jsonl"], cwd=tmp_path, check=True)
    write_json(tmp_path, "reports/repo_pristine_census_v1.json", {"duplicate_current_authority_status": "PASS"})
    write_json(tmp_path, "reports/repo_path_length_risk_index_v1.json", {"blocker_count": 0})
    write_json(tmp_path, "governance/repo_layout_contract.json", {"current_packet": None})
    write_json(tmp_path, "packets/current/manifest.json", {"packets": []})
    write_json(tmp_path, "memory/ARTIFACT_INDEX.json",
               {"current_packet": None, "current_packet_sha256": None,
                "selection_state": "NO_CURRENT_EXECUTION_PACKET"})
    write_json(tmp_path, "reports/current/current_truth_receipt.json",
               {"current_packet": None, "current_packet_sha256": None, "next_lawful_move": None,
                "selection_state": "NO_CURRENT_EXECUTION_PACKET"})
    (tmp_path / "memory" / "CURRENT_CONTEXT.md").write_text(
        "# Current Context\n\nCurrent packet: none.\n\n"
        "Current packet SHA256: none.\n\nNext lawful move: none.\n",
        encoding="utf-8",
    )
    (tmp_path / "memory" / "NEXT_LAWFUL_MOVE.md").write_text(
        "# Next Lawful Move\n\nCurrent packet: none.\n\n"
        "Current packet SHA256: none.\n\nNext lawful move: none.\n",
        encoding="utf-8",
    )
    (tmp_path / "memory" / "ACTIVE_CUTLINE.md").write_text(
        "# Active Cutline\n\nCurrent packet: none.\n\n"
        "Current packet SHA256: none.\n\nActive execution lane: none.\n",
        encoding="utf-8",
    )
    write_json(tmp_path, "registry/artifact_authority_registry.schema.json",
               json.loads((ROOT / "registry/artifact_authority_registry.schema.json").read_text(encoding="utf-8")))
    write_json(tmp_path, "registry/artifact_authority_registry.json",
               {"schema_id": "kt.artifact_authority_registry.v3", "current_head": "fixture",
                "generated_utc": "fixture", "artifact_count": 2,
                "digest_semantics": {"sha256": "HISTORICAL_REGISTRATION_BYTES",
                                     "current_file_sha256": "CURRENT_REPOSITORY_BYTES",
                                     "self_excluded_path": "registry/artifact_authority_registry.json"},
                "artifacts": [row("source.py", "one"),
                              {**row("memory/DECISION_LOG.jsonl", "historical_decision_log"),
                               "role": "archive_history", "primary_class": "ARCHIVE_HISTORY",
                               "authority_state": "ARCHIVE",
                               "current_file_sha256": hashlib.sha256(b"{}\n").hexdigest()}]})
    return tmp_path


def change_registry(root, mutate):
    name = "registry/artifact_authority_registry.json"
    value = json.loads((root / name).read_text(encoding="utf-8"))
    mutate(value)
    write_json(root, name, value)



@pytest.mark.parametrize("value", ["CON", "con.txt", "LPT9.log"])
def test_reserved_windows_device_names_fail_closed_across_path_guards(tmp_path, value):
    with pytest.raises(ValueError, match="unsafe_epoch_path_component"):
        analyze_autonomous_run._safe_child(tmp_path, value, label="epoch")
    with pytest.raises(ValueError, match="unsafe_epoch_path_component"):
        analyze_escalation._safe_epoch_dir(tmp_path, value)
    with pytest.raises(ValueError, match="nonportable_path_component"):
        eval_plus_runner._reject_nonportable_path_components(
            path=Path("safe") / value, label="output"
        )
    with pytest.raises(ValueError, match="portable direct path"):
        _repository_path(tmp_path, value)


def test_registry_merge_preserves_existing_identity_and_authority():
    original = {
        "artifact_id": "CANONICAL_ID",
        "path": "source.py",
        "primary_class": "CANONICAL_SOURCE",
        "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
        "current_authority": True,
        "claim_authority": "INTERNAL_SHADOW",
        "sha256": "historical",
    }
    registry = {"artifacts": [original.copy()]}
    replacement = {
        **original,
        "artifact_id": "SYNTHETIC_ID",
        "primary_class": "GENERATED_OUTPUT",
        "authority_state": "ARCHIVE",
        "current_authority": False,
        "sha256": "replacement",
    }
    merge_registry_entries(registry, [replacement])
    assert registry["artifacts"] == [original]


def test_legacy_nonexecuting_normalizer_rejects_current_authority_conflict():
    registry = {
        "artifacts": [{
            "artifact_id": "legacy",
            "path": "source.py",
            "authority": "PREP",
            "controls_execution": False,
            "current_authority": True,
        }]
    }
    _normalize_explicit_nonexecuting_rows(registry)
    assert registry["artifacts"][0]["current_authority"] is True
    assert "primary_class" not in registry["artifacts"][0]


def test_valid_registry_and_shared_source_roles(checkout):
    (checkout / "other.py").write_bytes(b"pass\n")
    subprocess.run(["git", "add", "other.py"], cwd=checkout, check=True)
    change_registry(checkout, lambda r: (r["artifacts"].append(row("other.py", "two")), r.update(artifact_count=3)))
    assert authority.check(checkout) == []
    assert bloat.check(checkout) == []


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: r["artifacts"][0].pop("primary_class"), "missing required field primary_class"),
    (lambda r: r["artifacts"][0].update(primary_class="INVENTED"), "outside declared enum"),
    (lambda r: r["artifacts"][0].update(controls_execution="false"), "invalid type"),
    (lambda r: r["artifacts"][0].update(current_authority="false"), "invalid type"),
    (lambda r: r.update(artifact_count=8), "artifact_count"),
    (lambda r: r.update(artifacts=[None]), "expected object"),
    (lambda r: r["artifacts"].append(row("source.py", "two")), "duplicate artifact path"),
    (lambda r: r["artifacts"].append(row("other.py", "one")), "duplicate artifact_id"),
    (lambda r: r["artifacts"][0].update(path="../source.py"), "repository-relative"),
])
def test_invalid_registry_fails_with_named_diagnostic(checkout, mutate, expected):
    change_registry(checkout, mutate)
    assert any(expected in error for error in authority.check(checkout))


def test_new_tracked_file_requires_registration(checkout):
    (checkout / "new.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "add", "new.py"], cwd=checkout, check=True)
    assert "registry missing tracked file: new.py" in authority.check(checkout)


def test_registered_regular_file_must_also_be_tracked(checkout):
    untracked = checkout / "untracked.py"
    untracked.write_bytes(b"pass\n")
    untracked_row = row("untracked.py", "untracked")
    change_registry(checkout, lambda r: (
        r["artifacts"].append(untracked_row),
        r.update(artifact_count=3),
    ))
    errors = authority.check(checkout)
    assert "registry contains untracked file: untracked.py" in errors


def test_registry_writer_binds_current_bytes_without_rewriting_historical_identity(checkout):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    historical = "0" * 64
    registry["artifacts"][0]["sha256"] = historical
    registry["artifacts"][0].pop("current_file_sha256")

    bind_current_file_digests(registry_path, registry)

    assert registry["artifacts"][0]["sha256"] == historical
    assert registry["artifacts"][0]["current_file_sha256"] == hashlib.sha256(b"pass\n").hexdigest()
    assert registry["artifact_count"] == 2
    assert registry["digest_semantics"] == DIGEST_SEMANTICS


@pytest.mark.parametrize("mutate, expected", [
    (lambda value: value["artifacts"][0].pop("primary_class"), "missing required field primary_class"),
    (lambda value: value["artifacts"][0].update(authority_state="INVENTED"), "outside declared enum"),
    (lambda value: value["artifacts"][0].update(controls_execution=True), "execution control requires"),
])
def test_registry_writer_rejects_invalid_v3_rows_before_persistence(checkout, mutate, expected):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    original = registry_path.read_bytes()
    registry = json.loads(original)
    mutate(registry)

    with pytest.raises(ValueError, match=expected):
        bind_current_file_digests(registry_path, registry)

    assert registry_path.read_bytes() == original


def test_registry_writer_rejects_duplicate_paths_before_persistence(checkout):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    original = registry_path.read_bytes()
    registry = json.loads(original)
    registry["artifacts"].append({**row("source.py", "two")})

    with pytest.raises(ValueError, match="duplicate artifact path"):
        bind_current_file_digests(registry_path, registry)

    assert registry_path.read_bytes() == original


@pytest.mark.parametrize("alias", ["SOURCE.py", "ｓｏｕｒｃｅ.py"])
def test_registry_writer_rejects_normalized_path_alias_before_persistence(checkout, alias):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    original = registry_path.read_bytes()
    (checkout / alias).write_bytes(b"pass\n")
    registry = json.loads(original)
    registry["artifacts"].append(row(alias, "alias"))

    with pytest.raises(ValueError, match="duplicate artifact path"):
        bind_current_file_digests(registry_path, registry)

    assert registry_path.read_bytes() == original


def test_generated_artifacts_reuse_only_exact_admitted_paths(checkout):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    original = registry_path.read_bytes()
    registry = json.loads(original)
    assert existing_artifact_ids_for_paths(registry, ["source.py"]) == ["one"]
    for path in ("SOURCE.py", "missing.json"):
        with pytest.raises(ValueError, match="one exact canonical registration"):
            existing_artifact_ids_for_paths(registry, [path])
    with pytest.raises(ValueError, match="duplicate paths"):
        existing_artifact_ids_for_paths(registry, ["source.py", "source.py"])
    assert registry_path.read_bytes() == original


def test_no_current_packet_requires_archived_decision_log_registration(checkout):
    assert authority.check(checkout) == []
    change_registry(checkout, lambda r: (
        r.update(artifacts=[entry for entry in r["artifacts"]
                            if entry["path"] != "memory/DECISION_LOG.jsonl"], artifact_count=1),
    ))
    assert "current truth surfaces conflict with no-current-packet selection" in authority.check(checkout)


def test_final_rebind_refreshes_a_registered_output_written_after_initial_binding(checkout):
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    receipt = checkout / "receipt.json"
    receipt.write_bytes(b'{"phase":1}\n')
    subprocess.run(["git", "add", "receipt.json"], cwd=checkout, check=True)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["artifacts"].append(row("receipt.json", "receipt"))
    bind_current_file_digests(registry_path, registry)
    write_json(checkout, "registry/artifact_authority_registry.json", registry)
    assert authority.check(checkout) == []

    receipt.write_bytes(b'{"phase":2}\n')
    assert any("stale current file digest" in error for error in authority.check(checkout))
    rebind_authority_registry_file(registry_path)

    assert authority.check(checkout) == []


def test_accountability_writer_preserves_existing_packet_archive_authority(checkout):
    from scripts.accountability_common import update_registry

    receipt = checkout / "accountability" / "accountability_kernel_receipt.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_bytes(b'{"status":"PASS"}\n')
    packet = checkout / "packets" / "ktg3full_v12.zip"
    packet.parent.mkdir(parents=True, exist_ok=True)
    packet.write_bytes(b"historical packet fixture\n")
    delta = checkout / "registry" / "artifact_authority_registry_accountability_kernel_delta_receipt.json"
    delta.write_bytes(b'{"phase":0}\n')
    subprocess.run(
        ["git", "add", "accountability/accountability_kernel_receipt.json",
         "packets/ktg3full_v12.zip",
         "registry/artifact_authority_registry_accountability_kernel_delta_receipt.json"],
        cwd=checkout, check=True,
    )
    registry_path = checkout / "registry" / "artifact_authority_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registered = [
        {**row("accountability/accountability_kernel_receipt.json", "canonical_receipt"),
         "authority_state": "LIVE_CURRENT_HEAD_VALIDATED", "validation_status": "PASS",
         "current_authority": True, "controls_execution": True,
         "claim_authority": "INTERNAL_SHADOW", "sha256": "1" * 64},
        {**row("packets/ktg3full_v12.zip", "historical_packet"),
         "primary_class": "ARCHIVE_HISTORY", "authority_state": "ARCHIVE",
         "role": "archive_history", "sha256": "2" * 64},
        {**row("registry/artifact_authority_registry_accountability_kernel_delta_receipt.json", "delta"),
         "sha256": "3" * 64},
    ]
    registry["artifacts"].extend(registered)
    bind_current_file_digests(registry_path, registry)
    write_json(checkout, "registry/artifact_authority_registry.json", registry)

    update_registry(checkout, "fixture-head", hashlib.sha256(packet.read_bytes()).hexdigest())

    result = json.loads(registry_path.read_text(encoding="utf-8"))
    by_path = {item["path"]: item for item in result["artifacts"]}
    assert len(by_path) == len(result["artifacts"]) == 5
    assert by_path["packets/ktg3full_v12.zip"]["artifact_id"] == "historical_packet"
    assert by_path["packets/ktg3full_v12.zip"]["primary_class"] == "ARCHIVE_HISTORY"
    assert by_path["packets/ktg3full_v12.zip"]["authority_state"] == "ARCHIVE"
    assert by_path["packets/ktg3full_v12.zip"]["controls_execution"] is False
    assert by_path["packets/ktg3full_v12.zip"]["sha256"] == "2" * 64
    assert by_path["accountability/accountability_kernel_receipt.json"]["sha256"] == "1" * 64
    assert by_path["registry/artifact_authority_registry_accountability_kernel_delta_receipt.json"]["current_file_sha256"] == hashlib.sha256(delta.read_bytes()).hexdigest()
    assert authority.check(checkout) == []


def test_every_main_registry_writer_invokes_current_digest_binding():
    write_patterns = (
        "write_json(registry_path, registry)",
        "write(registry_path, registry)",
        'write_json(root / "registry" / "artifact_authority_registry.json", registry)',
        'write_json(REGISTRY / "artifact_authority_registry.json", registry)',
        "write_json(path, registry)",
        "registry_path: registry",
    )
    writers = []
    missing = []
    for script in sorted((ROOT / "scripts").glob("*.py")):
        source = script.read_text(encoding="utf-8-sig")
        if "artifact_authority_registry.json" not in source:
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if not any(pattern in segment for pattern in write_patterns):
                continue
            writers.append(f"{script.name}:{node.name}")
            if "bind_current_file_digests" not in segment:
                missing.append(f"{script.name}:{node.name}")
    assert len(writers) >= 28, writers
    assert missing == []


def test_registered_output_writers_rebind_after_their_final_output_write():
    finalizing_writers = {
        "accountability_common.py",
        "g32_common.py",
        "v13_admission_common.py",
        "v141_truth_common.py",
        "v14_omni_common.py",
        "v15_oracle_harvest_common.py",
        "v16_crossroad_shadow_common.py",
        "v17_1_canary_repair_common.py",
        "v17_5_multirescuer_common.py",
        "v17_6_oracle_autopsy_common.py",
        "v17_7_3_evidence_acquisition_common.py",
        "v17_7_3_measured_arm_build_common.py",
        "v17_7_3_measurement_authority_common.py",
        "v17_canary_coalition_common.py",
        "build_v17_7_4_real_arm_config_packet.py",
        "build_v17_7_4_realbench_packet.py",
        "build_v17_7_4_truegen_runtime_packet.py",
    }
    defects = []
    for name in sorted(finalizing_writers):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
        bind_lines = []
        final_lines = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Name) and function.id == "bind_current_file_digests":
                bind_lines.append(node.lineno)
            if isinstance(function, ast.Name) and function.id == "rebind_authority_registry_file":
                final_lines.append(node.lineno)
        if not bind_lines or not final_lines or max(final_lines) <= max(bind_lines):
            defects.append(name)
    assert defects == []


@pytest.mark.parametrize("name,function_name", [
    ("v13_admission_common.py", "run_v13_superlane"),
    ("v141_truth_common.py", "generate_all"),
    ("v14_omni_common.py", "run_v14_superlane"),
    ("v17_1_canary_repair_common.py", "build_all_outputs"),
    ("v17_5_multirescuer_common.py", "build_all_outputs"),
    ("v17_6_oracle_autopsy_common.py", "build_all_outputs"),
    ("v17_7_3_evidence_acquisition_common.py", "build_all"),
    ("v17_7_3_measured_arm_build_common.py", "build_all"),
    ("v17_7_3_measurement_authority_common.py", "build_reports"),
    ("build_v17_7_4_real_arm_config_packet.py", "build"),
    ("build_v17_7_4_realbench_packet.py", "build"),
    ("build_v17_7_4_truegen_runtime_packet.py", "build"),
])
def test_outer_builder_rebinds_after_its_final_registered_write(name, function_name):
    source = (ROOT / "scripts" / name).read_text(encoding="utf-8-sig")
    functions = [node for node in ast.parse(source).body
                 if isinstance(node, ast.FunctionDef) and node.name == function_name]
    assert len(functions) == 1
    calls = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Call)]
    writes = [node.lineno for node in calls if isinstance(node.func, ast.Name)
              and node.func.id == "write_json"]
    rebinds = [node.lineno for node in calls if isinstance(node.func, ast.Name)
               and node.func.id == "rebind_authority_registry_file"]
    assert writes and rebinds and max(rebinds) > max(writes)


def test_historical_digest_does_not_substitute_for_current_bytes(checkout):
    change_registry(checkout, lambda r: r["artifacts"][0].update(sha256="0" * 64))
    assert authority.check(checkout) == []
    (checkout / "source.py").write_bytes(b"changed\n")
    assert any("stale current file digest" in error for error in authority.check(checkout))


@pytest.mark.parametrize("state", ["ARCHIVE", "STALE", "SUPERSEDED", "RETIRED"])
def test_historical_execution_and_claim_escalation_fail(checkout, state):
    change_registry(checkout, lambda r: r["artifacts"][0].update(
        authority_state=state, controls_execution=True, current_authority=True,
        claim_authority="CURRENT_HEAD"))
    errors = authority.check(checkout)
    assert any("cannot control current execution" in error for error in errors)
    assert any("cannot elevate current claims" in error for error in errors)


@pytest.mark.parametrize("path", ["/absolute.py", "C:/escape.py", "nested/../../escape.py"])
def test_absolute_and_escaping_registered_paths_fail(checkout, path):
    change_registry(checkout, lambda r: r["artifacts"][0].update(path=path))
    assert any("repository-relative" in error for error in authority.check(checkout))


def test_link_escape_is_rejected(checkout, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "outside.py"
    outside.write_bytes(b"pass\n")
    link = checkout / "linked.py"
    link.symlink_to(outside)
    change_registry(checkout, lambda r: r["artifacts"][0].update(path="linked.py"))
    assert any("link/reparse" in error for error in authority.check(checkout))


@pytest.mark.parametrize("path", ["source.py.", "source.py ", "nested. /source.py"])
def test_windows_trailing_path_aliases_fail(checkout, path):
    change_registry(checkout, lambda r: r["artifacts"][0].update(path=path))
    assert any("nonportable trailing dot or space" in error for error in authority.check(checkout))


def test_global_packet_selection_does_not_create_permission(checkout):
    assert authority.current_packet_errors([]) == []
    packet = {**row("source.py", "one"), "primary_class": "CANONICAL_PACKET_CURRENT",
              "authority_state": "LIVE_CURRENT_HEAD_VALIDATED", "validation_status": "PASS",
              "controls_execution": True, "current_authority": True}
    assert authority.current_packet_errors([packet]) == []
    assert authority.current_packet_errors([packet, {**packet, "path": "other.py", "artifact_id": "two"}])
    assert authority.current_packet_errors([{**packet, "authority_scope": "invented_scope"}])
    assert authority.current_packet_errors([{**packet, "authority_state": "STALE"}])


@pytest.mark.parametrize("state,status", [
    ("LIVE_CURRENT_HEAD_PREP_ONLY", "PASS"),
    ("BLOCKED", "PASS"),
    ("MISSING", "PASS"),
    ("GENERATED_PENDING_VALIDATION", "PENDING"),
    ("LIVE_CURRENT_HEAD_VALIDATED", "FAIL"),
    ("LIVE_CURRENT_HEAD_VALIDATED", "PENDING"),
])
def test_execution_control_requires_validated_live_pass(checkout, state, status):
    change_registry(checkout, lambda r: r["artifacts"][0].update(
        authority_state=state,
        validation_status=status,
        controls_execution=True,
    ))
    assert any(
        "execution control requires LIVE_CURRENT_HEAD_VALIDATED with PASS" in error
        for error in authority.check(checkout)
    )


def test_stale_manifest_cannot_resurrect_a_packet(checkout):
    write_json(checkout, "packets/current/manifest.json", {"packets": [
        {"path": "packets/ktbud100_v1.zip", "current_authority": True, "sha256": "0" * 64}]})
    assert any("no-packet selection conflicts" in e for e in authority.check(checkout))


def test_no_current_packet_requires_archived_decision_log_authority(checkout):
    decision_path = checkout / "memory" / "DECISION_LOG.jsonl"
    decision_path.write_text(
        '{"next_lawful_move":"RUN_KT_BUDGET_MONITOR_GSM8K_100"}\n',
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "memory/DECISION_LOG.jsonl"], cwd=checkout, check=True)
    change_registry(checkout, lambda r: r["artifacts"][1].update(
        validation_status="PASS",
        current_file_sha256=hashlib.sha256(decision_path.read_bytes()).hexdigest(),
    ))
    assert authority.check(checkout) == []

    change_registry(checkout, lambda r: r["artifacts"][1].update(
        primary_class="CANONICAL_GOVERNANCE",
        role="canonical_governance",
        authority_state="LIVE_CURRENT_HEAD_VALIDATED",
        claim_authority="CURRENT_HEAD",
        controls_execution=True,
        current_authority=True,
    ))
    assert any("current truth surfaces conflict" in error for error in authority.check(checkout))


@pytest.mark.parametrize("surface", [
    "memory_index",
    "current_truth",
    "current_context",
    "next_lawful_move",
    "active_cutline",
    "mixed_current_context",
])
def test_stale_current_truth_surface_cannot_resurrect_a_packet(checkout, surface):
    if surface == "memory_index":
        write_json(checkout, "memory/ARTIFACT_INDEX.json",
                   {"current_packet": "packets/ktbud100_v1.zip", "current_packet_sha256": "0" * 64,
                    "selection_state": "CURRENT_EXECUTION_PACKET"})
    elif surface == "current_truth":
        write_json(checkout, "reports/current/current_truth_receipt.json",
                   {"current_packet": "packets/ktbud100_v1.zip", "current_packet_sha256": "0" * 64,
                    "next_lawful_move": "RUN_KT_BUDGET_MONITOR_GSM8K_100",
                    "selection_state": "CURRENT_EXECUTION_PACKET"})
    elif surface == "current_context":
        (checkout / "memory" / "CURRENT_CONTEXT.md").write_text(
            "Current packet: packets/other.zip\n\nCurrent packet SHA256: none.\n\n"
            "Next lawful move: none.\n",
            encoding="utf-8",
        )
    elif surface == "next_lawful_move":
        (checkout / "memory" / "NEXT_LAWFUL_MOVE.md").write_text(
            "Current packet: none.\n\nCurrent packet SHA256: none.\n\n"
            "Next lawful move: RUN_UNAUTHORIZED_PACKET\n",
            encoding="utf-8",
        )
    elif surface == "active_cutline":
        (checkout / "memory" / "ACTIVE_CUTLINE.md").write_text(
            "Current packet: none.\n\nCurrent packet SHA256: none.\n\n"
            "Active execution lane: RUN_UNAUTHORIZED_PACKET\n",
            encoding="utf-8",
        )
    else:
        (checkout / "memory" / "CURRENT_CONTEXT.md").write_text(
            "Current packet: none.\nCurrent packet: packets/other.zip\n\n"
            "Current packet SHA256: none.\n\nNext lawful move: none.\n",
            encoding="utf-8",
        )
    assert any("current truth" in error for error in authority.check(checkout))


def select_current_packet(checkout):
    packet_path = "packets/current/example.zip"
    packet = checkout / packet_path
    packet.parent.mkdir(parents=True, exist_ok=True)
    packet.write_bytes(b"selected packet\n")
    subprocess.run(["git", "add", packet_path], cwd=checkout, check=True)
    digest = hashlib.sha256(packet.read_bytes()).hexdigest()
    write_json(checkout, "governance/repo_layout_contract.json",
               {"current_packet": packet_path, "current_packet_state": "CURRENT_EXECUTION_PACKET"})
    write_json(checkout, "packets/current/manifest.json",
               {"packets": [{"path": packet_path, "current_authority": True, "sha256": digest,
                              "next_lawful_move": "RUN_SELECTED_PACKET"}]})
    write_json(checkout, "memory/ARTIFACT_INDEX.json",
               {"current_packet": packet_path, "current_packet_sha256": digest,
                "selection_state": "CURRENT_EXECUTION_PACKET"})
    write_json(checkout, "reports/current/current_truth_receipt.json",
               {"current_packet": packet_path, "current_packet_sha256": digest,
                "next_lawful_move": "RUN_SELECTED_PACKET",
                "selection_state": "CURRENT_EXECUTION_PACKET"})
    (checkout / "memory" / "CURRENT_CONTEXT.md").write_text(
        f"Current packet: {packet_path}\n\nCurrent packet SHA256: {digest}\n\n"
        "Next lawful move: RUN_SELECTED_PACKET\n",
        encoding="utf-8",
    )
    (checkout / "memory" / "NEXT_LAWFUL_MOVE.md").write_text(
        f"Current packet: {packet_path}\n\nCurrent packet SHA256: {digest}\n\n"
        "Next lawful move: RUN_SELECTED_PACKET\n",
        encoding="utf-8",
    )
    (checkout / "memory" / "ACTIVE_CUTLINE.md").write_text(
        f"Current packet: {packet_path}\n\nCurrent packet SHA256: {digest}\n\n"
        "Active execution lane: RUN_SELECTED_PACKET\n",
        encoding="utf-8",
    )
    change_registry(checkout, lambda r: (
        r["artifacts"].append({
            **row(packet_path, "selected-packet"),
            "primary_class": "CANONICAL_PACKET_CURRENT",
            "authority_state": "LIVE_CURRENT_HEAD_VALIDATED",
            "validation_status": "PASS",
            "controls_execution": True,
            "current_authority": True,
            "current_file_sha256": digest,
        }),
        r.update(artifact_count=3),
    ))
    return packet_path, digest


def test_selected_packet_binds_every_current_truth_surface(checkout):
    select_current_packet(checkout)
    assert authority.check(checkout) == []


def test_selected_packet_rejects_stale_manifest_move(checkout):
    select_current_packet(checkout)
    path = checkout / "packets/current/manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["packets"][0]["next_lawful_move"] = "RUN_STALE_PACKET"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert "current packet manifest binding mismatch" in authority.check(checkout)


@pytest.mark.parametrize("surface", ["contract", "manifest"])
def test_selected_packet_rejects_no_current_selection_state(checkout, surface):
    select_current_packet(checkout)
    if surface == "contract":
        path = checkout / "governance/repo_layout_contract.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["current_packet_state"] = "NO_CURRENT_EXECUTION_PACKET"
    else:
        path = checkout / "packets/current/manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["selection_state"] = "NO_CURRENT_EXECUTION_PACKET"
    path.write_text(json.dumps(value), encoding="utf-8")
    assert "current packet selection-state mismatch" in authority.check(checkout)


@pytest.mark.parametrize("surface", [
    "memory_index", "current_truth", "current_context", "next_lawful_move", "active_cutline",
])
def test_selected_packet_rejects_stale_truth_mirror(checkout, surface):
    _, digest = select_current_packet(checkout)
    if surface == "memory_index":
        value = json.loads((checkout / "memory/ARTIFACT_INDEX.json").read_text(encoding="utf-8"))
        value["current_packet_sha256"] = "0" * 64
        write_json(checkout, "memory/ARTIFACT_INDEX.json", value)
    elif surface == "current_truth":
        value = json.loads((checkout / "reports/current/current_truth_receipt.json").read_text(encoding="utf-8"))
        value["current_packet"] = "packets/current/stale.zip"
        write_json(checkout, "reports/current/current_truth_receipt.json", value)
    else:
        names = {
            "current_context": "CURRENT_CONTEXT.md",
            "next_lawful_move": "NEXT_LAWFUL_MOVE.md",
            "active_cutline": "ACTIVE_CUTLINE.md",
        }
        path = checkout / "memory" / names[surface]
        path.write_text(path.read_text(encoding="utf-8").replace(digest, "0" * 64), encoding="utf-8")
    assert "current packet truth-surface binding mismatch" in authority.check(checkout)


def test_duplicate_report_keys_cannot_hide_a_blocker(checkout):
    (checkout / "reports/repo_path_length_risk_index_v1.json").write_text(
        '{"blocker_count": 1, "blocker_count": 0}', encoding="utf-8")
    assert any("duplicate JSON key" in error for error in bloat.check(checkout))


def test_duplicate_registry_keys_cannot_replace_authority(checkout):
    path = checkout / "registry/artifact_authority_registry.json"
    text = path.read_text(encoding="utf-8").replace('"controls_execution": false',
                                                  '"controls_execution": true, "controls_execution": false')
    path.write_text(text, encoding="utf-8")
    assert any("duplicate JSON key" in error for error in authority.check(checkout))


@pytest.mark.parametrize("root", bloat.GROWTH_ROOTS)
def test_force_added_runtime_output_fails_even_with_old_pass_reports(checkout, root):
    for policy in bloat.POLICY_FILES:
        path = checkout / policy
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("policy", encoding="utf-8")
        subprocess.run(["git", "add", "--", policy], cwd=checkout, check=True)
    assert bloat.check(checkout) == []
    leak = root + "run/receipt.json"
    write_json(checkout, leak, {"status": "PASS"})
    subprocess.run(["git", "add", "--force", "--", leak], cwd=checkout, check=True)
    assert f"tracked runtime output: {leak}" in bloat.check(checkout)


@pytest.mark.parametrize("value", [{}, {"blocker_count": False}, {"blocker_count": -1}, [], None])
def test_malformed_retained_report_does_not_default_to_pass(checkout, value):
    write_json(checkout, "reports/repo_path_length_risk_index_v1.json", value)
    assert any("blocker_count" in error for error in bloat.check(checkout))


@pytest.mark.parametrize("module_mode", [False, True])
def test_census_check_preserves_all_existing_bytes_and_paths(checkout, module_mode):
    (checkout / "scripts").mkdir()
    for name in ("repo_pristine_census.py", "check_no_bloat.py", "check_artifact_authority_registry.py"):
        shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
    # Preserve a deliberately noncanonical manifest: validation must never replace it with BUD100.
    write_json(checkout, "packets/current/manifest.json", {"packets": [], "preserve": "existing authority"})

    def snapshot():
        return {str(p.relative_to(checkout)): hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
                for p in checkout.rglob("*")}

    before = snapshot()
    argv = ["-m", "scripts.repo_pristine_census"] if module_mode else ["scripts/repo_pristine_census.py"]
    legacy = subprocess.run([sys.executable, "-B", *argv], cwd=checkout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert legacy.returncode == 2, legacy.stderr + legacy.stdout
    assert json.loads(legacy.stdout)["status"] == "BLOCKED_LEGACY_WRITE_PATH_DISABLED"
    assert snapshot() == before
    result = subprocess.run([sys.executable, "-B", *argv, "--check"], cwd=checkout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["mode"] == "read_only"
    assert snapshot() == before
    change_registry(checkout, lambda registry: registry["artifacts"][0].pop("primary_class"))
    blocked_before = snapshot()
    blocked = subprocess.run([sys.executable, "-B", *argv, "--check"], cwd=checkout,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert blocked.returncode == 1, blocked.stderr + blocked.stdout
    assert json.loads(blocked.stdout)["mode"] == "read_only"
    assert snapshot() == blocked_before
