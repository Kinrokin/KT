from __future__ import annotations

import hashlib
import importlib.util
import json
import copy
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8-sig"))


def canonical_sha(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def load_semantic_court():
    spec = importlib.util.spec_from_file_location("semantic", ROOT / "scripts/validate_livewire_semantic_invariants.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_envelope_tool():
    spec = importlib.util.spec_from_file_location("envelope", ROOT / "scripts/canonical_payload_envelope.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_artifact_builder():
    spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build_livewire_pr_a_artifacts.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_text(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def source_index_with_source(source: dict):
    return {
        "schema_id": "kt.livewire.source_evidence_index.v2",
        "observed_main": None,
        "starting_main_head": None,
        "build_subject_head": "a" * 40,
        "validated_at_head": None,
        "merged_main_head": None,
        "origin_main_discovery_status": "UNKNOWN",
        "created_utc": "2026-06-23T00:00:00Z",
        "law": "test",
        "sources": [source],
    }


def source_row(**overrides):
    row = {
        "source_id": "src:test",
        "authority_class": "LIVE_CANONICAL",
        "packet_relative_path": None,
        "repo_path": "governance/current_claim_ceiling.json",
        "external_locator": None,
        "head": None,
        "head_binding_mode": "CHECKOUT_RELATIVE_CURRENT_TREE",
        "sha256": sha256_file(ROOT / "governance/current_claim_ceiling.json"),
        "bytes": (ROOT / "governance/current_claim_ceiling.json").stat().st_size,
        "transport_identity_status": "BYTE_IDENTICAL",
        "controlling": True,
    }
    row.update(overrides)
    return row


def test_stop300_cleanroom_receipt_preserves_official_block_and_counterfactual_split():
    recompute = load("evidence/stop300/stop300_cleanroom_recomputation_v2.json")
    assert recompute["derived_field_dependency_count"] == 0
    assert recompute["record_count_total"] == 1185
    assert recompute["measured_record_count"] == 1176
    assert recompute["natural_pair_count"] == 300
    assert recompute["timing_triplet_count"] == 180
    assert recompute["edge_execution_count"] == 36
    assert recompute["l0_correct"] == 261
    assert recompute["s1_correct"] == 261
    assert recompute["paired_correctness_damage"] == 0
    assert recompute["output_tokens_saved"] == 1500
    assert recompute["raw_prefix_mismatch_count"] == 0
    assert recompute["official_unlawful_reference_count"] == 3
    assert recompute["official_recomputed_status"] == "BLOCK_UNSAFE_STOP"
    assert recompute["repaired_counterfactual_status"] == "BLOCK_TOKEN_ECONOMICS"

    bundle = load("reports/livewire_pr_a_receipt_bundle.json")
    official = bundle["official_block_preservation_receipt"]
    counterfactual = bundle["repaired_court_counterfactual_receipt"]
    assert official["official_verdict_preserved"] is True
    assert official["official_verdict_overwritten"] is False
    assert official["official_primary_status"] == "BLOCK_UNSAFE_STOP"
    assert counterfactual["counterfactual_scope"] == "REPAIRED_COURT_ONLY_NOT_OFFICIAL_VERDICT"
    assert counterfactual["official_primary_status_remains"] == "BLOCK_UNSAFE_STOP"
    if bundle["merged_main_head"] is not None:
        serialized_bundle = json.dumps(bundle, sort_keys=True)
        assert "_branch_derived" not in serialized_bundle


def test_heavy_stop300_evidence_is_pointer_only_not_vendored():
    source_index = load("SOURCE_EVIDENCE_INDEX.json")
    sources = {source["source_id"]: source for source in source_index["sources"]}
    assert sources["src:stop300_assessment"]["packet_relative_path"] is None
    assert sources["src:stop300_assessment"]["repo_path"] is None
    assert sources["src:stop300_assessment"]["transport_identity_status"] == "REPACKAGED_NOT_BYTE_IDENTICAL"
    assert sources["src:stop300_pair_rows"]["packet_relative_path"] is None
    assert sources["src:stop300_pair_rows"]["repo_path"] is None
    assert not (ROOT / "evidence/stop300/KT_STOP300_V4_1_ASSESSMENT_ONLY_HF_RECOVERED.zip").exists()
    assert not (ROOT / "evidence/stop300/stop300_cleanroom_pair_rows_v2.jsonl").exists()


def test_graph_truth_claims_and_registry_reconcile_current_authority():
    graph = load("reports/livewire_pr_a_system_evidence_graph_payload.json")
    truth = load("reports/livewire_pr_a_current_program_truth_payload.json")
    decisions = load("reports/livewire_pr_a_claim_decisions.json")["decisions"]
    registry = load("registry/artifact_authority_registry.json")

    assert truth["generated_from_graph_sha256"] == canonical_sha(graph)
    assert truth["open_contradiction_count"] == 0

    nodes = {node["node_id"]: node for node in graph["nodes"]}
    assert nodes["fact:stop300_v41_official_block"]["status"] == "BLOCK_UNSAFE_STOP"
    assert nodes["fact:stop300_v41_counterfactual"]["status"] == "BLOCK_TOKEN_ECONOMICS_COUNTERFACTUAL_ONLY"
    assert nodes["authority:stop300_run_next_demoted"]["authority_state"] == "STALE"
    assert nodes["product:stop300_verify_demo"]["status"] == "NOT_PRODUCTIZED"

    decision = decisions[0]
    assert decision["decision"] == "ALLOW_INTERNAL"
    assert "runtime authority" in decision["forbidden_claim_classes"]
    assert "official result remains BLOCK_UNSAFE_STOP" in decision["limitations"]

    artifacts = {artifact["artifact_id"]: artifact for artifact in registry["artifacts"]}
    assert artifacts["stop300_v41_packet_decision"]["authority_state"] == "STALE"
    assert artifacts["stop300_v41_packet_decision"]["controls_execution"] is False

    assert graph["build_subject_head"] == graph["generated_from_head"]
    assert truth["build_subject_head"] == graph["build_subject_head"]
    assert truth["merged_main_head"] == graph["merged_main_head"]
    if graph["merged_main_head"] is None:
        assert artifacts["livewire_pr_a_system_evidence_graph_payload"]["authority_state"] == "GENERATED_PENDING_VALIDATION"
        assert all(node["authority_state"] != "CURRENT_HEAD" for node in graph["nodes"])
        assert all(node["claim_authority"] != "CURRENT_HEAD" for node in graph["nodes"])
    else:
        assert graph["validated_at_head"] == graph["merged_main_head"] == graph["generated_from_head"]
        assert artifacts["livewire_pr_a_system_evidence_graph_payload"]["authority_state"] == "LIVE_CURRENT_HEAD_VALIDATED"
        assert not any(node["authority_state"] == "BRANCH_DERIVED_PENDING_PROTECTED_MERGE" for node in graph["nodes"])


def test_semantic_court_rejects_false_pass_fixtures():
    court = load_semantic_court()
    source_index = load("SOURCE_EVIDENCE_INDEX.json")
    graph = load("reports/livewire_pr_a_system_evidence_graph_payload.json")
    court.validate_source_index(source_index, ROOT)
    court.validate_graph(graph, source_index)
    court.validate_current_truth(load("reports/livewire_pr_a_current_program_truth_payload.json"), graph)
    court.validate_claim_decisions(load("reports/livewire_pr_a_claim_decisions.json")["decisions"], graph)

    bad_graph = copy.deepcopy(graph)
    bad_graph["contradictions"] = [
        {
            "contradiction_id": "bad:open",
            "subject": "open contradiction must fail",
            "conflicting_source_refs": ["src:stop300_cleanroom", "src:claim_ceiling_snapshot"],
            "status": "OPEN",
            "resolution_ref": None,
        }
    ]
    try:
        court.validate_graph(bad_graph, source_index)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted open graph contradiction")

    bad_truth = copy.deepcopy(load("reports/livewire_pr_a_current_program_truth_payload.json"))
    bad_truth["generated_from_graph_sha256"] = "0" * 64
    try:
        court.validate_current_truth(bad_truth, graph)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted mismatched graph digest")

    bad_decisions = copy.deepcopy(load("reports/livewire_pr_a_claim_decisions.json"))["decisions"]
    bad_decisions[0]["decision"] = "BLOCK"
    try:
        court.validate_claim_decisions(bad_decisions, graph)
    except court.SemanticError:
        pass
    else:
        raise AssertionError("semantic court accepted a BLOCK decision with allowed claims")


def test_source_index_path_validation_rejects_hostile_local_paths(tmp_path):
    court = load_semantic_court()
    root = tmp_path / "root"
    root.mkdir()
    safe = root / "safe.json"
    safe.write_text('{"ok": true}\n', encoding="utf-8")
    size = safe.stat().st_size
    digest = sha256_file(safe)

    court.validate_local_regular_file(
        trusted_root=root,
        relative_path="safe.json",
        declared_bytes=size,
        declared_sha256=digest,
        source_id="src:test",
        field_name="repo_path",
    )

    sibling = tmp_path / "root_evil"
    sibling.mkdir()
    (sibling / "safe.json").write_text("evil\n", encoding="utf-8")
    hostile_paths = [
        "../root_evil/safe.json",
        str(safe.resolve()),
        "C:/Users/attacker/safe.json",
        "safe\\json",
        ".",
    ]
    for hostile in hostile_paths:
        with pytest.raises(court.SemanticError):
            court.validate_local_regular_file(
                trusted_root=root,
                relative_path=hostile,
                declared_bytes=size,
                declared_sha256=digest,
                source_id="src:bad",
                field_name="repo_path",
            )

    directory = root / "directory"
    directory.mkdir()
    with pytest.raises(court.SemanticError):
        court.validate_local_regular_file(
            trusted_root=root,
            relative_path="directory",
            declared_bytes=0,
            declared_sha256="0" * 64,
            source_id="src:directory",
            field_name="repo_path",
        )

    link = root / "link.json"
    try:
        link.symlink_to(safe)
    except OSError:
        link = None
    if link is not None:
        with pytest.raises(court.SemanticError):
            court.validate_local_regular_file(
                trusted_root=root,
                relative_path="link.json",
                declared_bytes=size,
                declared_sha256=digest,
                source_id="src:symlink_leaf",
                field_name="repo_path",
            )


def test_source_index_validates_repo_path_even_without_packet_relative_path():
    court = load_semantic_court()
    claim_path = ROOT / "governance/current_claim_ceiling.json"
    bad_index = source_index_with_source(source_row(
        source_id="src:repo_hash_mismatch",
        sha256="0" * 64,
        bytes=claim_path.stat().st_size,
    ))
    with pytest.raises(court.SemanticError, match="repo_path_hash_mismatch"):
        court.validate_source_index(bad_index, ROOT)


def test_source_index_commit_bound_repo_path_must_match_declared_commit_bytes():
    court = load_semantic_court()
    current_head = git_text("rev-parse", "HEAD")
    current_path = ROOT / "governance/current_claim_ceiling.json"
    exact = source_index_with_source(source_row(
        source_id="src:commit_exact",
        head=current_head,
        head_binding_mode="COMMIT_BOUND",
        sha256=sha256_file(current_path),
        bytes=current_path.stat().st_size,
    ))
    court.validate_source_index(exact, ROOT)

    path_for_mismatch = "governance/current_claim_ceiling.json"
    mismatch = source_index_with_source(source_row(
        source_id="src:commit_wrong_hash",
        repo_path=path_for_mismatch,
        head=current_head,
        head_binding_mode="COMMIT_BOUND",
        sha256="0" * 64,
        bytes=(ROOT / path_for_mismatch).stat().st_size,
    ))
    with pytest.raises(court.SemanticError, match="repo_path_commit_hash_mismatch"):
        court.validate_source_index(mismatch, ROOT)


def test_source_index_checkout_relative_and_pointer_modes_are_explicit():
    court = load_semantic_court()
    checkout = source_index_with_source(source_row(source_id="src:checkout_current"))
    court.validate_source_index(checkout, ROOT)

    missing_mode_row = source_row(source_id="src:missing_mode")
    missing_mode_row.pop("head_binding_mode")
    with pytest.raises(court.SemanticError, match="head_binding_mode_invalid"):
        court.validate_source_index(source_index_with_source(missing_mode_row), ROOT)

    head_not_null = source_index_with_source(source_row(source_id="src:bad_checkout_head", head="a" * 40))
    with pytest.raises(court.SemanticError, match="checkout_binding_head_not_null"):
        court.validate_source_index(head_not_null, ROOT)

    pointer = source_index_with_source(source_row(
        source_id="src:pointer",
        authority_class="EXTERNAL_POINTER",
        repo_path=None,
        external_locator="hf://datasets/Kinrokin/example",
        head=None,
        head_binding_mode="EXTERNAL_POINTER",
        transport_identity_status="NOT_APPLICABLE",
    ))
    court.validate_source_index(pointer, ROOT)


def test_canonical_envelope_payload_paths_are_repo_relative_posix(tmp_path):
    envelope = load_envelope_tool()
    repo_root = tmp_path / "repo"
    payload_dir = repo_root / "reports"
    payload_dir.mkdir(parents=True)
    payload = payload_dir / "payload.json"
    payload.write_text('{"schema_id": "x"}\n', encoding="utf-8")

    resolved, normalized = envelope.resolve_repo_payload_path(repo_root, "reports/payload.json")
    assert resolved == payload.resolve()
    assert normalized == "reports/payload.json"

    hostile = [
        "reports\\payload.json",
        str(payload.resolve()),
        "../payload.json",
        "C:/payload.json",
    ]
    for candidate in hostile:
        with pytest.raises(SystemExit):
            envelope.resolve_repo_payload_path(repo_root, candidate)

    link = payload_dir / "link.json"
    try:
        link.symlink_to(payload)
    except OSError:
        link = None
    if link is not None:
        with pytest.raises(SystemExit):
            envelope.resolve_repo_payload_path(repo_root, "reports/link.json")


def test_envelope_verify_rejects_non_normalized_payload_path(tmp_path):
    repo_root = tmp_path / "repo"
    payload_dir = repo_root / "reports"
    payload_dir.mkdir(parents=True)
    payload = payload_dir / "payload.json"
    payload.write_text('{"schema_id": "x"}\n', encoding="utf-8")
    env = repo_root / "reports/payload.envelope.json"
    tool = load_envelope_tool()
    envelope_obj = tool.build_envelope(
        {"schema_id": "x"},
        payload_schema_id="x",
        payload_path="reports\\payload.json",
        generated_from_head="a" * 40,
        source_set_sha256="b" * 64,
        build_execution_id="test",
    )
    env.write_text(json.dumps(envelope_obj), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--payload",
            "reports/payload.json",
            "--envelope",
            str(env),
            "--payload-schema-id",
            "x",
            "--head",
            "a" * 40,
            "--source-set-sha256",
            "b" * 64,
            "--repo-root",
            str(repo_root),
            "--verify",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "envelope_payload_path_mismatch" in result.stderr or "envelope_payload_path_mismatch" in result.stdout


def test_envelope_verify_rejects_stale_self_consistent_envelope_metadata(tmp_path):
    repo_root = tmp_path / "repo"
    payload_dir = repo_root / "reports"
    payload_dir.mkdir(parents=True)
    payload_obj = {
        "schema_id": "x",
        "generated_from_head": "a" * 40,
        "source_set_sha256": "b" * 64,
    }
    payload = payload_dir / "payload.json"
    payload.write_text(json.dumps(payload_obj), encoding="utf-8")
    env = repo_root / "reports/payload.envelope.json"
    tool = load_envelope_tool()
    stale_envelope = tool.build_envelope(
        payload_obj,
        payload_schema_id="x",
        payload_path="reports/payload.json",
        generated_from_head="c" * 40,
        source_set_sha256="d" * 64,
        build_execution_id="test",
    )
    env.write_text(json.dumps(stale_envelope), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--payload",
            "reports/payload.json",
            "--envelope",
            str(env),
            "--repo-root",
            str(repo_root),
            "--verify",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "envelope_head_mismatch" in result.stderr or "envelope_head_mismatch" in result.stdout


def test_envelope_verify_rejects_stale_self_consistent_source_set_metadata(tmp_path):
    repo_root = tmp_path / "repo"
    payload_dir = repo_root / "reports"
    payload_dir.mkdir(parents=True)
    payload_obj = {
        "schema_id": "x",
        "generated_from_head": "a" * 40,
        "source_set_sha256": "b" * 64,
    }
    payload = payload_dir / "payload.json"
    payload.write_text(json.dumps(payload_obj), encoding="utf-8")
    env = repo_root / "reports/payload.envelope.json"
    tool = load_envelope_tool()
    stale_envelope = tool.build_envelope(
        payload_obj,
        payload_schema_id="x",
        payload_path="reports/payload.json",
        generated_from_head="a" * 40,
        source_set_sha256="d" * 64,
        build_execution_id="test",
    )
    env.write_text(json.dumps(stale_envelope), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--payload",
            "reports/payload.json",
            "--envelope",
            str(env),
            "--repo-root",
            str(repo_root),
            "--verify",
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "envelope_source_set_mismatch" in result.stderr or "envelope_source_set_mismatch" in result.stdout


def test_envelope_verify_rejects_empty_payload_fields_and_explicit_conflicts(tmp_path):
    repo_root = tmp_path / "repo"
    payload_dir = repo_root / "reports"
    payload_dir.mkdir(parents=True)
    tool = load_envelope_tool()

    def run_with_payload(payload_obj, *extra_args):
        payload = payload_dir / "payload.json"
        payload.write_text(json.dumps(payload_obj), encoding="utf-8")
        env = repo_root / "reports/payload.envelope.json"
        envelope_obj = tool.build_envelope(
            payload_obj,
            payload_schema_id=payload_obj.get("schema_id") or "x",
            payload_path="reports/payload.json",
            generated_from_head="a" * 40,
            source_set_sha256="b" * 64,
            build_execution_id="test",
        )
        env.write_text(json.dumps(envelope_obj), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/canonical_payload_envelope.py"),
                "--payload",
                "reports/payload.json",
                "--envelope",
                str(env),
                "--repo-root",
                str(repo_root),
                "--verify",
                *extra_args,
            ],
            cwd=repo_root,
            text=True,
            capture_output=True,
        )

    empty_head = run_with_payload({"schema_id": "x", "generated_from_head": "", "source_set_sha256": "b" * 64})
    assert empty_head.returncode != 0
    assert "payload_head_empty" in empty_head.stderr or "payload_head_empty" in empty_head.stdout

    whitespace_source = run_with_payload({"schema_id": "x", "generated_from_head": "a" * 40, "source_set_sha256": "   "})
    assert whitespace_source.returncode != 0
    assert "payload_source_set_sha256_empty" in whitespace_source.stderr or "payload_source_set_sha256_empty" in whitespace_source.stdout

    wrong_type_head = run_with_payload({"schema_id": "x", "generated_from_head": 123, "source_set_sha256": "b" * 64})
    assert wrong_type_head.returncode != 0
    assert "payload_head_invalid_type" in wrong_type_head.stderr or "payload_head_invalid_type" in wrong_type_head.stdout

    empty_explicit = run_with_payload(
        {"schema_id": "x", "generated_from_head": None, "source_set_sha256": "b" * 64},
        "--head",
        "",
    )
    assert empty_explicit.returncode != 0
    assert "explicit_head_empty" in empty_explicit.stderr or "explicit_head_empty" in empty_explicit.stdout

    conflicting_explicit = run_with_payload(
        {"schema_id": "x", "generated_from_head": "a" * 40, "source_set_sha256": "b" * 64},
        "--head",
        "c" * 40,
    )
    assert conflicting_explicit.returncode != 0
    assert "explicit_head_payload_mismatch" in conflicting_explicit.stderr or "explicit_head_payload_mismatch" in conflicting_explicit.stdout


def test_metadata_path_rejects_windows_drive_relative_paths(tmp_path):
    envelope = load_envelope_tool()
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    hostile_paths = [
        "C:relative\\path",
        "C:relative/path",
        "D:foo",
        "\\rooted\\not-native-absolute",
    ]
    for candidate in hostile_paths:
        with pytest.raises(SystemExit):
            envelope.resolve_repo_metadata_path(repo_root, candidate)


def test_metadata_path_requires_existing_contained_regular_file(tmp_path):
    envelope = load_envelope_tool()
    repo_root = tmp_path / "repo"
    reports = repo_root / "reports"
    reports.mkdir(parents=True)
    valid = reports / "payload.envelope.json"
    valid.write_text("{}", encoding="utf-8")
    assert envelope.resolve_repo_metadata_path(repo_root, "reports/payload.envelope.json") == valid.resolve()
    assert envelope.resolve_repo_metadata_path(repo_root, str(valid.resolve())) == valid.resolve()

    for candidate in ("reports/missing.envelope.json", "../outside.json", ".", "reports"):
        with pytest.raises(SystemExit):
            envelope.resolve_repo_metadata_path(repo_root, candidate)

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit):
        envelope.resolve_repo_metadata_path(repo_root, str(outside.resolve()))

    link = reports / "link.envelope.json"
    try:
        link.symlink_to(valid)
    except OSError:
        link = None
    if link is not None:
        with pytest.raises(SystemExit):
            envelope.resolve_repo_metadata_path(repo_root, "reports/link.envelope.json")


def test_canonical_envelope_verify_defaults_are_paired_and_repo_root_resolved(tmp_path):
    default_verify = subprocess.run(
        [sys.executable, str(ROOT / "scripts/canonical_payload_envelope.py"), "--verify"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert default_verify.returncode == 0, default_verify.stderr

    outside_verify = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--verify",
            "--repo-root",
            str(ROOT),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert outside_verify.returncode == 0, outside_verify.stderr

    only_payload = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--verify",
            "--payload",
            "reports/livewire_pr_a_system_evidence_graph_payload.json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert only_payload.returncode != 0
    assert "requires --payload and --envelope" in only_payload.stderr

    only_envelope = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--verify",
            "--envelope",
            "reports/livewire_pr_a_system_evidence_graph_payload.envelope.json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert only_envelope.returncode != 0
    assert "requires --payload and --envelope" in only_envelope.stderr


def test_pr_b_next_tranche_envelope_is_repo_relative_and_verifiable(tmp_path):
    decision = load("reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.json")
    assert decision["handoff_mode"] == "BRANCH_SIDE_COMPILE_EVIDENCE_NOT_EXECUTION_HANDOFF"
    assert decision["pr_b_execution_authorized"] is False
    prompt = (ROOT / "reports/livewire_pr_b_compiled_from_merged_main/COPY_PASTE_NEXT.txt").read_text(encoding="utf-8")
    assert "DO NOT EXECUTE PR B FROM THIS COMMITTED ARTIFACT" in prompt
    envelope = load("reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.envelope.json")
    assert envelope["payload_path"] == "reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/canonical_payload_envelope.py"),
            "--verify",
            "--repo-root",
            str(ROOT),
            "--payload",
            "reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.json",
            "--envelope",
            "reports/livewire_pr_b_compiled_from_merged_main/NEXT_TRANCHE_DECISION.envelope.json",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


def test_origin_main_discovery_fails_soft(monkeypatch):
    builder = load_artifact_builder()

    def fail_git_text(*_args):
        raise subprocess.CalledProcessError(128, "git rev-parse origin/main", output="fatal: no remote")

    monkeypatch.setattr(builder, "git_text", fail_git_text)
    result = builder.discover_git_ref("origin/main")
    assert result["status"] == "UNKNOWN"
    assert result["head"] is None
