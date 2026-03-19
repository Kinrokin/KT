from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.follow_on_campaign_v16_validate import (  # noqa: E402
    BENCHMARK_MATRIX,
    BLOCKERS_V2,
    BOOTSTRAP_RECEIPT,
    CHILD_DAG,
    OLD_PROOF,
    OLD_STATE,
    PARENT_DAG,
    PARENT_FINAL,
    PARENT_PRODUCT,
    PHASE_RUNTIME,
    PHASE_TRUST,
    PROOF_SUPERSEDE,
    PROOF_V2,
    RELEASE,
    RUNTIME_MATRIX,
    RUNTIME_RECEIPT,
    SINGLE_REALITY,
    STATE_STALE,
    STATE_SUPERSEDE,
    STATE_V2,
    TEST_REL,
    THEATER_MATRIX,
    TOOL_REL,
    TRUST_RECEIPT,
    TRUST_ROOT,
    WS11,
    WS17A,
    WS17B,
    emit_follow_on_campaign_v16,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _touch(path: Path, text: str = "seed\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True, encoding="utf-8").strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def _seed_runtime(tmp_path: Path) -> None:
    for rel in [
        "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py",
        "KT_PROD_CLEANROOM/tests/operator/test_paradox_verification_compile.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/tests/test_multiverse_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_adapters.py",
        "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_fl4_promotion_atomic.py",
    ]:
        _touch(tmp_path / rel)
    _write_json(tmp_path / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json", {"schema_id": "kt.runtime_registry.v1", "adapters": {"entries": []}})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/adapter_registry.json", {"schema_id": "kt.adapter_registry.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/router_policy_registry.json", {"schema_id": "kt.router_policy_registry.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/tournament_law.json", {"schema_id": "kt.tournament_law.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_paradox_invariants.json", {"schema_id": "seed", "status": "ACTIVE"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_adapter_testing_gate_receipt.json", {"schema_id": "seed", "status": "PASS"})


def _seed_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    tool_source = Path(__file__).resolve().parents[2] / "tools/operator/follow_on_campaign_v16_validate.py"
    (tmp_path / TOOL_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TOOL_REL).write_text(tool_source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    (tmp_path / TEST_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TEST_REL).write_text("seed\n", encoding="utf-8", newline="\n")
    _seed_runtime(tmp_path)
    _write_json(tmp_path / PARENT_DAG, {"schema_id": "kt.governance.execution_dag.v1", "status": "ACTIVE", "campaign_completion_status": "STILL_BLOCKED", "next_lawful_workstream": None})
    _write_json(tmp_path / PARENT_FINAL, {"schema_id": "kt.operator.ws18.final_readjudication_receipt.v1", "status": "PASS", "final_verdict": {"current_head_capability_status": "NOT_EXTERNALLY_CONFIRMED", "release_eligibility": "NOT_ELIGIBLE"}})
    _write_json(tmp_path / PARENT_PRODUCT, {"schema_id": "kt.operator.ws19.product_surface_receipt.v1", "status": "PASS", "campaign_completion_status": "STILL_BLOCKED", "next_lawful_workstream": None})
    _write_json(tmp_path / OLD_STATE, {"schema_id": "kt.operator.state_vector.v1", "state_vector_id": "legacy", "adjudication_status": "PRE_ADJUDICATION_PENDING_STEP_12"})
    _write_json(tmp_path / OLD_PROOF, {"schema_id": "kt.operator.claim_proof_ceiling_compiler.v1", "status": "PASS"})
    _write_json(tmp_path / TRUST_ROOT, {"schema_id": "kt.governance.trust_root_policy.v1", "status": "EXECUTED_RERATIFIED_3_OF_3", "verifier_acceptance_impact": {"post_pass_target_state": "THRESHOLD_ROOT_ACCEPTANCE_STILL_PENDING_LATER_EXPLICIT_BUNDLE"}})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/kt_signer_topology.json", {"schema_id": "kt.governance.signer_topology.v1", "status": "EXECUTED_RERATIFIED_3_OF_3"})
    _write_json(tmp_path / RELEASE, {"schema_id": "kt.governance.release_ceremony.v1", "status": "ACTIVE_LOCKED_PENDING_EXECUTION_PREREQUISITES"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json", {"schema_id": "kt.governance.determinism_envelope_policy.v1", "status": "ACTIVE"})
    _write_json(tmp_path / WS11, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS17A, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS17B, {"schema_id": "seed", "status": "PASS"})
    return _commit_all(tmp_path, "seed repo")


def test_child_campaign_bootstrap_and_runtime_baseline(tmp_path: Path) -> None:
    head = _seed_repo(tmp_path)
    summary = emit_follow_on_campaign_v16(tmp_path)
    assert summary["status"] == "PARTIAL_SUCCESS"
    assert summary["current_repo_head"] == head
    assert summary["phase_results"][PHASE_RUNTIME] == "PASS"
    assert summary["phase_results"][PHASE_TRUST] == "BLOCKED"

    runtime = json.loads((tmp_path / RUNTIME_RECEIPT).read_text(encoding="utf-8"))
    trust = json.loads((tmp_path / TRUST_RECEIPT).read_text(encoding="utf-8"))
    bench = json.loads((tmp_path / BENCHMARK_MATRIX).read_text(encoding="utf-8"))
    state = json.loads((tmp_path / STATE_V2).read_text(encoding="utf-8"))
    assert runtime["status"] == "PASS"
    assert trust["status"] == "BLOCKED"
    assert bench["coverage_percent"] >= 50.0
    assert state["next_lawful_transition"] == PHASE_TRUST

    for rel in [CHILD_DAG, SINGLE_REALITY, PROOF_V2, BLOCKERS_V2, RUNTIME_MATRIX, THEATER_MATRIX, STATE_STALE, STATE_SUPERSEDE, PROOF_SUPERSEDE, BOOTSTRAP_RECEIPT]:
        assert (tmp_path / rel).exists()


def test_child_campaign_fails_if_parent_has_illegal_next_workstream(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    broken = json.loads((tmp_path / PARENT_DAG).read_text(encoding="utf-8"))
    broken["next_lawful_workstream"] = "WS20_ILLEGAL_CONTINUATION"
    _write_json(tmp_path / PARENT_DAG, broken)
    _commit_all(tmp_path, "break parent closure")
    try:
        emit_follow_on_campaign_v16(tmp_path)
    except RuntimeError as exc:
        assert "prerequisites are not satisfied" in str(exc)
    else:
        raise AssertionError("expected fail-closed lineage error")
