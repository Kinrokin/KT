from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_wave5_cli_emits_scoped_final_truth_surfaces(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    state_core = tmp_path / "state_core.json"
    blocker_matrix = tmp_path / "blocker_matrix.json"
    runtime_truth = tmp_path / "runtime_truth.json"
    verifier_truth = tmp_path / "verifier_truth.json"
    release_truth = tmp_path / "release_truth.json"
    product_truth = tmp_path / "product_truth.json"
    claim_matrix = tmp_path / "claim_matrix.json"
    tier_ruling = tmp_path / "tier_ruling.json"
    gap_register = tmp_path / "gap_register.json"
    disposition = tmp_path / "disposition.json"
    receipt = tmp_path / "receipt.json"
    telemetry = tmp_path / "telemetry.jsonl"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.wave5_final_readjudication_and_tier_ruling_validate",
            "--state-core-output",
            str(state_core),
            "--blocker-matrix-output",
            str(blocker_matrix),
            "--runtime-truth-output",
            str(runtime_truth),
            "--verifier-truth-output",
            str(verifier_truth),
            "--release-truth-output",
            str(release_truth),
            "--product-truth-output",
            str(product_truth),
            "--claim-matrix-output",
            str(claim_matrix),
            "--tier-ruling-output",
            str(tier_ruling),
            "--gap-register-output",
            str(gap_register),
            "--disposition-output",
            str(disposition),
            "--receipt-output",
            str(receipt),
            "--telemetry-output",
            str(telemetry),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["tier_id"] == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1"
    assert payload["externality_ceiling"] == "E1_SAME_HOST_DETACHED_REPLAY"

    receipt_payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert receipt_payload["status"] == "PASS"
    assert receipt_payload["remaining_open_contradictions"] == [
        "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"
    ]
    assert "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED" not in receipt_payload["remaining_open_contradictions"]
    assert "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" not in receipt_payload["remaining_open_contradictions"]

    claim_matrix_payload = json.loads(claim_matrix.read_text(encoding="utf-8"))
    dims = {row["dimension"]: row["claim_class"] for row in claim_matrix_payload["dimensions"]}
    assert dims["runtime_truth"] == "CURRENT_HEAD_PARTIALLY_PROVEN_MINIMUM_VIABLE_ORGANISM_RUN"
    assert dims["external_confirmation"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert dims["release_truth"] == "CARRIED_FORWARD_BOUNDED_RELEASE_SURFACE_PRESENT_ON_CURRENT_HEAD"
    assert dims["product_truth"] == "CARRIED_FORWARD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_PRESENT_ON_CURRENT_HEAD"

    tier_payload = json.loads(tier_ruling.read_text(encoding="utf-8"))
    assert tier_payload["status"] == "PASS"
    assert "E3 independent hostile replay" in tier_payload["unearned_truths"]
    assert "cross-host or outsider-verified live-provider capability" in tier_payload["unearned_truths"]
    assert "commercial or enterprise readiness" in tier_payload["unearned_truths"]
    objective_rows = {row["objective_id"]: row for row in tier_payload["continuing_governed_advancement_objectives"]}
    assert objective_rows["ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION"]["status"] == "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE"
    assert "not mean abandoned" in objective_rows["ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION"]["boundary"]

    gap_payload = json.loads(gap_register.read_text(encoding="utf-8"))
    gap_ids = {row["gap_id"] for row in gap_payload["rows"]}
    assert gap_ids == {"C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"}
    gap_rows = {row["gap_id"]: row for row in gap_payload["rows"]}
    assert "prep-ready" in gap_rows["C006_EXTERNALITY_CEILING_REMAINS_BOUNDED"]["summary"].lower()

    disposition_payload = json.loads(disposition.read_text(encoding="utf-8"))
    rows = {row["organ_id"]: row for row in disposition_payload["rows"]}
    assert rows["router"]["disposition"] == "RATIFIED_STATIC_CANONICAL_BASELINE"
    assert "ratified" in rows["router"]["bounded_summary"].lower()
    assert "not abandon" in rows["router"]["bounded_summary"].lower()
    assert rows["router"]["continuing_governed_objective_id"] == "ROUTER_SUPERIORITY_AND_MULTI_LOBE_PROMOTION"
    assert rows["router"]["continuing_governed_objective_status"] == "ACTIVE_GOVERNED_ADVANCEMENT_OBJECTIVE"
    assert rows["detached_verifier"]["externality_class"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert rows["adapter_layer"]["disposition"] == "REALIZED_BOUNDED_CANONICAL_SAME_HOST_LIVE_HASHED"
