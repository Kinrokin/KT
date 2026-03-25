from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import post_wave5_c006_friendly_host_handoff_validate as handoff_mod
from tools.operator.post_wave5_c006_friendly_host_handoff_validate import (  # noqa: E402
    build_post_wave5_c006_friendly_host_handoff_pack,
)
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_post_wave5_c006_handoff_pack_is_explicitly_e1_only() -> None:
    pack = build_post_wave5_c006_friendly_host_handoff_pack(root=repo_root())

    assert pack["status"] == "PASS"
    assert pack["c006_status"] == "OPEN_READY_FOR_E2_FRIENDLY_HOST_HANDOFF_NOT_PROMOTED"
    assert pack["required_next_environment"] == "E_CROSS_HOST_FRIENDLY"
    assert "Do not claim E2 cross-host friendly replay" in pack["exact_remaining_forbidden_claims"][0]

    rows = {row["surface_id"]: row for row in pack["support_surface_bindings"]}
    assert rows["v2_1_1_anchor"]["head_binding_status"] == "CURRENT_HEAD_ACTIVE_ANCHOR"
    assert rows["wave5_verifier_truth"]["head_binding_status"] == "CURRENT_HEAD_BOUND"
    assert rows["external_reproduction_receipt"]["head_binding_status"] == "CARRIED_FORWARD_PREP_ONLY"
    assert rows["outsider_path_receipt"]["head_binding_status"] == "CARRIED_FORWARD_PREP_ONLY"


def test_post_wave5_c006_handoff_pack_cli_writes_output(tmp_path: Path) -> None:
    root = repo_root()
    output_path = tmp_path / "c006_handoff.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.post_wave5_c006_friendly_host_handoff_validate",
            "--output",
            str(output_path),
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
    assert payload["blocker_delta"] == "C006_NARROWED_TO_EXPLICIT_E2_FRIENDLY_HOST_HANDOFF_AWAITING_SECOND_HOST"
    assert output_path.exists()


def test_post_wave5_c006_handoff_pack_binds_verifier_truth_to_validated_subject(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(handoff_mod, "_git_head", lambda root: "carrier456")
    monkeypatch.setattr(
        handoff_mod,
        "resolve_truth_head_context",
        lambda root, live_head, dirty_lines: {
            "validated_subject_head_sha": "subject123",
            "publication_carrier_head_sha": "carrier456",
            "head_relation": "PUBLICATION_CARRIER_OF_VALIDATED_SUBJECT",
        },
    )
    monkeypatch.setattr(handoff_mod, "_git_status_lines", lambda root: [])

    payloads = {
        handoff_mod.ANCHOR_REL: {"current_authorized_scope": {"authoritative_track": "C006 only"}},
        handoff_mod.PREP_REL: {"status": "PASS", "current_externality_ceiling": "E1_SAME_HOST_DETACHED_REPLAY"},
        handoff_mod.VERIFIER_TRUTH_REL: {
            "status": "PASS",
            "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
            "compiled_head_commit": "subject123",
        },
        handoff_mod.EXTERNAL_REPRO_RECEIPT_REL: {
            "status": "PASS",
            "summary": {"stronger_claim_not_made": "does not claim cross-host"},
            "compiled_head_commit": "olderprep",
        },
        handoff_mod.OUTSIDER_PATH_REL: {"status": "PASS", "hidden_secret_dependency": "ABSENT", "compiled_head_commit": "olderprep"},
    }
    monkeypatch.setattr(handoff_mod, "_load_required", lambda root, rel: payloads[rel])
    replay_recipe = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_independent_replay_recipe.md"
    external_matrix = tmp_path / "KT_PROD_CLEANROOM" / "reports" / "kt_external_reproduction_matrix.json"
    replay_recipe.parent.mkdir(parents=True, exist_ok=True)
    replay_recipe.write_text("recipe\n", encoding="utf-8")
    external_matrix.write_text("{}\n", encoding="utf-8")

    pack = build_post_wave5_c006_friendly_host_handoff_pack(root=tmp_path)
    rows = {row["surface_id"]: row for row in pack["support_surface_bindings"]}

    assert pack["validated_subject_head_sha"] == "subject123"
    assert pack["publication_carrier_head_sha"] == "carrier456"
    assert rows["wave5_verifier_truth"]["head_binding_status"] == "CURRENT_HEAD_BOUND"
