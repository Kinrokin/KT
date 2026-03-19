from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.outsider_verifier_v2 import (  # noqa: E402
    ADJUDICATION_NAME,
    MANIFEST_NAME,
    VSA_NAME,
    build_outsider_verifier_v2_report,
)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_pack(tmp_path: Path) -> None:
    data_file = tmp_path / "data" / "surface.json"
    threshold_file = tmp_path / "data" / "threshold_policy.json"
    tuf_file = tmp_path / "data" / "tuf_policy.json"
    _write(data_file, {"status": "PASS"})
    manifest = {
        "schema_id": "kt.child_campaign.public_verifier_release_manifest.v2",
        "compiled_head_commit": "head123",
        "bounded_scope": "CURRENT_HEAD_ASSURANCE_ONLY_DECLARED_CHILD_VERIFIER_SURFACES",
        "requires_secret_material": False,
        "required_env_vars": [],
        "adjudication_packet_ref": ADJUDICATION_NAME,
        "vsa_ref": VSA_NAME,
        "surface_id": "F04_CHILD_OUTSIDER_VERIFIER_V2_PACKAGE",
        "threshold_policy_package_path": "data/threshold_policy.json",
        "tuf_policy_package_path": "data/tuf_policy.json",
        "machine_output_path": "outputs/outsider_result.json",
        "human_output_path": "outputs/outsider_summary.txt",
        "allowed_claims": ["claim_a"],
        "forbidden_claims": ["claim_b"],
        "expected_open_blockers": ["release_readiness_not_proven"],
        "exit_code_contract": {
            "0_PASS": "PASS",
            "1_BOUNDED_FAIL": "BOUND",
            "2_INPUT_OR_ENV_INVALID": "INPUT",
            "3_TRUST_OR_FRESHNESS_FAIL": "TRUST",
        },
        "package_entries": [
            {
                "package_path": "data/surface.json",
                "authoritative_ref": "KT_PROD_CLEANROOM/reports/example.json",
                "role": "bounded_input",
                "sha256": _sha256(data_file),
            }
        ],
    }
    adjudication = {
        "schema_id": "kt.child_campaign.adjudication_packet.v1",
        "status": "PASS",
        "current_repo_head": "head123",
        "subject_head_commit": "head123",
        "allowed_claims": ["claim_a"],
        "forbidden_claims": ["claim_b"],
        "remaining_open_blockers": ["release_readiness_not_proven"],
    }
    vsa = {
        "schema_id": "kt.child_campaign.public_verifier_vsa.v1",
        "status": "PASS",
        "compiled_head_commit": "head123",
        "adjudication_packet_ref": ADJUDICATION_NAME,
        "allowed_claims": ["claim_a"],
        "forbidden_claims": ["claim_b"],
        "remaining_open_blockers": ["release_readiness_not_proven"],
    }
    manifest_hash = hashlib.sha256((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")).hexdigest()
    threshold_policy = {
        "status": "ACTIVE",
        "accepted_verifier_surfaces": [{"surface_id": "F04_CHILD_OUTSIDER_VERIFIER_V2_PACKAGE", "primary_manifest_sha256": manifest_hash}],
    }
    tuf_policy = {
        "status": "ACTIVE",
        "distribution_targets": [{"surface_id": "F04_CHILD_OUTSIDER_VERIFIER_V2_PACKAGE", "primary_manifest_sha256": manifest_hash}],
    }
    _write(threshold_file, threshold_policy)
    _write(tuf_file, tuf_policy)
    _write(tmp_path / MANIFEST_NAME, manifest)
    _write(tmp_path / ADJUDICATION_NAME, adjudication)
    _write(tmp_path / VSA_NAME, vsa)


def test_outsider_verifier_v2_passes_on_consistent_pack(tmp_path: Path) -> None:
    _seed_pack(tmp_path)
    report, summary, exit_code = build_outsider_verifier_v2_report(pack_root=tmp_path)
    assert exit_code == 0
    assert report["status"] == "PASS"
    assert "status: PASS" in summary


def test_outsider_verifier_v2_blocks_on_hash_mismatch(tmp_path: Path) -> None:
    _seed_pack(tmp_path)
    (tmp_path / "data" / "surface.json").write_text("{\"status\":\"FAIL\"}\n", encoding="utf-8", newline="\n")
    report, _summary, exit_code = build_outsider_verifier_v2_report(pack_root=tmp_path)
    assert exit_code == 3
    assert report["status"] == "BLOCKED"
    assert any(row["check"] == "packaged_entries_hash_bound" and row["status"] == "FAIL" for row in report["checks"])
