from __future__ import annotations

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402


def test_preflight_summary_schema_binding_validates() -> None:
    obj = {
        "schema_id": "kt.fl4.preflight_summary.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.fl4.preflight_summary.v1.json"),
        "git_sha": "a" * 40,
        "out_dir": "KT_PROD_CLEANROOM/exports/_runs/FL4_SEAL/TEST",
        "registry_path": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
        "job_id": "b" * 64,
        "job_dir": "KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/x/job_dir",
        "evidence_job_dir": "KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/x/job_dir",
        "seal_doctrine_sha256": "c" * 64,
        "env_lock_id": "d" * 64,
        "fl3_pressure_growth_gate": {"executed": True, "receipt": "growth_e2e_gate_report.json"},
    }
    validate_object_with_binding(obj)


def test_promotion_report_schema_binding_validates() -> None:
    obj = {
        "schema_id": "kt.fl4.promotion_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.fl4.promotion_report.v1.json"),
        "job_dir": "KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/x/job_dir",
        "promoted_dir": "KT_PROD_CLEANROOM/exports/adapters/a/1/0" * 6,
        "promoted_index_path": "KT_PROD_CLEANROOM/exports/adapters/promoted_index.json",
        "content_hash": "e" * 64,
        "promoted_manifest_id": "f" * 64,
        "promoted_manifest_sha256": "0" * 64,
        "canary_artifact_hash": "1" * 64,
    }
    validate_object_with_binding(obj)

