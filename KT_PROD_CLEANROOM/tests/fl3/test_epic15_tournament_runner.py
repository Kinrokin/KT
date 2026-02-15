from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from tools.tournament.run_tournament import run_tournament  # noqa: E402
from tools.verification.fl3_validators import validate_schema_bound_object  # noqa: E402


def _sha_seed(base_model_id: str, suite_id: str, entrant_hashes: list[str]) -> str:
    payload = base_model_id + "|" + suite_id + "|" + "|".join(entrant_hashes)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, obj: dict) -> bytes:
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def _mk_eval_report_v2(*, job_id: str, adapter_id: str, adapter_version: str, utility_floor_score: float, verdict: str) -> dict:
    created_at = "1970-01-01T00:00:00Z"
    rep = {
        "schema_id": "kt.factory.eval_report.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.eval_report.v2.json"),
        "eval_id": "",
        "job_id": job_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "battery_id": "kt.eval.battery.fl4.utility_v1",
        "utility_pack_id": "UTILITY_PACK_V1",
        "utility_pack_hash": "a" * 64,
        "utility_floor_score": float(utility_floor_score),
        "utility_floor_pass": True,
        "metric_bindings": [
            {
                "metric_id": "utility_floor_score",
                "metric_version_hash": "b" * 64,
                "metric_schema_hash": "c" * 64,
                "metric_impl_hash": "d" * 64,
            }
        ],
        "metric_probes": [
            {
                "metric_id": "utility_floor_score_probe",
                "metric_impl_hash": "d" * 64,
                "delta": 0.0,
                "agreement": True,
            }
        ],
        "probe_policy": {"tolerance": 0.0, "fail_on_disagreement": True},
        "results": {
            "best_bundle_id": "B0",
            "utility_floor_score": float(utility_floor_score),
            "utility_floor_pass": True,
            "trace_required": True,
            "trace_present": True,
            "trace_coverage": 1.0,
            "trace_id": "t" * 64,
            "trace_hash": "t" * 64,
            "metric_probe_agreement": True,
        },
        "final_verdict": str(verdict),
        "created_at": created_at,
    }
    rep["eval_id"] = sha256_hex_of_obj(rep, drop_keys={"created_at", "eval_id"})
    validate_schema_bound_object(rep)
    return rep


def _mk_job_dir_manifest(*, job_id: str, adapter_root_hash: str, eval_report_bytes: bytes) -> dict:
    created_at = "1970-01-01T00:00:00Z"
    entry = {
        "schema_id": "kt.factory.job_dir_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.factory.job_dir_manifest.v1.json"),
        "job_dir_manifest_id": "",
        "job_id": job_id,
        "files": [
            {"path": "eval_report.json", "required": True, "sha256": _sha256_bytes(eval_report_bytes)},
        ],
        "hash_manifest_root_hash": adapter_root_hash,
        "parent_hash": "0" * 64,
        "created_at": created_at,
    }
    entry["job_dir_manifest_id"] = sha256_hex_of_obj(entry, drop_keys={"created_at", "job_dir_manifest_id"})
    validate_schema_bound_object(entry)
    return entry


def test_epic15_tournament_runner_bit_identical_rerun(tmp_path: Path) -> None:
    entrants_root = tmp_path / "entrants"
    out_dir = tmp_path / "out"

    a_hash = "1" * 64
    b_hash = "2" * 64

    job_a = "a" * 64
    job_b = "b" * 64

    eval_a = _mk_eval_report_v2(job_id=job_a, adapter_id="lobe.alpha.v1", adapter_version="1", utility_floor_score=0.9, verdict="PASS")
    eval_b = _mk_eval_report_v2(job_id=job_b, adapter_id="lobe.beta.v1", adapter_version="1", utility_floor_score=0.5, verdict="PASS")

    eval_a_bytes = _write_json(entrants_root / a_hash / "eval_report.json", eval_a)
    eval_b_bytes = _write_json(entrants_root / b_hash / "eval_report.json", eval_b)

    jdm_a = _mk_job_dir_manifest(job_id=job_a, adapter_root_hash=a_hash, eval_report_bytes=eval_a_bytes)
    jdm_b = _mk_job_dir_manifest(job_id=job_b, adapter_root_hash=b_hash, eval_report_bytes=eval_b_bytes)
    _ = _write_json(entrants_root / a_hash / "job_dir_manifest.json", jdm_a)
    _ = _write_json(entrants_root / b_hash / "job_dir_manifest.json", jdm_b)

    entrants = [
        {"adapter_root_hash": a_hash, "adapter_id": "lobe.alpha.v1", "adapter_version": "1"},
        {"adapter_root_hash": b_hash, "adapter_id": "lobe.beta.v1", "adapter_version": "1"},
    ]
    plan = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_plan.v1.json"),
        "tournament_plan_id": "",
        "base_model_id": "mistral-7b",
        "suite_id": "SUITE_X",
        "suite_root_hash": "c" * 64,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "d" * 64,
        "tournament_mode": "round_robin_v1",
        "epsilon": 0.01,
        "entrants": entrants,
        "seed": _sha_seed("mistral-7b", "SUITE_X", [a_hash, b_hash]),
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    plan["tournament_plan_id"] = sha256_hex_of_obj(plan, drop_keys={"created_at", "tournament_plan_id"})
    validate_schema_bound_object(plan)

    plan_path = tmp_path / "tournament_plan.json"
    _ = _write_json(plan_path, plan)

    res1 = run_tournament(repo_root=_REPO_ROOT, plan_path=plan_path, entrants_root=entrants_root, out_dir=out_dir)
    res_path = out_dir / "tournament_result.json"
    b1 = res_path.read_bytes()

    res2 = run_tournament(repo_root=_REPO_ROOT, plan_path=plan_path, entrants_root=entrants_root, out_dir=out_dir)
    b2 = res_path.read_bytes()

    assert b1 == b2
    assert res1["tournament_result_id"] == res2["tournament_result_id"]
    assert res1["champion_set"] == [a_hash]


def test_epic15_tournament_runner_fail_closed_on_missing_entrants(tmp_path: Path) -> None:
    entrants_root = tmp_path / "entrants"
    out_dir = tmp_path / "out"

    a_hash = "1" * 64
    b_hash = "2" * 64

    job_a = "a" * 64
    eval_a = _mk_eval_report_v2(job_id=job_a, adapter_id="lobe.alpha.v1", adapter_version="1", utility_floor_score=0.9, verdict="PASS")
    eval_a_bytes = _write_json(entrants_root / a_hash / "eval_report.json", eval_a)
    jdm_a = _mk_job_dir_manifest(job_id=job_a, adapter_root_hash=a_hash, eval_report_bytes=eval_a_bytes)
    _ = _write_json(entrants_root / a_hash / "job_dir_manifest.json", jdm_a)

    entrants = [
        {"adapter_root_hash": a_hash, "adapter_id": "lobe.alpha.v1", "adapter_version": "1"},
        {"adapter_root_hash": b_hash, "adapter_id": "lobe.beta.v1", "adapter_version": "1"},
    ]
    plan = {
        "schema_id": "kt.tournament_plan.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.tournament_plan.v1.json"),
        "tournament_plan_id": "",
        "base_model_id": "mistral-7b",
        "suite_id": "SUITE_X",
        "suite_root_hash": "c" * 64,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "d" * 64,
        "tournament_mode": "round_robin_v1",
        "epsilon": 0.01,
        "entrants": entrants,
        "seed": _sha_seed("mistral-7b", "SUITE_X", [a_hash, b_hash]),
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    plan["tournament_plan_id"] = sha256_hex_of_obj(plan, drop_keys={"created_at", "tournament_plan_id"})
    validate_schema_bound_object(plan)

    plan_path = tmp_path / "tournament_plan.json"
    _ = _write_json(plan_path, plan)

    try:
        _ = run_tournament(repo_root=_REPO_ROOT, plan_path=plan_path, entrants_root=entrants_root, out_dir=out_dir)
        assert False, "expected fail-closed"
    except Exception:
        pass

    res_path = out_dir / "tournament_result.json"
    assert res_path.exists()
    obj = json.loads(res_path.read_text(encoding="utf-8"))
    validate_schema_bound_object(obj)
    assert obj["status"] == "FAIL_CLOSED"
    assert "TOURNAMENT_IMMUTABLE_INPUT_MISSING" in obj.get("reason_codes", [])

