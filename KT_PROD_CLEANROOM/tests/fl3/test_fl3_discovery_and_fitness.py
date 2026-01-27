from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.verification.fl3_validators import assert_path_under_exports, read_json, validate_schema_bound_object  # noqa: E402
from tools.verification.run_discovery_battery import run_discovery_battery  # noqa: E402
from tools.verification.compute_cognitive_fitness import compute_cognitive_fitness  # noqa: E402


def _exports_shadow_root() -> Path:
    p = _REPO_ROOT / "KT_PROD_CLEANROOM" / "exports" / "adapters_shadow" / "_pytest"
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_discovery_battery_and_fitness_smoke(tmp_path: Path) -> None:
    repo_root = _REPO_ROOT
    job_dir = _exports_shadow_root() / "job_smoke"
    if job_dir.exists():
        for c in job_dir.rglob("*"):
            if c.is_file():
                c.unlink()
        for d in sorted([p for p in job_dir.rglob("*") if p.is_dir()], reverse=True):
            d.rmdir()
        job_dir.rmdir()
    job_dir.mkdir(parents=True, exist_ok=True)
    assert_path_under_exports(repo_root=repo_root, path=job_dir, allow_promoted=True)

    battery = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "DISCOVERY_BATTERY.json")
    anchor = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ANCHOR_REFERENCE_SET.json")
    role_spec = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json")
    policy = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "COGNITIVE_FITNESS_POLICY.json")

    rec_serial = run_discovery_battery(
        repo_root=repo_root,
        adapter_id="lobe.architect.v1",
        adapter_version="1",
        job_id="b" * 64,
        role_id="ARCHITECT",
        seed=42,
        battery=battery,
        anchor=anchor,
        role_spec=role_spec,
        force_canary_fail=False,
        shards=1,
        workers=1,
    )
    validate_schema_bound_object(rec_serial)
    assert rec_serial["canary_pass"] is True

    rec_sharded = run_discovery_battery(
        repo_root=repo_root,
        adapter_id="lobe.architect.v1",
        adapter_version="1",
        job_id="b" * 64,
        role_id="ARCHITECT",
        seed=42,
        battery=battery,
        anchor=anchor,
        role_spec=role_spec,
        force_canary_fail=False,
        shards=4,
        workers=4,
    )
    validate_schema_bound_object(rec_sharded)
    assert rec_sharded == rec_serial

    fitness, trace_replay = compute_cognitive_fitness(
        battery_result=rec_serial,
        anchor=anchor,
        role_spec=role_spec,
        policy=policy,
        role_id="ARCHITECT",
    )
    validate_schema_bound_object(fitness)
    assert fitness["promotion_verdict"] in {"PROMOTE", "SHADOW", "QUARANTINE"}
    assert trace_replay["trace_replay"] == "SKIPPED"

    # Evidence hashes are valid hex and stable/canonical.
    for k in ("battery_bundle_hash", "anchor_eval_hash", "trace_replay_hash"):
        v = fitness["evidence"]["evidence_hashes"][k]
        assert isinstance(v, str) and len(v) == 64
        int(v, 16)


def test_discovery_canary_failure_yields_halt() -> None:
    repo_root = _REPO_ROOT
    battery = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "DISCOVERY_BATTERY.json")
    anchor = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ANCHOR_REFERENCE_SET.json")
    role_spec = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "ROLE_FITNESS_WEIGHTS.json")
    policy = read_json(repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "COGNITIVE_FITNESS_POLICY.json")

    rec = run_discovery_battery(
        repo_root=repo_root,
        adapter_id="lobe.architect.v1",
        adapter_version="1",
        job_id="b" * 64,
        role_id="ARCHITECT",
        seed=42,
        battery=battery,
        anchor=anchor,
        role_spec=role_spec,
        force_canary_fail=True,
        shards=3,
        workers=3,
    )
    validate_schema_bound_object(rec)
    assert rec["canary_pass"] is False

    fitness, _ = compute_cognitive_fitness(
        battery_result=rec,
        anchor=anchor,
        role_spec=role_spec,
        policy=policy,
        role_id="ARCHITECT",
    )
    validate_schema_bound_object(fitness)
    assert fitness["promotion_verdict"] == "HALT"
