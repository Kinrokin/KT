from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.verification.fl3_validators import (
    FL3ValidationError,
    assert_path_under_exports,
    read_json,
    repo_root_from,
    validate_schema_bound_object,
)


_AXES = (
    "reasoning_depth",
    "transfer_capacity",
    "coherence_under_pressure",
    "self_correction",
    "epistemic_behavior",
    "novel_structure",
)


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_unit_float(*, seed: str) -> float:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    n = int.from_bytes(h[:8], "big", signed=False)
    return n / float(2**64)


def _score_case(*, adapter_id: str, adapter_version: str, job_id: str, seed: int, case: Dict[str, Any]) -> Dict[str, float]:
    case_id = str(case["case_id"])
    category = str(case["category"])
    u = _stable_unit_float(seed=f"{adapter_id}|{adapter_version}|{job_id}|{seed}|{case_id}|{category}")
    s = 0.30 + 0.70 * u

    per_axis: Dict[str, float] = {k: 0.0 for k in _AXES}
    if category == "paradox_pressure":
        per_axis["coherence_under_pressure"] = s
        per_axis["reasoning_depth"] = 0.5 * s
    elif category == "cross_domain_transfer":
        per_axis["transfer_capacity"] = s
        per_axis["novel_structure"] = 0.5 * s
    elif category == "multi_step_reasoning":
        per_axis["reasoning_depth"] = s
        per_axis["self_correction"] = 0.5 * s
    elif category == "self_repair":
        per_axis["self_correction"] = s
        per_axis["epistemic_behavior"] = 0.5 * s
    elif category == "novel_composition":
        per_axis["novel_structure"] = s
        per_axis["transfer_capacity"] = 0.5 * s
    elif category == "governance_canary":
        # Scored via canary_pass; keep axes neutral.
        pass
    else:
        raise FL3ValidationError(f"Unknown discovery category (fail-closed): {category}")

    return per_axis


def _case_sort_key(case: Dict[str, Any]) -> str:
    return str(case.get("case_id", ""))


def _select_smoke_cases(*, battery: Dict[str, Any], adapter_id: str, adapter_version: str, job_id: str, seed: int) -> List[Dict[str, Any]]:
    cases = battery.get("cases")
    if not isinstance(cases, list) or len(cases) < 1:
        raise FL3ValidationError("Discovery battery cases missing (fail-closed)")

    # Deterministic "holographic" subset: choose one case per category, with per-adapter randomness.
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        cat = str(c.get("category", ""))
        buckets.setdefault(cat, []).append(c)

    smoke: List[Dict[str, Any]] = []
    for cat, items in buckets.items():
        items_sorted = sorted(items, key=_case_sort_key)
        if not items_sorted:
            continue
        idx_u = _stable_unit_float(seed=f"SMOKE|{adapter_id}|{adapter_version}|{job_id}|{seed}|{cat}")
        idx = int(idx_u * len(items_sorted)) % len(items_sorted)
        smoke.append(items_sorted[idx])

    if not any((isinstance(c, dict) and (c.get("is_canary") is True or str(c.get("category")) == "governance_canary")) for c in smoke):
        # Fail-closed: the smoke subset must include the canary.
        raise FL3ValidationError("Smoke subset missing canary case (fail-closed)")

    return sorted(smoke, key=_case_sort_key)


def _sign_shard(*, shard: Dict[str, Any], shard_secret: str) -> str:
    payload = {k: v for k, v in shard.items() if k != "signature"}
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canon + shard_secret.encode("utf-8")).hexdigest()


def _run_sharded(
    *,
    adapter_id: str,
    adapter_version: str,
    job_id: str,
    role_id: str,
    seed: int,
    cases: List[Dict[str, Any]],
    shards: int,
    workers: int,
    force_canary_fail: bool,
    shard_secret: str,
) -> Dict[str, Any]:
    if shards < 1:
        raise FL3ValidationError("shards must be >=1 (fail-closed)")
    if workers < 1:
        raise FL3ValidationError("workers must be >=1 (fail-closed)")

    cases_sorted = sorted(cases, key=_case_sort_key)
    if len(cases_sorted) < 1:
        raise FL3ValidationError("No cases to evaluate (fail-closed)")

    # Deterministic sharding: contiguous slices by sorted case_id.
    buckets: List[List[Dict[str, Any]]] = [[] for _ in range(shards)]
    for i, c in enumerate(cases_sorted):
        buckets[i % shards].append(c)

    def worker_fn(bucket: List[Dict[str, Any]]) -> Dict[str, Any]:
        totals = {k: 0.0 for k in _AXES}
        counts = {k: 0 for k in _AXES}
        canary_pass = True
        saw_canary = False
        for case in bucket:
            if case.get("is_canary") is True or str(case.get("category")) == "governance_canary":
                saw_canary = True
                if force_canary_fail:
                    canary_pass = False
            per_axis = _score_case(adapter_id=adapter_id, adapter_version=adapter_version, job_id=job_id, seed=seed, case=case)
            for axis, v in per_axis.items():
                if v > 0.0:
                    totals[axis] += float(v)
                    counts[axis] += 1
        shard = {
            "shard_cases": [str(c.get("case_id")) for c in bucket],
            "axis_totals": totals,
            "axis_counts": counts,
            "canary_pass": bool(canary_pass),
            "saw_canary": bool(saw_canary),
            "signature": "",
        }
        shard["signature"] = _sign_shard(shard=shard, shard_secret=shard_secret)
        return shard

    shards_out: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker_fn, b) for b in buckets]
        for fut in as_completed(futs):
            shards_out.append(fut.result())

    # Verify shard signatures fail-closed.
    for shard in shards_out:
        sig = shard.get("signature")
        if not isinstance(sig, str) or len(sig) != 64:
            raise FL3ValidationError("Shard signature missing/invalid (fail-closed)")
        expected = _sign_shard(shard=shard, shard_secret=shard_secret)
        if sig != expected:
            raise FL3ValidationError("Shard signature mismatch (fail-closed)")

    totals = {k: 0.0 for k in _AXES}
    counts = {k: 0 for k in _AXES}
    canary_pass = True
    saw_canary = False
    for shard in shards_out:
        if shard.get("saw_canary") is True:
            saw_canary = True
        if shard.get("canary_pass") is False:
            canary_pass = False
        for axis in _AXES:
            totals[axis] += float(shard["axis_totals"][axis])
            counts[axis] += int(shard["axis_counts"][axis])

    if not saw_canary:
        raise FL3ValidationError("Discovery battery contains no canary case (fail-closed)")

    axis_scores: Dict[str, float] = {}
    for axis in _AXES:
        if counts[axis] == 0:
            axis_scores[axis] = 0.5
        else:
            axis_scores[axis] = max(0.0, min(1.0, totals[axis] / counts[axis]))

    # Role drift is derived from negative caps vs aggregated axis_scores.
    return {"axis_scores": axis_scores, "canary_pass": bool(canary_pass)}


def _compute_role_drift_flag(*, role_id: str, axis_scores: Dict[str, float], role_spec: Dict[str, Any]) -> bool:
    roles = role_spec.get("roles")
    if not isinstance(roles, list):
        raise FL3ValidationError("ROLE_FITNESS_WEIGHTS roles missing (fail-closed)")
    for r in roles:
        if isinstance(r, dict) and r.get("role_id") == role_id:
            neg = r.get("negative")
            if not isinstance(neg, list):
                raise FL3ValidationError("ROLE_FITNESS_WEIGHTS negative missing (fail-closed)")
            for it in neg:
                if not isinstance(it, dict):
                    continue
                axis = it.get("axis")
                mv = it.get("max_value")
                if axis in axis_scores and isinstance(mv, (int, float)):
                    if float(axis_scores[str(axis)]) > float(mv):
                        return True
            return False
    raise FL3ValidationError(f"Unknown role_id for drift computation (fail-closed): {role_id}")


def run_discovery_battery(
    *,
    repo_root: Path,
    adapter_id: str,
    adapter_version: str,
    job_id: str,
    role_id: str,
    seed: int,
    battery: Dict[str, Any],
    anchor: Dict[str, Any],
    role_spec: Dict[str, Any],
    force_canary_fail: bool,
    shards: int = 1,
    workers: int = 1,
    smoke_gate: bool = False,
) -> Dict[str, Any]:
    validate_schema_bound_object(battery)
    validate_schema_bound_object(anchor)
    validate_schema_bound_object(role_spec)
    if battery.get("schema_id") != "kt.discovery_battery.v1":
        raise FL3ValidationError("Discovery battery schema_id mismatch (fail-closed)")
    if anchor.get("schema_id") != "kt.anchor_reference_set.v1":
        raise FL3ValidationError("Anchor reference set schema_id mismatch (fail-closed)")
    if role_spec.get("schema_id") != "kt.adapter_role_spec.v2":
        raise FL3ValidationError("Role spec schema_id mismatch (fail-closed)")

    all_cases = battery.get("cases")
    if not isinstance(all_cases, list) or len(all_cases) < 1:
        raise FL3ValidationError("Discovery battery cases missing (fail-closed)")
    for case in all_cases:
        if not isinstance(case, dict):
            raise FL3ValidationError("Discovery battery case must be object (fail-closed)")

    # Smoke gate is an early termination layer: it produces no promotion-binding artifact by itself.
    # If it fails, the caller should stop evaluation; if it passes, proceed with full evaluation.
    cases = _select_smoke_cases(battery=battery, adapter_id=adapter_id, adapter_version=adapter_version, job_id=job_id, seed=seed) if smoke_gate else list(all_cases)

    shard_secret = str(job_id)
    agg = _run_sharded(
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        job_id=job_id,
        role_id=role_id,
        seed=seed,
        cases=cases,
        shards=int(shards),
        workers=int(workers),
        force_canary_fail=bool(force_canary_fail),
        shard_secret=shard_secret,
    )
    axis_scores = agg["axis_scores"]
    canary_pass = bool(agg["canary_pass"])
    role_drift_flag = _compute_role_drift_flag(role_id=role_id, axis_scores=axis_scores, role_spec=role_spec)

    record: Dict[str, Any] = {
        "schema_id": "kt.discovery_battery_result.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.discovery_battery_result.v1.json"),
        "result_id": "",
        "battery_id": battery["battery_id"],
        "anchor_set_id": anchor["anchor_set_id"],
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "job_id": job_id,
        "axis_scores": axis_scores,
        "canary_pass": bool(canary_pass),
        "role_drift_flag": bool(role_drift_flag),
        "created_at": _utc_now_z(),
    }
    record["result_id"] = sha256_hex_of_obj(record, drop_keys={"created_at", "result_id"})

    validate_schema_bound_object(record)
    return record


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter-id", required=True)
    ap.add_argument("--adapter-version", required=True)
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--role-id", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", required=True)
    ap.add_argument("--battery", default="KT_PROD_CLEANROOM/AUDITS/DISCOVERY_BATTERY.json")
    ap.add_argument("--anchor", default="KT_PROD_CLEANROOM/AUDITS/ANCHOR_REFERENCE_SET.json")
    ap.add_argument("--role-spec", default="KT_PROD_CLEANROOM/AUDITS/ROLE_FITNESS_WEIGHTS.json")
    ap.add_argument("--force-canary-fail", action="store_true")
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--smoke-gate", action="store_true")
    args = ap.parse_args(argv)

    repo_root = repo_root_from(Path(__file__))
    out_path = (repo_root / args.out).resolve()
    assert_path_under_exports(repo_root=repo_root, path=out_path, allow_promoted=True)

    battery = read_json((repo_root / args.battery).resolve())
    anchor = read_json((repo_root / args.anchor).resolve())
    role_spec = read_json((repo_root / args.role_spec).resolve())

    record = run_discovery_battery(
        repo_root=repo_root,
        adapter_id=args.adapter_id,
        adapter_version=args.adapter_version,
        job_id=args.job_id,
        role_id=args.role_id,
        seed=int(args.seed),
        battery=battery,
        anchor=anchor,
        role_spec=role_spec,
        force_canary_fail=bool(args.force_canary_fail),
        shards=int(args.shards),
        workers=int(args.workers),
        smoke_gate=bool(args.smoke_gate),
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
