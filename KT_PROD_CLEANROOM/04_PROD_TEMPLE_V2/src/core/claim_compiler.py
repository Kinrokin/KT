from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
RUNTIME_TRUTH_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_runtime_truth_surface.json"
VERIFIER_TRUTH_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_verifier_truth_surface.json"
TIER_RULING_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_final_tier_ruling.json"
DEFERRED_BLOCKERS_REL = "KT_PROD_CLEANROOM/reports/deferred_blockers.json"
C016A_SUCCESS_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c016a_success_matrix.json"
C016B_RESILIENCE_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c016b_resilience_pack.json"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _load_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return payload


def _coerce_mapping(payload: Optional[Mapping[str, Any]], path: Path) -> Dict[str, Any]:
    if payload is None:
        return _load_json(path)
    return dict(payload)


def _coerce_optional_mapping(payload: Optional[Mapping[str, Any]], path: Path) -> Dict[str, Any]:
    if payload is None:
        if not path.exists():
            return {}
        return _load_json(path)
    return dict(payload)


def _find_deferred_c006(payload: Mapping[str, Any]) -> Dict[str, Any]:
    rows = payload.get("deferred", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        blocker_id = str(row.get("blocker_id", "")).strip()
        if blocker_id == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED":
            return dict(row)
    return {}


def _sentence(value: str) -> str:
    text = str(value).strip().rstrip(".")
    if not text:
        return ""
    if text.lower().startswith("do not "):
        return f"{text}."
    return f"Do not {text}."


def compile_runtime_claims(
    *,
    root: Optional[Path] = None,
    useful_output_benchmark: Mapping[str, Any],
    provider_path_integrity: Mapping[str, Any],
    truth_lock: Optional[Mapping[str, Any]] = None,
    runtime_truth: Optional[Mapping[str, Any]] = None,
    verifier_truth: Optional[Mapping[str, Any]] = None,
    tier_ruling: Optional[Mapping[str, Any]] = None,
    deferred_blockers: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    base = (root or repo_root()).resolve()
    truth_lock_payload = _coerce_mapping(truth_lock, base / TRUTH_LOCK_REL)
    runtime_truth_payload = _coerce_mapping(runtime_truth, base / RUNTIME_TRUTH_REL)
    verifier_truth_payload = _coerce_mapping(verifier_truth, base / VERIFIER_TRUTH_REL)
    tier_ruling_payload = _coerce_mapping(tier_ruling, base / TIER_RULING_REL)
    deferred_blockers_payload = _coerce_optional_mapping(deferred_blockers, base / DEFERRED_BLOCKERS_REL)
    useful_payload = dict(useful_output_benchmark)
    provider_payload = dict(provider_path_integrity)

    statuses = [
        str(truth_lock_payload.get("status", "")).strip().upper(),
        str(runtime_truth_payload.get("status", "")).strip().upper(),
        str(verifier_truth_payload.get("status", "")).strip().upper(),
        str(tier_ruling_payload.get("status", "")).strip().upper(),
        str(useful_payload.get("status", "")).strip().upper(),
        str(provider_payload.get("status", "")).strip().upper(),
    ]
    status = "PASS" if all(value == "PASS" for value in statuses) else "FAIL"

    compiled_head_commit = (
        str(runtime_truth_payload.get("compiled_head_commit", "")).strip()
        or str(verifier_truth_payload.get("compiled_head_commit", "")).strip()
        or str(tier_ruling_payload.get("compiled_head_commit", "")).strip()
    )
    active_open_blocker_ids = [
        str(item).strip()
        for item in truth_lock_payload.get("active_open_blocker_ids", [])
        if str(item).strip()
    ]
    deferred_c006 = _find_deferred_c006(deferred_blockers_payload)
    deferred_machine_state = (
        dict(deferred_c006.get("machine_effective_state", {}))
        if isinstance(deferred_c006.get("machine_effective_state", {}), Mapping)
        else {}
    )
    c006_deferral_required = "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED" in active_open_blocker_ids
    c006_deferral_present = (
        str(deferred_c006.get("status", "")).strip() == "DEFERRED_RESOURCE_CONSTRAINT"
        if deferred_c006
        else False
    )
    tier_id = str(tier_ruling_payload.get("tier_id", "")).strip()
    externality_class = str(verifier_truth_payload.get("externality_class", "")).strip()
    externality_class_max = (
        str(deferred_machine_state.get("externality_class_max", "")).strip()
        or str(deferred_c006.get("current_externality_ceiling", "")).strip()
        or externality_class
    )
    comparative_widening = str(deferred_machine_state.get("comparative_widening", "")).strip() or "FORBIDDEN"
    commercial_widening = str(deferred_machine_state.get("commercial_widening", "")).strip() or "FORBIDDEN"
    deferred_reentry_condition = (
        str(deferred_machine_state.get("reentry_condition", "")).strip()
        or str(deferred_c006.get("reentry_condition", {}).get("description", "")).strip()
    )
    successful_provider_ids = [
        str(item).strip()
        for item in provider_payload.get("same_host_live_hashed_provider_ids", [])
        if str(item).strip()
    ]

    status = (
        "PASS"
        if all(value == "PASS" for value in statuses) and (not c006_deferral_required or c006_deferral_present)
        else "FAIL"
    )

    allowed_current_claims = [
        "One bounded canonical organism path executes through kt.entrypoint.invoke -> core.spine.run on current head.",
        f"One bounded useful-output witness exists on the same-host LIVE_HASHED lane for {', '.join(successful_provider_ids) or 'no providers'} only.",
        f"Detached verifier truth remains bounded at {externality_class_max or externality_class or 'E1_SAME_HOST_DETACHED_REPLAY'} and must not be read above that class.",
        f"Current runtime language remains bounded by {tier_id or 'the active tier ruling'} and the active blocker family {', '.join(active_open_blocker_ids) or 'with no declared blockers'}.",
    ]
    if c006_deferral_present:
        allowed_current_claims.append(
            "C006 remains open and deferred under resource constraint; bounded runtime, lab, packaging, and buyer-safe E1 work may continue without implying E2 or higher."
        )

    forbidden_current_claims = [
        *[
            f"Do not claim {value}."
            for value in tier_ruling_payload.get("unearned_truths", [])
            if isinstance(value, str) and value.strip()
        ],
        *[
            f"Do not claim {value}."
            for value in truth_lock_payload.get("stronger_claims_not_made", [])
            if isinstance(value, str) and value.strip()
        ],
        "Do not narrate same-host LIVE_HASHED provider success as a C006 or externality upgrade.",
        "Do not narrate bounded cognition execution as router, lobe, or civilization superiority.",
        "Do not widen commercial or enterprise language from runtime claim compilation.",
    ]
    for item in deferred_c006.get("deferral_law", {}).get("must_not", []) if isinstance(deferred_c006.get("deferral_law", {}), Mapping) else []:
        sentence = _sentence(str(item))
        if sentence:
            forbidden_current_claims.append(sentence)
    if c006_deferral_required and not c006_deferral_present:
        forbidden_current_claims.append(
            "Do not proceed as if C006 deferral law is optional while C006 remains the active current-head blocker."
        )
    deduped_forbidden: list[str] = []
    for item in forbidden_current_claims:
        text = str(item).strip()
        if text and text not in deduped_forbidden:
            deduped_forbidden.append(text)

    return {
        "schema_id": "kt.runtime.claim_compilation.v1",
        "status": status,
        "compiled_head_commit": compiled_head_commit,
        "claim_boundary": (
            "Runtime claim compilation is bounded to current-head runtime, verifier, and tier surfaces plus the declared useful-output and provider-path receipts. "
            "It is not a router-promotion, externality-upgrade, or commercial-widening surface."
        ),
        "input_refs": [
            TRUTH_LOCK_REL,
            RUNTIME_TRUTH_REL,
            VERIFIER_TRUTH_REL,
            TIER_RULING_REL,
            DEFERRED_BLOCKERS_REL,
            C016A_SUCCESS_REL,
            C016B_RESILIENCE_REL,
        ],
        "active_open_blocker_ids": active_open_blocker_ids,
        "deferred_blocker_ids": [str(deferred_c006.get("blocker_id", "")).strip()] if c006_deferral_present else [],
        "runtime_truth_class": str(runtime_truth_payload.get("runtime_truth_class", "")).strip(),
        "verifier_truth_class": str(verifier_truth_payload.get("verifier_truth_class", "")).strip(),
        "runtime_claim_ceiling": tier_id,
        "externality_class": externality_class,
        "externality_class_max": externality_class_max,
        "comparative_widening": comparative_widening,
        "commercial_widening": commercial_widening,
        "deferred_reentry_condition": deferred_reentry_condition,
        "same_host_live_hashed_provider_ids": successful_provider_ids,
        "allowed_current_claims": allowed_current_claims,
        "forbidden_current_claims": deduped_forbidden,
    }


__all__ = ["compile_runtime_claims", "repo_root"]
