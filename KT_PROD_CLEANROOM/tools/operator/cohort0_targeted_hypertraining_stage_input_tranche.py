from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_ORACLE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_receipt.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ALPHA_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_FORGE_REGISTRY_REL = "KT_PROD_CLEANROOM/tools/operator/config/forge_cohort0_registry.json"

DEFAULT_TRACKED_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_manifest.json"
DEFAULT_TRACKED_INDEX_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_index.json"
DEFAULT_TRACKED_KAGGLE_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_kaggle_packet.json"
DEFAULT_TRACKED_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_receipt.json"

DEFAULT_STAGE_FOLDER_NAME = "kt-targeted-hypertraining-stage"
FIXED_ZIP_DT = (1980, 1, 1, 0, 0, 0)
TARGET_LOBE_IDS = [
    "lobe.p2.v1",
    "lobe.child.v1",
    "lobe.strategist.v1",
    "lobe.beta.v1",
    "lobe.scout.v1",
    "lobe.auditor.v1",
]
QUARANTINED_LOBE_IDS = [
    "lobe.critic.v1",
    "lobe.muse.v1",
    "lobe.p1.v1",
    "lobe.architect.v1",
    "lobe.censor.v1",
    "lobe.quant.v1",
]
OUTCOME_ROUTE = "ROUTE_TO_SPECIALIST"
OUTCOME_ABSTAIN = "ABSTAIN_FOR_REVIEW"
VISIBLE = "VISIBLE_TO_AUTHORING"
SOURCE_CASE_VARIANT_ORDER = [
    "ADVERSARIAL",
    "AMBIGUITY_BOUNDARY",
    "GOVERNED_EXECUTION",
    "MIXED_PRESSURE",
]
PROMPT_FRAMES: Tuple[Dict[str, str], ...] = (
    {"frame_id": "DECISION_MEMO", "task_suffix": "Return a short decision memo that keeps the decisive wedge visible.", "response_mode": "DECIDE"},
    {"frame_id": "CONSTRAINT_LEDGER", "task_suffix": "Return a constraint ledger with decisive items separated from decorative or unresolved items.", "response_mode": "LEDGER"},
    {"frame_id": "COUNTERFACTUAL_REWRITE", "task_suffix": "Return a counterfactual rewrite that shows what goes wrong if the alpha instinct wins here.", "response_mode": "COUNTERFACTUAL"},
    {"frame_id": "FAIL_CLOSED_HANDOFF", "task_suffix": "Return a fail-closed handoff note that a downstream operator could execute safely.", "response_mode": "HANDOFF"},
    {"frame_id": "DOWNSTREAM_COST_NOTE", "task_suffix": "Return a note that prices the downstream cost of the wrong route choice.", "response_mode": "DOWNSTREAM"},
    {"frame_id": "ROUTE_JUSTIFICATION", "task_suffix": "Return the route justification and the acceptance metric that would prove the wedge sharpened.", "response_mode": "JUSTIFY"},
    {"frame_id": "REVIEW_CHECKLIST", "task_suffix": "Return a review checklist that catches the exact family-specific failure mode.", "response_mode": "CHECKLIST"},
    {"frame_id": "RECOVERY_SEQUENCE", "task_suffix": "Return a recovery sequence that reduces failure cost after the wrong instinct appears.", "response_mode": "RECOVER"},
)
PRESSURE_PROFILES: Tuple[Dict[str, Any], ...] = (
    {"profile_id": "PRIMARY_LOW", "profile_label": "Primary wedge isolated at low intensity.", "primary_intensity": 0.40, "secondary_intensity": 0.10, "governance_intensity": 0.05},
    {"profile_id": "PRIMARY_MEDIUM", "profile_label": "Primary wedge isolated at medium intensity.", "primary_intensity": 0.65, "secondary_intensity": 0.15, "governance_intensity": 0.10},
    {"profile_id": "PRIMARY_HIGH", "profile_label": "Primary wedge isolated at high intensity.", "primary_intensity": 0.85, "secondary_intensity": 0.20, "governance_intensity": 0.15},
    {"profile_id": "BOUNDARY_GUARD", "profile_label": "Boundary pressure amplified so wrong commitment becomes expensive.", "primary_intensity": 0.60, "secondary_intensity": 0.75, "governance_intensity": 0.25},
    {"profile_id": "GOVERNED_EXECUTION", "profile_label": "Receipt and rollback pressure raised above rhetorical comfort.", "primary_intensity": 0.55, "secondary_intensity": 0.35, "governance_intensity": 0.80},
    {"profile_id": "MIXED_DOWNSTREAM", "profile_label": "Multi-axis downstream-cost pressure where wrong routing should visibly hurt.", "primary_intensity": 0.78, "secondary_intensity": 0.60, "governance_intensity": 0.55},
)
CASE_VARIANT_SECONDARY_AXIS = {
    "ADVERSARIAL": "DECOY_TRAP",
    "AMBIGUITY_BOUNDARY": "BOUNDARY_UNCERTAINTY",
    "GOVERNED_EXECUTION": "RECEIPT_GOVERNANCE",
    "MIXED_PRESSURE": "DOWNSTREAM_COST",
}
SHARD_PLAN: Tuple[Dict[str, Any], ...] = (
    {"shard_id": "SHARD_01", "target_lobe_ids": ["lobe.p2.v1", "lobe.child.v1"]},
    {"shard_id": "SHARD_02", "target_lobe_ids": ["lobe.strategist.v1", "lobe.beta.v1"]},
    {"shard_id": "SHARD_03", "target_lobe_ids": ["lobe.scout.v1", "lobe.auditor.v1"]},
)
FAMILY_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "P2_SIGNAL_NOISE_SEPARATION": {
        "primary_pressure_axis": "DECISIVE_CONSTRAINT_SEPARATION",
        "observable_failure_cost": "Decorative constraints outrank the decisive one, so the plan looks coherent while violating the real blocker.",
        "expected_receipt_signal": "Constraint-fidelity wins rise, downstream-error cost falls, and route-bearing divergence remains nonzero on decoy families.",
        "specialist_moves": [
            "Separate decisive from decorative constraints before proposing action.",
            "Name the missing decisive variable when the evidence is incomplete.",
            "Rank evidence by consequence instead of surface plausibility.",
            "Keep the answer bounded to the constraint set that survived scrutiny.",
        ],
        "config": {"max_steps": 160, "batch_size": 1, "seq_len": 640, "lora_rank": 12, "lora_alpha": 24, "lora_dropout": 0.05},
    },
    "CHILD_ANOMALY_PRESERVATION": {
        "primary_pressure_axis": "ANOMALY_RETENTION",
        "observable_failure_cost": "A rare anomaly is silently normalized away, so the system proceeds on a smooth but false median.",
        "expected_receipt_signal": "Anomaly-retention wins rise, silent-normalization drops, and mismatch-triggered halts become more faithful.",
        "specialist_moves": [
            "Keep the rare observation visible instead of folding it into the average story.",
            "Say explicitly what should halt because the anomaly changes the state class.",
            "Preserve the raw mismatch before summarizing.",
            "Keep the explanation simple without flattening the anomaly away.",
        ],
        "config": {"max_steps": 144, "batch_size": 1, "seq_len": 640, "lora_rank": 10, "lora_alpha": 20, "lora_dropout": 0.05},
    },
    "STRATEGIST_CONSEQUENCE_CHAIN": {
        "primary_pressure_axis": "DOWNSTREAM_SEQUENCE_DISCIPLINE",
        "observable_failure_cost": "A locally strong answer chooses the wrong order, so later steps lose optionality or fail outright.",
        "expected_receipt_signal": "Step-order discipline rises, downstream-failure cost falls, and dependency-miss penalties drop on gate-order families.",
        "specialist_moves": [
            "Sequence the work in the order that protects later optionality.",
            "Price downstream failure cost before committing to the first plausible step.",
            "Name the dependency whose absence should block the path.",
            "Tie the next move to a reversible recovery path.",
        ],
        "config": {"max_steps": 176, "batch_size": 1, "seq_len": 768, "lora_rank": 12, "lora_alpha": 24, "lora_dropout": 0.05},
    },
    "BETA_SECOND_ORDER_REFRAME": {
        "primary_pressure_axis": "RIVAL_FRAME_PRESERVATION",
        "observable_failure_cost": "The first clean framing locks the system too early, so the safer rival interpretation never gets a chance to win.",
        "expected_receipt_signal": "Rival-frame preservation rises, framing-lock losses fall, and overclaim risk drops on reframing families.",
        "specialist_moves": [
            "Hold at least one live rival frame until the decisive evidence separates them.",
            "Name the cost of committing to the first clean framing.",
            "Show what changes if the rival frame is true.",
            "Commit only when one framing survives the second-order check.",
        ],
        "config": {"max_steps": 144, "batch_size": 1, "seq_len": 640, "lora_rank": 10, "lora_alpha": 20, "lora_dropout": 0.05},
    },
    "SCOUT_SPARSE_SEARCH": {
        "primary_pressure_axis": "SPARSE_CANDIDATE_COVERAGE",
        "observable_failure_cost": "The search collapses onto the first plausible answer and never explores the sparse winning branch.",
        "expected_receipt_signal": "Candidate coverage rises, early-commit losses fall, and search-frontier breadth improves on sparse families.",
        "specialist_moves": [
            "Widen the candidate set before collapsing to synthesis.",
            "Name which candidate remains underexplored and why it matters.",
            "Keep the frontier visible long enough to compare alternatives.",
            "Only narrow after candidate coverage crosses a safe threshold.",
        ],
        "config": {"max_steps": 144, "batch_size": 1, "seq_len": 640, "lora_rank": 10, "lora_alpha": 20, "lora_dropout": 0.05},
    },
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": {
        "primary_pressure_axis": "FAIL_CLOSED_ADMISSIBILITY",
        "observable_failure_cost": "The output sounds acceptable, but missing receipts or rollback make execution unlawful or unsafe.",
        "expected_receipt_signal": "Fail-closed correctness rises, overclaim rate falls, and lawful abstention beats premature action on audit families.",
        "specialist_moves": [
            "Check admissibility before usefulness and stop if the evidence path is broken.",
            "Name the missing receipt or rollback surface explicitly.",
            "Prefer abstention or review handoff over improvisation when proof is thin.",
            "Keep the remediation path as concrete as the diagnosis.",
        ],
        "config": {"max_steps": 176, "batch_size": 1, "seq_len": 768, "lora_rank": 12, "lora_alpha": 24, "lora_dropout": 0.05},
    },
}


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _remove_if_exists(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _assert_under(parent: Path, path: Path, *, label: str) -> None:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError as exc:
        raise RuntimeError(f"FAIL_CLOSED: {label} escapes {parent.as_posix()}: {path.as_posix()}") from exc


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tracked_copy(obj: Dict[str, Any], *, carrier_role: str, ref_field: str, authoritative_path: Path) -> Dict[str, Any]:
    tracked = dict(obj)
    tracked["carrier_surface_role"] = carrier_role
    tracked[ref_field] = authoritative_path.as_posix()
    return tracked


def _stage_file_entries(stage_root: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for path in sorted(p for p in stage_root.rglob("*") if p.is_file()):
        entries.append(
            {
                "path": path.relative_to(stage_root).as_posix(),
                "sha256": _sha256_file(path),
                "bytes": int(path.stat().st_size),
            }
        )
    return entries


def _write_stage_zip(stage_root: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zip_path.open("wb") as handle:
        with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(p for p in stage_root.rglob("*") if p.is_file()):
                rel = path.relative_to(stage_root.parent).as_posix()
                zi = zipfile.ZipInfo(rel, date_time=FIXED_ZIP_DT)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = (0o644 & 0xFFFF) << 16
                zf.writestr(zi, path.read_bytes())


def _family_sort_key(family_id: str) -> int:
    order = list(FAMILY_CONTRACTS)
    return order.index(family_id) if family_id in order else len(order)


def _family_target_lobe_id(family_id: str) -> str:
    mapping = {
        "P2_SIGNAL_NOISE_SEPARATION": "lobe.p2.v1",
        "CHILD_ANOMALY_PRESERVATION": "lobe.child.v1",
        "STRATEGIST_CONSEQUENCE_CHAIN": "lobe.strategist.v1",
        "BETA_SECOND_ORDER_REFRAME": "lobe.beta.v1",
        "SCOUT_SPARSE_SEARCH": "lobe.scout.v1",
        "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": "lobe.auditor.v1",
    }
    return mapping[family_id]


def _validate_sources(
    *,
    oracle_receipt: Dict[str, Any],
    oracle_scorecard: Dict[str, Any],
    stage_pack_manifest: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
    forge_registry: Dict[str, Any],
) -> None:
    if str(oracle_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle receipt must PASS")
    if str(oracle_receipt.get("oracle_stage_pack_posture", "")).strip() != "PREREGISTERED_STAGE_PACK_BOUND__LOCAL_ORACLE_PASS__COUNTED_LANE_STILL_CLOSED":
        raise RuntimeError("FAIL_CLOSED: oracle stage-pack posture mismatch")
    if str(oracle_receipt.get("kaggle_admissibility", "")).strip() != "ADMISSIBLE_FOR_TARGETED_HYPERTRAINING_ONLY":
        raise RuntimeError("FAIL_CLOSED: Kaggle must be admissible for targeted hypertraining only")
    if list(oracle_receipt.get("kaggle_target_lobe_ids", [])) != TARGET_LOBE_IDS:
        raise RuntimeError("FAIL_CLOSED: oracle receipt target lobe set mismatch")
    if bool(oracle_receipt.get("generic_all_13_heavier_rerun_forbidden")) is not True:
        raise RuntimeError("FAIL_CLOSED: generic all-13 heavier rerun must remain forbidden")

    if str(oracle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle scorecard must PASS")
    if list(oracle_scorecard.get("oracle_positive_lobe_ids", [])) != TARGET_LOBE_IDS:
        raise RuntimeError("FAIL_CLOSED: oracle-positive lobe ids mismatch")
    if int(oracle_scorecard.get("route_divergence_count", 0)) <= 0:
        raise RuntimeError("FAIL_CLOSED: route divergence must remain nonzero")

    if str(stage_pack_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route-bearing stage pack manifest must PASS")
    if list(stage_pack_manifest.get("selected_working_set", [])) != ["lobe.alpha.v1"] + TARGET_LOBE_IDS:
        raise RuntimeError("FAIL_CLOSED: selected working set mismatch")
    if list(stage_pack_manifest.get("quarantined_set", [])) != QUARANTINED_LOBE_IDS:
        raise RuntimeError("FAIL_CLOSED: quarantined set mismatch")
    if str(stage_pack_manifest.get("kaggle_opening_rule", "")).strip() != "Only targeted hypertraining on oracle-positive families is admissible. Generic all-13 reruns remain forbidden.":
        raise RuntimeError("FAIL_CLOSED: Kaggle opening rule mismatch")

    if str(alpha_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha manifest must PASS")
    if len(alpha_manifest.get("rows", [])) != len(TARGET_LOBE_IDS):
        raise RuntimeError("FAIL_CLOSED: alpha manifest must contain exactly six target rows")

    if str(forge_registry.get("schema_id", "")).strip() != "kt.operator.forge_cohort0_registry.unbound.v1":
        raise RuntimeError("FAIL_CLOSED: forge registry schema mismatch")
    adapter_rows = forge_registry.get("adapters") if isinstance(forge_registry.get("adapters"), list) else []
    seen_target_ids = sorted(str(row.get("adapter_id", "")).strip() for row in adapter_rows if str(row.get("adapter_id", "")).strip() in TARGET_LOBE_IDS)
    if seen_target_ids != sorted(TARGET_LOBE_IDS):
        raise RuntimeError("FAIL_CLOSED: forge registry missing one or more target lobe ids")


def _forge_seed_map(forge_registry: Dict[str, Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in forge_registry.get("adapters", []):
        if not isinstance(row, dict):
            continue
        adapter_id = str(row.get("adapter_id", "")).strip()
        params = row.get("training_params") if isinstance(row.get("training_params"), dict) else {}
        if adapter_id:
            out[adapter_id] = int(params.get("seed", 0))
    return out


def _visible_target_cases(cases_payload: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    rows = cases_payload.get("rows") if isinstance(cases_payload.get("rows"), list) else []
    grouped: Dict[str, List[Dict[str, Any]]] = {family_id: [] for family_id in FAMILY_CONTRACTS}
    for row in rows:
        if not isinstance(row, dict):
            continue
        family_id = str(row.get("family_id", "")).strip()
        target_lobe_id = str(row.get("target_lobe_id", "")).strip()
        if family_id not in FAMILY_CONTRACTS or target_lobe_id not in TARGET_LOBE_IDS:
            continue
        if str(row.get("pack_visibility", "")).strip() != VISIBLE:
            continue
        grouped[family_id].append(row)

    for family_id, family_rows in grouped.items():
        family_rows.sort(
            key=lambda row: (
                SOURCE_CASE_VARIANT_ORDER.index(str(row.get("case_variant", "")).strip())
                if str(row.get("case_variant", "")).strip() in SOURCE_CASE_VARIANT_ORDER
                else len(SOURCE_CASE_VARIANT_ORDER),
                str(row.get("case_id", "")).strip(),
            )
        )
        if len(family_rows) != 4:
            raise RuntimeError(f"FAIL_CLOSED: expected 4 visible source cases for {family_id}, got {len(family_rows)}")
    return grouped


def _family_alpha_rows(alpha_manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = alpha_manifest.get("rows") if isinstance(alpha_manifest.get("rows"), list) else []
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            out[str(row.get("family_id", "")).strip()] = row
    return out


def _profile_axes(*, family_id: str, case_variant: str, profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    primary_axis = str(FAMILY_CONTRACTS[family_id]["primary_pressure_axis"])
    secondary_axis = CASE_VARIANT_SECONDARY_AXIS[str(case_variant)]
    return [
        {"axis": primary_axis, "intensity": float(profile["primary_intensity"])},
        {"axis": secondary_axis, "intensity": float(profile["secondary_intensity"])},
        {"axis": "GOVERNED_RECEIPT_DISCIPLINE", "intensity": float(profile["governance_intensity"])},
    ]


def _response_lines(
    *,
    family_id: str,
    case: Dict[str, Any],
    frame: Dict[str, str],
    acceptance_metric: str,
    failure_cost: str,
    expected_receipt_signal: str,
) -> List[str]:
    moves = list(FAMILY_CONTRACTS[family_id]["specialist_moves"])
    outcome = str(case.get("oracle_policy_outcome", "")).strip()
    frame_id = str(frame["frame_id"])
    if outcome == OUTCOME_ABSTAIN:
        return [
            f"{frame_id}: fail closed instead of forcing action because the admissibility path is not yet earned.",
            f"Name the exact blocker and why it matters: {failure_cost}",
            f"Escalate using the registered handoff rule: {str(case.get('review_handoff_rule', '')).strip()}",
            f"Only reopen once the receipt signal is visible: {expected_receipt_signal}",
        ]

    first, second, third, fourth = moves
    mode = str(frame["response_mode"])
    if mode == "LEDGER":
        return [
            f"Decisive line: {first}",
            f"Noise filter: {second}",
            f"Failure-cost line: {failure_cost}",
            f"Acceptance proof: {acceptance_metric}",
        ]
    if mode == "COUNTERFACTUAL":
        return [
            f"If alpha wins here, the likely miss is: {failure_cost}",
            f"Specialist correction: {first}",
            f"Second-order safeguard: {second}",
            f"Receipt proof to watch: {expected_receipt_signal}",
        ]
    if mode == "HANDOFF":
        return [
            f"Bound the task before action: {first}",
            f"Handoff note for downstream operator: {third}",
            f"Keep recovery reversible: {fourth}",
            f"Do not mark success until: {expected_receipt_signal}",
        ]
    if mode == "DOWNSTREAM":
        return [
            f"Price the wrong-route cost first: {failure_cost}",
            f"Then reduce it by doing this: {first}",
            f"Protect optionality with this move: {third}",
            f"Score success with: {acceptance_metric}",
        ]
    if mode == "JUSTIFY":
        return [
            f"Route justification: {str(case.get('route_justification', '')).strip() or first}",
            f"Why alpha should lose here: {str(case.get('alpha_liability', '')).strip()}",
            f"Acceptance metric: {acceptance_metric}",
            f"Receipt signal: {expected_receipt_signal}",
        ]
    if mode == "CHECKLIST":
        return [
            f"Checklist 1: {first}",
            f"Checklist 2: {second}",
            f"Checklist 3: {third}",
            f"Checklist 4: prove {expected_receipt_signal}",
        ]
    if mode == "RECOVER":
        return [
            f"Recovery step 1: {third}",
            f"Recovery step 2: {fourth}",
            f"Keep the failure cost visible: {failure_cost}",
            f"Only close the loop if {acceptance_metric}",
        ]
    return [
        f"Decision anchor: {first}",
        f"Guardrail: {second}",
        f"Next move: {third}",
        f"Success signal: {expected_receipt_signal}",
    ]


def _render_training_text(
    *,
    adapter_id: str,
    family_id: str,
    case: Dict[str, Any],
    frame: Dict[str, str],
    profile: Dict[str, Any],
    acceptance_metric: str,
    failure_cost: str,
    expected_receipt_signal: str,
) -> str:
    axes = _profile_axes(family_id=family_id, case_variant=str(case["case_variant"]), profile=profile)
    axes_text = ", ".join(f"{row['axis']}:{row['intensity']:.2f}" for row in axes)
    response = _response_lines(
        family_id=family_id,
        case=case,
        frame=frame,
        acceptance_metric=acceptance_metric,
        failure_cost=failure_cost,
        expected_receipt_signal=expected_receipt_signal,
    )
    return "\n".join(
        [
            "<kt_targeted_hypertraining_row>",
            f"adapter_id={adapter_id}",
            f"family_id={family_id}",
            f"case_id={str(case['case_id']).strip()}",
            f"case_variant={str(case['case_variant']).strip()}",
            f"oracle_policy_outcome={str(case['oracle_policy_outcome']).strip()}",
            f"frame_id={str(frame['frame_id']).strip()}",
            f"pressure_profile_id={str(profile['profile_id']).strip()}",
            f"pressure_profile_label={str(profile['profile_label']).strip()}",
            f"pressure_axes={axes_text}",
            f"alpha_liability={str(case['alpha_liability']).strip()}",
            f"observable_failure_cost={failure_cost}",
            f"acceptance_metric={acceptance_metric}",
            f"expected_receipt_signal={expected_receipt_signal}",
            "[task]",
            str(case["case_prompt"]).strip(),
            str(frame["task_suffix"]).strip(),
            "[/task]",
            "[preferred_response]",
            *response,
            "[/preferred_response]",
            "</kt_targeted_hypertraining_row>",
        ]
    )


def _dataset_records(
    *,
    family_id: str,
    adapter_id: str,
    case_rows: Sequence[Dict[str, Any]],
    acceptance_metric: str,
    failure_cost: str,
    expected_receipt_signal: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for case in case_rows:
        for profile in PRESSURE_PROFILES:
            axes = _profile_axes(family_id=family_id, case_variant=str(case["case_variant"]), profile=profile)
            for frame in PROMPT_FRAMES:
                text = _render_training_text(
                    adapter_id=adapter_id,
                    family_id=family_id,
                    case=case,
                    frame=frame,
                    profile=profile,
                    acceptance_metric=acceptance_metric,
                    failure_cost=failure_cost,
                    expected_receipt_signal=expected_receipt_signal,
                )
                records.append(
                    {
                        "text": text,
                        "adapter_id": adapter_id,
                        "family_id": family_id,
                        "source_case_id": str(case["case_id"]).strip(),
                        "source_case_variant": str(case["case_variant"]).strip(),
                        "pressure_profile_id": str(profile["profile_id"]).strip(),
                        "frame_id": str(frame["frame_id"]).strip(),
                        "oracle_policy_outcome": str(case["oracle_policy_outcome"]).strip(),
                        "alpha_liability": str(case["alpha_liability"]).strip(),
                        "observable_failure_cost": failure_cost,
                        "acceptance_metric": acceptance_metric,
                        "expected_receipt_signal": expected_receipt_signal,
                        "pressure_axes": axes,
                    }
                )
    return records


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n")
            count += 1
    return {
        "path": path,
        "line_count": count,
        "bytes": int(path.stat().st_size),
        "sha256": _sha256_file(path),
    }


def _config_for(*, adapter_id: str, seed: int) -> Dict[str, Any]:
    family_id = next(key for key in FAMILY_CONTRACTS if adapter_id == _family_target_lobe_id(key))
    config = dict(FAMILY_CONTRACTS[family_id]["config"])
    warmup_steps = max(16, min(32, int(config["max_steps"]) // 8))
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_config.v1",
        "stage_id": "TARGETED_HYPERTRAINING__ORACLE_POSITIVE_WEDGE_ONLY",
        "job_id": f"cohort0_targeted_hypertrain_{adapter_id}",
        "adapter_id": adapter_id,
        "adapter_version": adapter_id.split(".")[-1],
        "trainer_module": "tools.training.phase2_train",
        "training_engine": "hf_lora_heavy_historical",
        "training_mode": "lora",
        "seed": seed + 5000,
        "claim_boundary": "Targeted hypertraining starter config only. This is not a counted-lane claim, optimizer claim, or superiority claim.",
        "num_epochs": 1,
        "learning_rate": 1e-4,
        "warmup_steps": warmup_steps,
        "gradient_checkpointing": False,
        **config,
    }


def _build_manifest(
    *,
    current_head: str,
    subject_head: str,
    source_oracle_receipt_ref: str,
    source_oracle_scorecard_ref: str,
    dataset_rows: Sequence[Dict[str, Any]],
    stage_root: Path,
    mirror_input_root: Path,
    zip_path: Path,
    readme_path: Path,
    base_snapshot_id: str,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "stage_input_posture": "SIX_LOBE_TARGETED_STAGE_INPUTS_BOUND__KAGGLE_HYPERTRAINING_READY__COUNTED_LANE_STILL_CLOSED",
        "claim_boundary": (
            "This manifest binds only the six-lobe targeted hypertraining stage inputs. "
            "It does not reopen the counted lane, authorize learned routing, or claim R6/Gate E/Gate F progress."
        ),
        "source_refs": {
            "authoritative_oracle_router_local_receipt_ref": source_oracle_receipt_ref,
            "authoritative_oracle_router_local_scorecard_ref": source_oracle_scorecard_ref,
        },
        "target_lobe_ids": TARGET_LOBE_IDS,
        "quarantined_lobe_ids": QUARANTINED_LOBE_IDS,
        "held_out_training_exclusion_rule": "Only visible oracle-positive source rows are allowed into the training pack. Held-out mutation rows remain excluded from training.",
        "generic_all_13_heavier_rerun_forbidden": True,
        "base_snapshot_id": base_snapshot_id,
        "base_model_requirement": "A real local base model dir must still be provided on Kaggle via HF_TOKEN or FORCE_BASE_MODEL_DIR.",
        "stage_root": stage_root.as_posix(),
        "mirror_input_root": mirror_input_root.as_posix(),
        "zip_path": zip_path.as_posix(),
        "readme_path": readme_path.as_posix(),
        "dataset_rows": list(dataset_rows),
    }


def _build_index(*, dataset_rows: Sequence[Dict[str, Any]], stage_root: Path, zip_path: Path) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_index.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "stage_root": stage_root.as_posix(),
        "zip_path": zip_path.as_posix(),
        "dataset_count": len(dataset_rows),
        "rows": [
            {
                "adapter_id": row["adapter_id"],
                "family_id": row["family_id"],
                "line_count": row["line_count"],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
                "config_relpath": row["config_relpath"],
                "dataset_relpath": row["dataset_relpath"],
                "visible_source_case_count": row["visible_source_case_count"],
                "excluded_held_out_case_count": row["excluded_held_out_case_count"],
            }
            for row in dataset_rows
        ],
    }


def _build_kaggle_packet(
    *,
    current_head: str,
    subject_head: str,
    stage_root: Path,
    zip_path: Path,
    readme_path: Path,
    dataset_rows: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    row_by_adapter = {str(row["adapter_id"]): row for row in dataset_rows}
    shard_rows: List[Dict[str, Any]] = []
    for shard_index, shard in enumerate(SHARD_PLAN, start=1):
        start_index = ((shard_index - 1) * 2) + 1
        end_index = start_index + len(shard["target_lobe_ids"]) - 1
        commands = []
        for adapter_id in shard["target_lobe_ids"]:
            row = row_by_adapter[adapter_id]
            training_params = dict(row["training_params"])
            commands.append(
                {
                    "adapter_id": adapter_id,
                    "dataset_relpath": row["dataset_relpath"],
                    "config_relpath": row["config_relpath"],
                    "seed": int(training_params["seed"]),
                    "trainer_module": "tools.training.phase2_train",
                    "command_template": [
                        "python",
                        "-m",
                        "tools.training.phase2_train",
                        "--allow-legacy",
                        "--base-model",
                        "<BASE_MODEL_DIR>",
                        "--dataset",
                        f"<STAGED_INPUT_ROOT>/{row['dataset_relpath']}",
                        "--out-dir",
                        f"<FULL_RUN_ROOT>/adapters/{adapter_id}",
                        "--load-in-4bit",
                        "true",
                        "--lora-rank",
                        str(training_params["lora_rank"]),
                        "--batch-size",
                        str(training_params["batch_size"]),
                        "--learning-rate",
                        str(training_params["learning_rate"]),
                        "--num-epochs",
                        str(training_params["num_epochs"]),
                        "--max-seq-len",
                        str(training_params["max_seq_len"]),
                        "--gradient-checkpointing",
                        str(training_params["gradient_checkpointing"]).lower(),
                        "--warmup-steps",
                        str(training_params["warmup_steps"]),
                    ],
                }
            )
        shard_rows.append(
            {
                "shard_id": shard["shard_id"],
                "target_lobe_ids": list(shard["target_lobe_ids"]),
                "start_index": start_index,
                "end_index": end_index,
                "commands": commands,
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_kaggle_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "execution_mode": "KAGGLE_GPU_HEAVY_TARGETED_SIX_LOBE",
        "trainer_module": "tools.training.phase2_train",
        "claim_boundary": (
            "This packet authorizes Kaggle only for six-lobe targeted hypertraining on oracle-positive families. "
            "It does not authorize blanket stronger-cycle reruns or counted-lane claims."
        ),
        "stage_root": stage_root.as_posix(),
        "zip_path": zip_path.as_posix(),
        "readme_path": readme_path.as_posix(),
        "all_in_one_window": {
            "start_index": 1,
            "end_index": len(TARGET_LOBE_IDS),
            "target_lobe_ids": list(TARGET_LOBE_IDS),
        },
        "recommended_shards": shard_rows,
        "expected_run_outputs": [
            "adapter_weights/",
            "training_report.json",
            "train_receipt.json",
            "adapter_bundle.zip",
            "adapter_training_receipt.json",
            "adapter_reload_receipt.json",
            "adapter_eval_receipt.json",
            "training_run_manifest.PASS.json",
            "train_manifest.json",
            "eval_report.json",
            "reasoning_trace.json",
            "dataset_hash_manifest.json",
            "verdict.txt",
        ],
        "next_local_followthrough": "IMPORT_TARGETED_HYPERTRAINING_RUNS_AND_RERUN_LOCAL_PROOF_CHAIN",
    }


def _build_receipt(
    *,
    current_head: str,
    subject_head: str,
    oracle_receipt: Dict[str, Any],
    zip_sha256: str,
    stage_manifest_external_path: Path,
    kaggle_packet_ref: Path,
) -> Dict[str, Any]:
    counted_lane_guardrail = oracle_receipt.get("counted_lane_guardrail") if isinstance(oracle_receipt.get("counted_lane_guardrail"), dict) else {}
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "stage_input_posture": "SIX_LOBE_TARGETED_STAGE_INPUTS_BOUND__KAGGLE_HYPERTRAINING_READY__COUNTED_LANE_STILL_CLOSED",
        "claim_boundary": (
            "This receipt binds only the six-lobe targeted stage-input tranche and Kaggle readiness. "
            "The counted lane remains closed until downstream proof objects move."
        ),
        "target_lobe_ids": TARGET_LOBE_IDS,
        "quarantined_lobe_ids": QUARANTINED_LOBE_IDS,
        "generic_all_13_heavier_rerun_forbidden": True,
        "counted_lane_guardrail": counted_lane_guardrail,
        "source_oracle_receipt_ref": str(oracle_receipt["authoritative_oracle_router_local_receipt_ref"]),
        "stage_manifest_ref": stage_manifest_external_path.as_posix(),
        "kaggle_packet_ref": kaggle_packet_ref.as_posix(),
        "zip_sha256": zip_sha256,
        "next_lawful_move": "EXECUTE_TARGETED_HYPERTRAINING_ON_KAGGLE_FOR_ORACLE_POSITIVE_LOBES",
    }


def _write_readme(*, path: Path, stage_root: Path, zip_path: Path, shard_rows: Sequence[Dict[str, Any]]) -> None:
    lines = [
        "COHORT0 TARGETED HYPERTRAINING PACK",
        "",
        "Scope: six oracle-positive lobes only. Counted lane remains closed.",
        f"STAGE_ROOT={stage_root.as_posix()}",
        f"ZIP_PATH={zip_path.as_posix()}",
        "",
        "Kaggle rule:",
        "1. Upload the zip or point Kaggle to the mirrored input root.",
        "2. Resolve STAGED_INPUT_ROOT from the exact dataset path on Kaggle.",
        "3. Verify BASE_MODEL_DIR is real before training.",
        "4. Default notebook window is START_INDEX=1 / END_INDEX=6 for one run-all push.",
        "5. If Kaggle runtime or disk pushes back, narrow to one shard window at a time.",
        "6. The sanctioned heavy lane for this pack is tools.training.phase2_train, not rapid_lora_loop.",
        "",
        "Recommended shard windows:",
    ]
    for shard in shard_rows:
        lines.append(
            f"{shard['shard_id']}: {', '.join(shard['target_lobe_ids'])} "
            f"(START_INDEX={shard['start_index']} END_INDEX={shard['end_index']})"
        )
        for command in shard["commands"]:
            lines.append("  " + " ".join(command["command_template"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _build_freeze_boundary(
    *,
    current_head: str,
    subject_head: str,
    oracle_receipt_ref: Path,
    dataset_rows: Sequence[Dict[str, Any]],
    stage_root: Path,
    readme_path: Path,
    shard_plan: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    contracts = {
        "dataset_manifest": (stage_root / "datasets" / "cohort0_targeted_hypertraining_dataset_manifest.json").resolve(),
        "pressure_profile_registry": (stage_root / "contracts" / "pressure_profile_registry.json").resolve(),
        "family_contracts": (stage_root / "contracts" / "family_contracts.json").resolve(),
        "kaggle_packet": (stage_root / "contracts" / "kaggle_packet.json").resolve(),
        "snapshot": (stage_root / "snapshots" / "cohort0" / "base_snapshot" / "SNAPSHOT.txt").resolve(),
        "readme": readme_path.resolve(),
    }
    contract_hashes = {name: _sha256_file(path) for name, path in contracts.items()}
    return {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_freeze_boundary.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": subject_head,
        "claim_boundary": "This boundary freezes only the six-lobe targeted hypertraining packet. It does not reopen the counted lane.",
        "source_oracle_receipt_ref": oracle_receipt_ref.as_posix(),
        "target_lobe_ids": TARGET_LOBE_IDS,
        "quarantined_lobe_ids": QUARANTINED_LOBE_IDS,
        "generic_all_13_heavier_rerun_forbidden": True,
        "held_out_training_exclusion_rule": "Held-out mutation rows remain excluded from training.",
        "shard_plan": list(shard_plan),
        "dataset_rows": [
            {
                "adapter_id": row["adapter_id"],
                "family_id": row["family_id"],
                "dataset_relpath": row["dataset_relpath"],
                "dataset_sha256": row["sha256"],
                "config_relpath": row["config_relpath"],
                "config_sha256": _sha256_file((stage_root / row["config_relpath"]).resolve()),
                "line_count": row["line_count"],
            }
            for row in dataset_rows
        ],
        "contract_hashes": contract_hashes,
    }


def run_targeted_hypertraining_stage_input_tranche(
    *,
    oracle_receipt_path: Path,
    oracle_scorecard_path: Path,
    stage_pack_manifest_path: Path,
    alpha_manifest_path: Path,
    forge_registry_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    stage_root: Path,
    mirror_input_root: Path,
    zip_path: Path,
    stage_manifest_path: Path,
    receipt_path: Path,
    readme_path: Path,
    force: bool,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()

    authoritative_oracle_receipt_path, oracle_receipt = _resolve_authoritative(
        root,
        oracle_receipt_path.resolve(),
        "authoritative_oracle_router_local_receipt_ref",
        "oracle router local receipt",
    )
    authoritative_oracle_scorecard_path, oracle_scorecard = _resolve_authoritative(
        root,
        oracle_scorecard_path.resolve(),
        "authoritative_oracle_router_local_scorecard_ref",
        "oracle router local scorecard",
    )
    authoritative_stage_pack_manifest_path, stage_pack_manifest = _resolve_authoritative(
        root,
        stage_pack_manifest_path.resolve(),
        "authoritative_route_bearing_stage_pack_manifest_ref",
        "route-bearing stage pack manifest",
    )
    authoritative_alpha_manifest_path, alpha_manifest = _resolve_authoritative(
        root,
        alpha_manifest_path.resolve(),
        "authoritative_alpha_should_lose_here_manifest_ref",
        "alpha should lose manifest",
    )
    forge_registry = _load_json_required(forge_registry_path.resolve(), label="forge registry")
    authoritative_stage_pack_cases_ref = str(stage_pack_manifest.get("authoritative_stage_pack_cases_ref", "")).strip()
    if not authoritative_stage_pack_cases_ref:
        raise RuntimeError("FAIL_CLOSED: route-bearing stage pack manifest missing authoritative_stage_pack_cases_ref")
    authoritative_stage_pack_cases_path = _resolve_path(root, authoritative_stage_pack_cases_ref)
    stage_pack_cases = _load_json_required(authoritative_stage_pack_cases_path, label="route-bearing stage pack cases")

    _validate_sources(
        oracle_receipt=oracle_receipt,
        oracle_scorecard=oracle_scorecard,
        stage_pack_manifest=stage_pack_manifest,
        alpha_manifest=alpha_manifest,
        forge_registry=forge_registry,
    )

    subject_head = str(oracle_receipt.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: subject_head missing from oracle receipt")
    current_head = _git_head(root)

    onedrive_root = root.parent.resolve()
    kt_stage_root = (onedrive_root / "KT_FORGE_STAGE").resolve()
    for label, path in (
        ("stage_root", stage_root),
        ("mirror_input_root", mirror_input_root),
        ("zip_path", zip_path),
        ("stage_manifest_path", stage_manifest_path),
        ("receipt_path", receipt_path),
        ("readme_path", readme_path),
    ):
        _assert_under(kt_stage_root, path, label=label)

    if not force:
        for path in (stage_root, mirror_input_root, zip_path, stage_manifest_path, receipt_path, readme_path):
            if path.exists():
                raise RuntimeError(f"FAIL_CLOSED: output already exists, rerun with --force: {path.as_posix()}")

    for path in (stage_root, mirror_input_root, zip_path, stage_manifest_path, receipt_path, readme_path):
        _remove_if_exists(path)

    target_root = (
        authoritative_root.resolve()
        if authoritative_root is not None
        else (root / "tmp" / "cohort0_targeted_hypertraining_stage_inputs_current_head").resolve()
    )
    target_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    stage_root.mkdir(parents=True, exist_ok=True)
    (stage_root / "snapshots" / "cohort0" / "base_snapshot").mkdir(parents=True, exist_ok=True)
    snapshot_text = "\n".join(
        [
            str(forge_registry.get("base_snapshot_id", "COHORT0_STAGED_BASE_SNAPSHOT_V1")).strip(),
            f"subject_head={subject_head}",
            f"current_git_head={current_head}",
            "NOTE: targeted hypertraining requires an external real base-model dir on Kaggle.",
        ]
    )
    (stage_root / "snapshots" / "cohort0" / "base_snapshot" / "SNAPSHOT.txt").write_text(snapshot_text + "\n", encoding="utf-8", newline="\n")

    case_rows_by_family = _visible_target_cases(stage_pack_cases)
    alpha_rows_by_family = _family_alpha_rows(alpha_manifest)
    seed_map = _forge_seed_map(forge_registry)

    dataset_rows: List[Dict[str, Any]] = []
    for family_id in sorted(FAMILY_CONTRACTS, key=_family_sort_key):
        adapter_id = _family_target_lobe_id(family_id)
        alpha_row = alpha_rows_by_family[family_id]
        case_rows = case_rows_by_family[family_id]
        records = _dataset_records(
            family_id=family_id,
            adapter_id=adapter_id,
            case_rows=case_rows,
            acceptance_metric=str(alpha_row["acceptance_metric"]).strip(),
            failure_cost=str(FAMILY_CONTRACTS[family_id]["observable_failure_cost"]).strip(),
            expected_receipt_signal=str(FAMILY_CONTRACTS[family_id]["expected_receipt_signal"]).strip(),
        )
        dataset_path = (stage_root / "datasets" / adapter_id / "failures.jsonl").resolve()
        write_result = _write_jsonl(dataset_path, records)
        config = _config_for(adapter_id=adapter_id, seed=seed_map[adapter_id])
        config_path = (stage_root / "configs" / f"{adapter_id}.targeted_hypertraining_config.json").resolve()
        write_json_stable(config_path, config)
        dataset_rows.append(
            {
                "adapter_id": adapter_id,
                "family_id": family_id,
                "dataset_relpath": dataset_path.relative_to(stage_root).as_posix(),
                "config_relpath": config_path.relative_to(stage_root).as_posix(),
                "line_count": write_result["line_count"],
                "bytes": write_result["bytes"],
                "sha256": write_result["sha256"],
                "visible_source_case_count": len(case_rows),
                "excluded_held_out_case_count": 1,
                "pressure_profile_count": len(PRESSURE_PROFILES),
                "prompt_frame_count": len(PROMPT_FRAMES),
                "acceptance_metric": str(alpha_row["acceptance_metric"]).strip(),
                "alpha_liability": str(alpha_row["alpha_should_lose_here_because"]).strip(),
                "observable_failure_cost": str(FAMILY_CONTRACTS[family_id]["observable_failure_cost"]).strip(),
                "expected_receipt_signal": str(FAMILY_CONTRACTS[family_id]["expected_receipt_signal"]).strip(),
                "oracle_policy_outcomes": sorted({str(row["oracle_policy_outcome"]).strip() for row in case_rows}),
                "source_case_ids": [str(row["case_id"]).strip() for row in case_rows],
                "training_params": {
                    "trainer_module": config["trainer_module"],
                    "training_engine": config["training_engine"],
                    "seed": int(config["seed"]),
                    "batch_size": int(config["batch_size"]),
                    "lora_rank": int(config["lora_rank"]),
                    "learning_rate": float(config["learning_rate"]),
                    "num_epochs": int(config["num_epochs"]),
                    "max_seq_len": int(config["seq_len"]),
                    "warmup_steps": int(config["warmup_steps"]),
                    "gradient_checkpointing": bool(config["gradient_checkpointing"]),
                },
            }
        )

    dataset_manifest = {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_dataset_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "target_lobe_ids": TARGET_LOBE_IDS,
        "entries": dataset_rows,
    }
    pressure_registry = {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_pressure_profile_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "profiles": list(PRESSURE_PROFILES),
        "case_variant_secondary_axes": CASE_VARIANT_SECONDARY_AXIS,
    }
    family_contract_manifest = {
        "schema_id": "kt.operator.cohort0_targeted_hypertraining_family_contracts.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "rows": [
            {
                "family_id": family_id,
                "target_lobe_id": _family_target_lobe_id(family_id),
                "primary_pressure_axis": FAMILY_CONTRACTS[family_id]["primary_pressure_axis"],
                "observable_failure_cost": FAMILY_CONTRACTS[family_id]["observable_failure_cost"],
                "expected_receipt_signal": FAMILY_CONTRACTS[family_id]["expected_receipt_signal"],
                "specialist_moves": list(FAMILY_CONTRACTS[family_id]["specialist_moves"]),
            }
            for family_id in sorted(FAMILY_CONTRACTS, key=_family_sort_key)
        ],
    }
    write_json_stable((stage_root / "datasets" / "cohort0_targeted_hypertraining_dataset_manifest.json").resolve(), dataset_manifest)
    write_json_stable((stage_root / "contracts" / "pressure_profile_registry.json").resolve(), pressure_registry)
    write_json_stable((stage_root / "contracts" / "family_contracts.json").resolve(), family_contract_manifest)

    _remove_if_exists(mirror_input_root)
    shutil.copytree(stage_root, mirror_input_root)

    kaggle_packet = _build_kaggle_packet(
        current_head=current_head,
        subject_head=subject_head,
        stage_root=stage_root,
        zip_path=zip_path,
        readme_path=readme_path,
        dataset_rows=dataset_rows,
    )
    _write_readme(path=readme_path, stage_root=stage_root, zip_path=zip_path, shard_rows=kaggle_packet["recommended_shards"])
    write_json_stable((stage_root / "contracts" / "kaggle_packet.json").resolve(), kaggle_packet)
    freeze_boundary = _build_freeze_boundary(
        current_head=current_head,
        subject_head=subject_head,
        oracle_receipt_ref=authoritative_oracle_receipt_path,
        dataset_rows=dataset_rows,
        stage_root=stage_root,
        readme_path=readme_path,
        shard_plan=kaggle_packet["recommended_shards"],
    )
    write_json_stable((stage_root / "contracts" / "stage_freeze_boundary.json").resolve(), freeze_boundary)

    stage_manifest = _build_manifest(
        current_head=current_head,
        subject_head=subject_head,
        source_oracle_receipt_ref=authoritative_oracle_receipt_path.as_posix(),
        source_oracle_scorecard_ref=authoritative_oracle_scorecard_path.as_posix(),
        dataset_rows=dataset_rows,
        stage_root=stage_root,
        mirror_input_root=mirror_input_root,
        zip_path=zip_path,
        readme_path=readme_path,
        base_snapshot_id=str(forge_registry.get("base_snapshot_id", "COHORT0_STAGED_BASE_SNAPSHOT_V1")).strip(),
    )
    stage_manifest["stage_file_entries"] = _stage_file_entries(stage_root)
    stage_manifest["stage_file_count"] = len(stage_manifest["stage_file_entries"])

    _write_stage_zip(stage_root, zip_path)
    zip_sha256 = _sha256_file(zip_path)
    stage_manifest["zip_sha256"] = zip_sha256
    write_json_stable(stage_manifest_path, stage_manifest)
    write_json_stable(
        receipt_path,
        {
            "schema_id": "kt.operator.cohort0_targeted_hypertraining_stage_input_build_receipt.v1",
            "generated_utc": utc_now_iso_z(),
            "status": "PASS",
            "stage_root": stage_root.as_posix(),
            "mirror_input_root": mirror_input_root.as_posix(),
            "zip_path": zip_path.as_posix(),
            "zip_sha256": zip_sha256,
            "readme_path": readme_path.as_posix(),
            "dataset_rows": dataset_rows,
        },
    )

    authoritative_paths = {
        "manifest": (target_root / Path(DEFAULT_TRACKED_MANIFEST_REL).name).resolve(),
        "index": (target_root / Path(DEFAULT_TRACKED_INDEX_REL).name).resolve(),
        "kaggle_packet": (target_root / Path(DEFAULT_TRACKED_KAGGLE_PACKET_REL).name).resolve(),
        "receipt": (target_root / Path(DEFAULT_TRACKED_RECEIPT_REL).name).resolve(),
    }
    tracked_index = _build_index(dataset_rows=dataset_rows, stage_root=stage_root, zip_path=zip_path)
    receipt = _build_receipt(
        current_head=current_head,
        subject_head=subject_head,
        oracle_receipt=_tracked_copy(
            oracle_receipt,
            carrier_role="SOURCE_ONLY",
            ref_field="authoritative_oracle_router_local_receipt_ref",
            authoritative_path=authoritative_oracle_receipt_path,
        ),
        zip_sha256=zip_sha256,
        stage_manifest_external_path=stage_manifest_path,
        kaggle_packet_ref=authoritative_paths["kaggle_packet"],
    )

    write_json_stable(authoritative_paths["manifest"], stage_manifest)
    write_json_stable(authoritative_paths["index"], tracked_index)
    write_json_stable(authoritative_paths["kaggle_packet"], kaggle_packet)
    write_json_stable(authoritative_paths["receipt"], receipt)

    tracked_payloads = {
        Path(DEFAULT_TRACKED_MANIFEST_REL).name: _tracked_copy(
            stage_manifest,
            carrier_role="TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_STAGE_INPUT_MANIFEST",
            ref_field="authoritative_targeted_hypertraining_stage_input_manifest_ref",
            authoritative_path=authoritative_paths["manifest"],
        ),
        Path(DEFAULT_TRACKED_INDEX_REL).name: _tracked_copy(
            tracked_index,
            carrier_role="TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_STAGE_INPUT_INDEX",
            ref_field="authoritative_targeted_hypertraining_stage_input_index_ref",
            authoritative_path=authoritative_paths["index"],
        ),
        Path(DEFAULT_TRACKED_KAGGLE_PACKET_REL).name: _tracked_copy(
            kaggle_packet,
            carrier_role="TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_KAGGLE_PACKET",
            ref_field="authoritative_targeted_hypertraining_kaggle_packet_ref",
            authoritative_path=authoritative_paths["kaggle_packet"],
        ),
        Path(DEFAULT_TRACKED_RECEIPT_REL).name: _tracked_copy(
            receipt,
            carrier_role="TRACKED_CARRIER_ONLY_TARGETED_HYPERTRAINING_STAGE_INPUT_RECEIPT",
            ref_field="authoritative_targeted_hypertraining_stage_input_receipt_ref",
            authoritative_path=authoritative_paths["receipt"],
        ),
    }
    for filename, obj in tracked_payloads.items():
        write_json_stable((reports_root / filename).resolve(), obj)

    return {
        "cohort0_targeted_hypertraining_stage_input_manifest": stage_manifest,
        "cohort0_targeted_hypertraining_stage_input_index": tracked_index,
        "cohort0_targeted_hypertraining_kaggle_packet": kaggle_packet,
        "cohort0_targeted_hypertraining_stage_input_receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    root = repo_root().resolve()
    onedrive_root = root.parent.resolve()
    kt_stage_root = (onedrive_root / "KT_FORGE_STAGE").resolve()
    kaggle_stage_pack_root = (kt_stage_root / "kaggle_stage_pack").resolve()
    default_stage_root = (kaggle_stage_pack_root / DEFAULT_STAGE_FOLDER_NAME).resolve()
    default_mirror = (kt_stage_root / "input_root_targeted_hypertraining").resolve()
    default_zip = (kaggle_stage_pack_root / f"{DEFAULT_STAGE_FOLDER_NAME}.zip").resolve()
    default_stage_manifest = (kaggle_stage_pack_root / "cohort0_targeted_hypertraining_stage_pack_manifest.json").resolve()
    default_receipt = (kaggle_stage_pack_root / "cohort0_targeted_hypertraining_stage_input_build_receipt.json").resolve()
    default_readme = (kaggle_stage_pack_root / "TARGETED_HYPERTRAINING_README.txt").resolve()

    ap = argparse.ArgumentParser(description="Author the six-lobe targeted hypertraining stage inputs and Kaggle packet from the preregistered oracle-positive court.")
    ap.add_argument("--oracle-receipt", default=DEFAULT_ORACLE_RECEIPT_REL)
    ap.add_argument("--oracle-scorecard", default=DEFAULT_ORACLE_SCORECARD_REL)
    ap.add_argument("--stage-pack-manifest", default=DEFAULT_STAGE_PACK_MANIFEST_REL)
    ap.add_argument("--alpha-manifest", default=DEFAULT_ALPHA_MANIFEST_REL)
    ap.add_argument("--forge-registry", default=DEFAULT_FORGE_REGISTRY_REL)
    ap.add_argument("--authoritative-root", default="", help="Optional authoritative output root. Default: <repo>/tmp/cohort0_targeted_hypertraining_stage_inputs_current_head")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    ap.add_argument("--stage-root", default=default_stage_root.as_posix())
    ap.add_argument("--mirror-input-root", default=default_mirror.as_posix())
    ap.add_argument("--zip-path", default=default_zip.as_posix())
    ap.add_argument("--stage-manifest-path", default=default_stage_manifest.as_posix())
    ap.add_argument("--receipt-path", default=default_receipt.as_posix())
    ap.add_argument("--readme-path", default=default_readme.as_posix())
    ap.add_argument("--force", action="store_true", help="Replace any existing stage-pack outputs.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_targeted_hypertraining_stage_input_tranche(
        oracle_receipt_path=_resolve_path(root, str(args.oracle_receipt)),
        oracle_scorecard_path=_resolve_path(root, str(args.oracle_scorecard)),
        stage_pack_manifest_path=_resolve_path(root, str(args.stage_pack_manifest)),
        alpha_manifest_path=_resolve_path(root, str(args.alpha_manifest)),
        forge_registry_path=_resolve_path(root, str(args.forge_registry)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        stage_root=Path(str(args.stage_root)).expanduser().resolve(),
        mirror_input_root=Path(str(args.mirror_input_root)).expanduser().resolve(),
        zip_path=Path(str(args.zip_path)).expanduser().resolve(),
        stage_manifest_path=Path(str(args.stage_manifest_path)).expanduser().resolve(),
        receipt_path=Path(str(args.receipt_path)).expanduser().resolve(),
        readme_path=Path(str(args.readme_path)).expanduser().resolve(),
        force=bool(args.force),
        workspace_root=root,
    )
    receipt = payload["cohort0_targeted_hypertraining_stage_input_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "stage_input_posture": receipt["stage_input_posture"],
                "target_lobe_ids": receipt["target_lobe_ids"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
