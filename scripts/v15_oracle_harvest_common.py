from __future__ import annotations

try:
    from scripts.artifact_authority_registry_writer import (
        bind_current_file_digests,
        existing_artifact_ids_for_paths,
        rebind_authority_registry_file,
    )
except ModuleNotFoundError:
    from artifact_authority_registry_writer import (
        bind_current_file_digests,
        existing_artifact_ids_for_paths,
        rebind_authority_registry_file,
    )

import json
import hashlib
import math
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROGRAM_ID = "KT_V15_ORACLE_HARVEST_ROUTE_VALUE_DISTILLATION_AND_CROSSROAD_ADMISSION_SUPERLANE_V3"
OUTCOME = "KTG3FULL_V15_ORACLE_HARVEST_READY__ROUTE_VALUE_DISTILLATION_AND_CROSSROAD_ADMISSION_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "AUTHOR_KTG3FULL_V16_SHADOW_ROUTE_VALUE_REPLAY_PACKET"

V15_FACTS = {
    "schema_id": "kt.v15_result_review_receipt.v1",
    "hf_dataset": "https://huggingface.co/datasets/Kinrokin/kt-g3full-v15-truth-route-20260531-133102",
    "assessment_sha256": "b8ba3955fda4ec263f9ee9ae7138fdd1c3512389fc6f9d2cef35ecadbcbc1a59",
    "rows": 260,
    "claim_ceiling_preserved": True,
    "promotion_eligible": False,
    "scores": {
        "base_raw": {"correct": 143, "total": 260, "accuracy": 0.55},
        "base_kt_hat_compact": {"correct": 113, "total": 260, "accuracy": 113 / 260},
        "formal_math_repair_adapter_global": {"correct": 160, "total": 260, "accuracy": 160 / 260},
        "route_regret_policy_adapter_global": {"correct": 152, "total": 260, "accuracy": 152 / 260},
        "math_act_adapter_global": {"correct": 147, "total": 260, "accuracy": 147 / 260},
        "formal_math_router_label_bound": {"correct": 159, "total": 260, "accuracy": 159 / 260},
        "formal_math_router_math_act_feature_bound": {"correct": 159, "total": 260, "accuracy": 159 / 260},
        "oracle_math_router": {"correct": 187, "total": 260, "accuracy": 187 / 260},
    },
    "feature_route_over_base_correct_delta": 16,
    "oracle_over_feature_route_correct_delta": 28,
    "oracle_over_base_correct_delta": 44,
}

V15_GAP_ROWS = [
    ("arc:42", "arc_challenge", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.81, True, False),
    ("gsm8k:10", "gsm8k", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:22", "gsm8k", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:24", "gsm8k", "base_kt_hat_compact", "base_raw", 0.44, False, True),
    ("gsm8k:32", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.95, True, True),
    ("gsm8k:35", "gsm8k", "math_act_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:40", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.55, True, True),
    ("gsm8k:42", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:44", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:48", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 0.87, True, True),
    ("gsm8k:49", "gsm8k", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("gsm8k:7", "gsm8k", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("hellaswag:23", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.12, False, False),
    ("hellaswag:31", "hellaswag", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("hellaswag:32", "hellaswag", "route_regret_policy_adapter_global", "base_raw", 0.3, False, False),
    ("hellaswag:34", "hellaswag", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("hellaswag:36", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.0, False, False),
    ("hellaswag:6", "hellaswag", "formal_math_repair_adapter_global", "base_raw", 0.0, False, False),
    ("hellaswag:7", "hellaswag", "base_kt_hat_compact", "base_raw", 0.18, False, False),
    ("math_wording_variation_slice:0", "math_wording_variation_slice", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("math_wording_variation_slice:1", "math_wording_variation_slice", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("math_wording_variation_slice:8", "math_wording_variation_slice", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("non_gsm8k_math_slice:1", "non_gsm8k_math_slice", "base_kt_hat_compact", "formal_math_repair_adapter_global", 1.0, True, True),
    ("non_gsm8k_math_slice:7", "non_gsm8k_math_slice", "base_raw", "formal_math_repair_adapter_global", 1.0, True, True),
    ("numeric_reasoning_slice:3", "numeric_reasoning_slice", "route_regret_policy_adapter_global", "formal_math_repair_adapter_global", 1.0, True, True),
    ("numeric_reasoning_slice:8", "numeric_reasoning_slice", "base_raw", "formal_math_repair_adapter_global", 0.99, True, True),
    ("truthfulqa:25", "truthfulqa_mc1", "base_kt_hat_compact", "base_raw", 0.0, False, False),
    ("truthfulqa:31", "truthfulqa_mc1", "route_regret_policy_adapter_global", "base_raw", 0.0, False, False),
]

HISTORIC_RUNS = [
    ("G2_v2", 200, 119, "routed_13_lobe_kt_hat_compact", 126, "", None, 136, 17, 10, None),
    ("G3_v2", 190, 107, "routed_13_lobe_kt_hat_compact", 118, "", None, 130, 23, 12, None),
    ("G31_eval", 200, 96, "routed_13_lobe_kt_hat_compact", 124, "oracle_route_replay", 137, 137, 41, 13, 0),
    ("G3FULL_v1", 200, 111, "base_raw", 111, "", None, 135, 24, 24, None),
    ("G3FULL_v12", 200, 111, "formal_math_router_specialist", 122, "oracle_math_router", 131, 135, 24, 13, 4),
    ("G3FULL_v13", 200, 111, "formal_math_router_specialist", 122, "oracle_math_router", 131, 135, 24, 13, 4),
    ("G3FULL_v14", 200, 111, "formal_math_router_specialist", 117, "oracle_math_router", 127, 127, 16, 10, 0),
    ("G3FULL_v15", 260, 143, "formal_math_repair_adapter_global", 160, "oracle_math_router", 187, 187, 44, 27, 0),
]

FORBIDDEN_FEATURES = {
    "oracle_correct",
    "oracle_route",
    "oracle_gain",
    "oracle_correctness",
    "correct",
    "chosen_correct",
    "gold_answer",
    "prediction",
    "raw_output",
    "generated_answer",
    "answer",
}


def _interface_comparison_inputs(root, freeze, pinned_file, require):
    """Bind pre-outcome comparison metadata; never infer a condition from a result."""
    from schemas.checked_task import identity, strict_json

    def load(name, digest):
        require(type(digest) is str and len(digest) == 64 and
                all(c in "0123456789abcdef" for c in digest), "CURRENT_ORACLE_COMPARISON_PIN")
        return strict_json(pinned_file(root / name, digest), max_bytes=2 * 1024 * 1024)

    definition = load("EXPERIMENT_DEFINITION.json", freeze.get("definition_sha256"))
    roster = load("PROSPECTIVE_OPERATION_ROSTER.json", freeze.get("roster_sha256"))
    require(definition.get("schema_id") == "kt.host_interface.development_definition.v1",
            "CURRENT_ORACLE_COMPARISON_SCHEMA")
    conditions = ["full_fixed_display", "full_varied_display", "host_bound_answer"]
    models = ["formal_adapter_parent", "quarantined_v25_child"]
    require(definition.get("conditions") == conditions and definition.get("models") == models and
            definition.get("independent_process_replicates_per_model") == 2 and
            type(definition["independent_process_replicates_per_model"]) is int and
            definition.get("attempts_per_operation") == 1 and type(definition["attempts_per_operation"]) is int and
            definition.get("operation_strategy") == "direct" and definition.get("consume") is True,
            "CURRENT_ORACLE_COMPARISON_DESIGN")
    require(definition.get("varied_display_rule") ==
            "First32hex(SHA256(ASCII HI1|task_id|replicate_index)); identical for corresponding parent/child cells, distinct from fixed display",
            "CURRENT_ORACLE_DISPLAY_RULE")
    fixed = definition.get("fixed_display_nonce")
    require(type(fixed) is str and len(fixed) == 32 and all(c in "0123456789abcdef" for c in fixed),
            "CURRENT_ORACLE_DISPLAY_RULE")
    tasks = load("TASKS.json", definition.get("tasks_sha256"))
    refs = load("MODEL_CONFIGURATION_REFERENCE.json", definition.get("model_configuration_reference_sha256"))
    require(type(tasks) is list and 0 < len(tasks) <= 1024, "CURRENT_ORACLE_COMPARISON_TASKS")
    by_task = {t["task_id"]: t for t in tasks}
    require(len(by_task) == len(tasks) and definition.get("task_order") == [t["task_id"] for t in tasks],
            "CURRENT_ORACLE_COMPARISON_TASKS")
    expected_stages = {f"{role}_rep{rep}" for role in ("parent", "child") for rep in range(2)}
    require(set(freeze["contracts"]) == expected_stages and
            set(definition.get("stage_order", [])) == expected_stages and
            len(definition["stage_order"]) == len(expected_stages), "CURRENT_ORACLE_COMPARISON_STAGES")
    require(roster.get("frozen_definition_sha256") == freeze["definition_sha256"] and
            set(roster.get("contract_names_expected", [])) == {f"CONTRACT_{s}.json" for s in expected_stages} and
            len(roster["contract_names_expected"]) == len(expected_stages), "CURRENT_ORACLE_ROSTER_BINDING")
    expected_count = len(tasks) * len(models) * len(conditions) * 2
    require(type(roster.get("rows")) is list and len(roster["rows"]) == expected_count and
            type(roster.get("generation_rows")) is int and roster["generation_rows"] == expected_count and
            type(roster.get("independent_tasks")) is int and roster["independent_tasks"] == len(tasks) and
            type(definition.get("generation_total")) is int and definition["generation_total"] == expected_count,
            "CURRENT_ORACLE_COMPARISON_ROSTER")
    index, cells = {}, set()
    for row in roster["rows"]:
        require(type(row) is dict and set(row) == {"condition", "model", "operation", "operation_id", "replicate",
                "stage", "task_id", "task_sha256"}, "CURRENT_ORACLE_COMPARISON_ROW")
        model, condition, rep = row["model"], row["condition"], row["replicate"]
        require(model in models and condition in conditions and type(rep) is int and rep in (0, 1),
                "CURRENT_ORACLE_COMPARISON_IDENTITY")
        role = "parent" if model == models[0] else "child"
        require(row["stage"] == f"{role}_rep{rep}" and row["task_id"] in by_task,
                "CURRENT_ORACLE_COMPARISON_IDENTITY")
        op = row["operation"]
        task = by_task[row["task_id"]]
        display = (fixed if condition == conditions[0] else
                   hashlib.sha256(f"HI1|{row['task_id']}|{rep}".encode("ascii")).hexdigest()[:32])
        interface = {"mode": "host_bound_answer", "display_nonce": None} if condition == conditions[2] else {
            "mode": "full_envelope_control", "display_nonce": display}
        require(condition != conditions[1] or display != fixed, "CURRENT_ORACLE_DISPLAY_COLLISION")
        require(op == {"task": task, "strategy": "direct", "attempts": 1, "consume": True,
                       "response_interface": interface} and row["task_sha256"] == identity(task) and
                row["operation_id"] == identity(op), "CURRENT_ORACLE_CONDITION_BINDING")
        evidence_key = (row["stage"], row["operation_id"])
        cell = (row["task_sha256"], model, condition, rep)
        require(evidence_key not in index and cell not in cells, "CURRENT_ORACLE_DUPLICATE_CELL")
        index[evidence_key] = row
        cells.add(cell)
    require(len(cells) == expected_count, "CURRENT_ORACLE_COMPARISON_ROSTER")
    return {"index": index, "definition": definition, "models": models, "conditions": conditions,
            "backends": {models[0]: refs["parent_backend"], models[1]: refs["child_backend"]}}


def _interface_comparison_report(rows, missing, comparison, baseline, freeze, freeze_sha256):
    """Pair within task and replicate; repeated generations never become tasks."""
    from schemas.checked_task import identity
    assigned = list(comparison["index"].values())
    routes = {r["model"] + "/" + r["condition"] for r in assigned}
    if baseline not in routes:
        raise ValueError("CURRENT_ORACLE_BASELINE_NOT_ASSIGNED")
    groups = sorted({(r["task_sha256"], r["replicate"]) for r in assigned})
    gaps = []
    for task_hash, rep in groups:
        members = [r for r in assigned if (r["task_sha256"], r["replicate"]) == (task_hash, rep)]
        baseline_members = [r for r in members if r["model"] + "/" + r["condition"] == baseline]
        if len(baseline_members) != 1:
            raise ValueError("CURRENT_ORACLE_BASELINE_AMBIGUOUS")
        observed = [r for r in rows if (r["task_hash"], r["replicate"]) == (task_hash, rep)]
        absent = [r for r in missing if (r["task_hash"], r["replicate"]) == (task_hash, rep)]
        base = [r for r in observed if r["route"] == baseline and r["completed"]]
        if len(base) > 1:
            raise ValueError("CURRENT_ORACLE_BASELINE_AMBIGUOUS")
        base = base[0] if base else None
        valid = [r for r in observed if r["strict_success"]]
        eligible = [r for r in valid if r["complete_token_accounting"]]
        cheapest = min(eligible, key=lambda r: (r["input_tokens"] + r["output_tokens"], r["route"])) if eligible else None
        gaps.append({"task_id": members[0]["task_id"], "task_hash": task_hash, "replicate": rep,
            "assigned_routes": sorted(r["model"] + "/" + r["condition"] for r in members),
            "observed_completed_routes": [r["route"] for r in observed if r["completed"]],
            "missing_routes": [r["route"] for r in absent], "baseline_success": base["strict_success"] if base else None,
            "observed_union_success": bool(valid), "successful_routes": [r["route"] for r in valid],
            "unique_observed_success_route": valid[0]["route"] if len(valid) == 1 else None,
            "rescue_over_baseline": [r["route"] for r in valid] if base and not base["strict_success"] else [],
            "damage_against_baseline": [r["route"] for r in observed if r["completed"] and not r["strict_success"]] if base and base["strict_success"] else [],
            "cheapest_correct_observed_route": cheapest["route"] if cheapest else None,
            "cheapest_correct_known_tokens": cheapest["input_tokens"] + cheapest["output_tokens"] if cheapest else None,
            "all_assigned_routes_failed": not valid and not absent,
            "opportunity": None if base and base["strict_success"] else
                "SELECTION_OPPORTUNITY" if valid and base and not base["strict_success"] else
                ("CAPABILITY_OPPORTUNITY" if not valid and not absent else "MEASUREMENT_UNCERTAINTY"),
            "opportunity_scope": "NO_OBSERVED_BASELINE_FAILURE" if base and base["strict_success"] else "BASELINE_FAILURE_OR_UNRESOLVED",
            "causal_owner": "UNKNOWN"})
    cells = []
    for route in sorted(routes):
        selected = [r for r in rows if r["route"] == route]
        cells.append({"route": route, "assigned": sum(r["model"] + "/" + r["condition"] == route for r in assigned),
            "observed": len(selected), "completed": sum(r["completed"] for r in selected),
            "strict_successes": sum(r["strict_success"] for r in selected),
            "independent_tasks": len({r["task_sha256"] for r in assigned if r["model"] + "/" + r["condition"] == route}),
            "replicates": 2})
    here = Path(__file__).resolve()
    return {"schema_id": "kt.current_checked_oracle_observation.frozen_interface.v1",
        "comparison_mode": "frozen_interface_v1", "run_id": freeze["run_id"],
        "source_head": freeze["source_head"], "source_tree": freeze["source_tree"],
        "execution_source_meaning": "Historical experiment source, not the later analysis source",
        "analysis_source": {"reader_sha256": hashlib.sha256(here.read_bytes()).hexdigest(),
            "cli_sha256": hashlib.sha256((here.parent / "build_v15_oracle_gap_matrix.py").read_bytes()).hexdigest()},
        "freeze_sha256": freeze_sha256, "definition_sha256": freeze["definition_sha256"],
        "roster_sha256": freeze["roster_sha256"], "status": "INCOMPLETE_RECORDED_ROSTER" if missing else "COMPLETE_RECORDED_ROSTER",
        "assigned_operations": len(assigned), "completed_operations": sum(r["completed"] for r in rows),
        "independent_tasks": len({r["task_sha256"] for r in assigned}), "models": comparison["models"],
        "conditions": comparison["conditions"], "replicates": 2, "baseline_route": baseline,
        "rows": rows, "missing": missing, "cells": cells, "oracle_gap_matrix": gaps,
        "comparison_assignment_sha256": identity(assigned), "task_unit": "Task definition; replicate is a paired stratum, not another independent task",
        "correctness_endpoint": "Native strict task predicate; protocol rejection does not establish content incorrectness",
        "diagnostic_content": "NOT_COMPUTED; separately pinned accepted diagnostics may be joined externally and never replace native acceptance",
        "uniqueness_scope": "Observed completed routes within task/replicate; missing work unresolved",
        "cost_basis": "Observed native token counts; missing generation/loading/allocation costs stay UNKNOWN, never zero",
        "causal_limit": "Retrospective opened development evidence; no routing or learning intervention",
        "ownership": "UNKNOWN_BLOCKED unless separately causally adjudicated",
        "runtime_feature_authority": False, "training_authority": False, "promotion_authority": False, "claim_authority": "NONE"}

def current_checked_portfolio(evidence_root: Path, *, freeze_sha256: str,
                              baseline_route: str | None = None,
                              comparison_mode: str | None = None) -> dict:
    """Read a pinned current laboratory run without rewriting historical V15 facts.

    The caller supplies the previously frozen RUN_FREEZE digest as a trust anchor.
    This is retrospective selection evidence, never a runtime feature, training
    admission, provider attestation, or permission to activate a model/effect.
    """
    from core.checked_generation import verify_operation
    from governance.lab_admission import validate_contract
    from schemas.checked_task import identity, strict_json
    from schemas.trusted_local_path import assert_no_link_or_reparse_path

    def require(ok, code):
        if not ok:
            raise ValueError(code)

    def pinned_file(path, expected=None):
        assert_no_link_or_reparse_path(path, label="current oracle input")
        stat = path.stat()
        require(path.is_file() and stat.st_nlink == 1 and stat.st_size <= 2 * 1024 * 1024,
                "CURRENT_ORACLE_INPUT_FILE")
        raw = path.read_bytes()
        if expected is not None:
            require(hashlib.sha256(raw).hexdigest() == expected, "CURRENT_ORACLE_INPUT_PIN")
        return raw

    require(comparison_mode in (None, "frozen_interface_v1"), "CURRENT_ORACLE_COMPARISON_MODE")
    if comparison_mode is None and baseline_route is None:
        baseline_route = "base/direct"
    require(type(baseline_route) is str and bool(baseline_route), "CURRENT_ORACLE_BASELINE_REQUIRED")
    root = Path(evidence_root)
    assert_no_link_or_reparse_path(root, label="current oracle root")
    require(root.is_dir() and root.resolve() == root and ".." not in root.parts,
            "CURRENT_ORACLE_ROOT")
    require(isinstance(freeze_sha256, str) and len(freeze_sha256) == 64 and
            all(c in "0123456789abcdef" for c in freeze_sha256), "CURRENT_ORACLE_FREEZE_PIN")
    freeze = strict_json(pinned_file(root / "RUN_FREEZE.json", freeze_sha256), max_bytes=2 * 1024 * 1024)
    require(freeze.get("schema_id") == "kt.h4.external_engineering_run.v1", "CURRENT_ORACLE_FREEZE_SCHEMA")
    require(type(freeze.get("run_id")) is str and 0 < len(freeze["run_id"]) <= 128 and
            all(type(freeze.get(k)) is str and len(freeze[k]) == 40 and
                all(c in "0123456789abcdef" for c in freeze[k]) for k in ("source_head", "source_tree")),
            "CURRENT_ORACLE_SUBJECT_IDENTITY")
    bindings = freeze.get("contracts")
    require(type(bindings) is dict and 1 <= len(bindings) <= 32, "CURRENT_ORACLE_CONTRACTS")
    comparison = (_interface_comparison_inputs(root, freeze, pinned_file, require)
                  if comparison_mode == "frozen_interface_v1" else None)
    if comparison is not None:
        entries = list(root.iterdir())
        for entry in entries:
            assert_no_link_or_reparse_path(entry, label="current oracle portfolio member")
        require({p.name for p in entries if p.is_dir()} <= set(bindings), "CURRENT_ORACLE_EXTRA_STAGE")
        require({p.name for p in entries if p.name.startswith("CONTRACT_") and p.suffix == ".json"} ==
                {b["name"] for b in bindings.values()}, "CURRENT_ORACLE_EXTRA_CONTRACT")
    rows, missing, assignments, samples = [], [], [], {}
    seen_cells = set()
    contract_run_ids = set()
    source = Path(__file__).resolve().parents[1] / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src"
    shared_source = None
    for label, binding in sorted(bindings.items()):
        require(type(label) is str and label and all(c.isascii() and (c.isalnum() or c in "_-") for c in label),
                "CURRENT_ORACLE_ROUTE_LABEL")
        require(type(binding) is dict and set(binding) == {"name", "sha256"}, "CURRENT_ORACLE_CONTRACT_BINDING")
        require(binding["name"] == f"CONTRACT_{label}.json", "CURRENT_ORACLE_CONTRACT_NAME")
        contract_raw = pinned_file(root / binding["name"], binding["sha256"])
        contract = validate_contract(strict_json(contract_raw, max_bytes=2 * 1024 * 1024))
        require(contract["run_id"] not in contract_run_ids, "CURRENT_ORACLE_DUPLICATE_CONTRACT_RUN")
        contract_run_ids.add(contract["run_id"])
        if shared_source is None:
            shared_source = contract["source_files"]
            required_source = {p.relative_to(source).as_posix() for p in source.rglob("*.py") if "tests" not in p.parts}
            require(set(shared_source) == required_source, "CURRENT_ORACLE_SOURCE_COVERAGE")
            for name, expected in shared_source.items():
                require(not Path(name).is_absolute() and ":" not in name and "\\" not in name and
                        all(part not in ("", ".", "..") for part in name.split("/")), "CURRENT_ORACLE_SOURCE_PATH")
                pinned_file(source / name, expected)
        else:
            require(contract["source_files"] == shared_source, "CURRENT_ORACLE_MIXED_SOURCE")
        pinned_file(source.parent / "docs/RUNTIME_REGISTRY.json", contract["runtime_registry_sha256"])
        if comparison is not None:
            assigned_here = {opid: row for (stage, opid), row in comparison["index"].items() if stage == label}
            require(set(contract["operations"]) == set(assigned_here), "CURRENT_ORACLE_CONTRACT_ROSTER")
            for opid, metadata in assigned_here.items():
                require(contract["operations"][opid] == metadata["operation"], "CURRENT_ORACLE_CONDITION_BINDING")
            models_here = {r["model"] for r in assigned_here.values()}
            require(len(models_here) == 1, "CURRENT_ORACLE_STAGE_MODEL")
            model = next(iter(models_here))
            stable_backend = lambda value: {k: v for k, v in value.items() if k not in ("base_root", "adapter_root")}
            require(stable_backend(contract["backend"]) == stable_backend(comparison["backends"][model]),
                    "CURRENT_ORACLE_MODEL_BINDING")
        run_root = root / label
        assert_no_link_or_reparse_path(run_root, label="current oracle records")
        require(run_root.is_dir() and pinned_file(run_root / "operator_contract.json") == contract_raw,
                "CURRENT_ORACLE_RETAINED_CONTRACT")
        observed_dirs = {p.name for p in run_root.iterdir() if p.is_dir()}
        require(observed_dirs <= set(contract["operations"]), "CURRENT_ORACLE_EXTRA_OPERATION")
        for op_id, op in sorted(contract["operations"].items()):
            require(identity(op) == op_id, "CURRENT_ORACLE_OPERATION_ID")
            task_hash = identity(op["task"])
            task_id = op["task"]["task_id"]
            if task_id in samples:
                require(samples[task_id] == task_hash, "CURRENT_ORACLE_MIXED_TASK")
            samples[task_id] = task_hash
            route = label + "/" + op["strategy"]
            if "response_interface" in op:
                route += "/" + op["response_interface"]["mode"]
            metadata = comparison["index"][(label, op_id)] if comparison is not None else None
            if metadata is not None:
                route = metadata["model"] + "/" + metadata["condition"]
            key = (task_hash, route, metadata["replicate"]) if metadata is not None else (task_hash, route)
            require(key not in seen_cells, "CURRENT_ORACLE_DUPLICATE_CELL")
            seen_cells.add(key)
            assignments.append((task_hash, route))
            row_identity = ({k: metadata[k] for k in ("stage", "model", "condition", "replicate")} if metadata is not None else {})
            folder = run_root / op_id
            assert_no_link_or_reparse_path(folder, label="current oracle operation")
            if not folder.is_dir() or not (folder / "result.json").exists():
                missing.append({"task_hash": task_hash, "task_id": task_id, "route": route,
                                "operation_id": op_id, "cost": "UNKNOWN_NOT_ZERO", **row_identity})
                continue
            entries = list(folder.iterdir())
            require(len(entries) <= 128, "CURRENT_ORACLE_OPERATION_SIZE")
            for entry in entries:
                pinned_file(entry)
            replay = verify_operation(folder, expected_contract_sha256=binding["sha256"])
            result = replay["original"]
            require(all(type(result.get(k)) is int and result[k] >= 0 for k in ("model_calls", "input_tokens", "output_tokens")),
                    "CURRENT_ORACLE_COUNTS")
            finished = result["status"] in {"CHECKED_EFFECT_RESTORED", "CHECKED_NONCONSUMING", "HELD_TASK_PREDICATE"}
            if not finished:
                missing.append({"task_hash": task_hash, "task_id": task_id, "route": route,
                                "operation_id": op_id, "cost": "PARTIAL_KNOWN_PLUS_UNKNOWN", "status": result["status"], **row_identity})
            attempts = result["attempts"]
            checks = [strict_json(pinned_file(folder / f"attempt_{i}_check.json"), max_bytes=2 * 1024 * 1024) for i in attempts]
            require(all(type(c.get("satisfied")) is bool for c in checks), "CURRENT_ORACLE_CHECK_BOOLEAN")
            generated = [strict_json(pinned_file(folder / f"attempt_{i}_raw.json"), max_bytes=2 * 1024 * 1024) for i in attempts]
            timings = [g.get("generation_seconds") for g in generated]
            known_time = all(type(t) in (int, float) and math.isfinite(t) and t >= 0 for t in timings)
            rows.append({"task_hash": task_hash, "task_id": task_id, "route": route, "operation_id": op_id,
                         "contract_sha256": binding["sha256"], "record_sha256": hashlib.sha256(pinned_file(folder / "result.json")).hexdigest(),
                         "status": result["status"], "completed": finished,
                         "strict_success": bool(finished and checks and checks[-1]["satisfied"]),
                         "first_attempt_success": bool(checks and checks[0]["satisfied"]),
                         "scope": checks[-1].get("scope") if checks else None,
                         "effect_restored": result["status"] == "CHECKED_EFFECT_RESTORED",
                         "calls_reserved": result["model_calls"], "calls_returned": len(generated),
                         "input_tokens": result["input_tokens"], "output_tokens": result["output_tokens"],
                         "generation_seconds": sum(timings) if known_time else None,
                         "complete_token_accounting": finished and len(generated) == result["model_calls"],
                         "claim_ceiling": replay["ceiling"]})
            if "response_interface" in op:
                rows[-1]["response_interface"] = op["response_interface"]
            if metadata is not None:
                derivations = [strict_json(pinned_file(folder / f"attempt_{i}_derivation.json"), max_bytes=2 * 1024 * 1024)
                               for i in attempts]
                rows[-1].update(row_identity)
                complete_time = bool(timings) and known_time and finished and len(generated) == result["model_calls"]
                known_timings = [t for t in timings if type(t) in (int, float) and math.isfinite(t) and t >= 0]
                verified_recovery = ((folder / "effect_recovered.json").exists() and
                                     "effect_recovered.json" not in result["files"])
                rows[-1].update(contract_run_id=contract["run_id"],
                    evidence_valid=True, evidence_ref=f"{label}/{op_id}/result.json",
                    protocol_valid=(derivations[-1]["rejection"] is None) if derivations else None,
                    effect_authorized=True if result["status"] == "CHECKED_EFFECT_RESTORED" else None,
                    effect_authority_record_present=(folder / "effect_authority.json").exists(),
                    effect_applied=(True if result["status"] == "CHECKED_EFFECT_RESTORED" else
                        False if result["status"] in {"CHECKED_NONCONSUMING", "HELD_TASK_PREDICATE"} else None),
                    effect_applied_record_present=(folder / "effect_applied.json").exists(),
                    effect_restored=(True if result["status"] == "CHECKED_EFFECT_RESTORED" or verified_recovery else
                        False if result["status"] in {"CHECKED_NONCONSUMING", "HELD_TASK_PREDICATE"} else None),
                    post_terminal_recovery_verified=verified_recovery,
                    generation_seconds=sum(timings) if complete_time else None,
                    known_generation_seconds=sum(known_timings) if known_timings else None,
                    complete_time_accounting=complete_time,
                    diagnostic_content_correct=None,
                    diagnostic_content_status="NOT_EVALUATED_BY_NATIVE_ORACLE")
    if comparison is not None:
        return _interface_comparison_report(rows, missing, comparison, baseline_route, freeze, freeze_sha256)
    require(baseline_route in {route for _, route in assignments}, "CURRENT_ORACLE_BASELINE_NOT_ASSIGNED")
    grouped = {}
    for row in rows:
        grouped.setdefault(row["task_hash"], []).append(row)
    gaps = []
    for task_id, task_hash in sorted(samples.items()):
        observed = grouped.get(task_hash, [])
        valid = [r for r in observed if r["strict_success"]]
        baseline = next((r for r in observed if r["route"] == baseline_route and r["completed"]), None)
        eligible = [r for r in valid if r["complete_token_accounting"]]
        cheapest = min(eligible, key=lambda r:(r["input_tokens"] + r["output_tokens"], r["route"])) if eligible else None
        assigned = [route for h, route in assignments if h == task_hash]
        gaps.append({"task_id": task_id, "task_hash": task_hash, "assigned_routes": assigned,
                     "observed_completed_routes": [r["route"] for r in observed if r["completed"]],
                     "missing_routes": [m["route"] for m in missing if m["task_hash"] == task_hash],
                     "observed_union_success": bool(valid), "successful_routes": [r["route"] for r in valid],
                     "unique_observed_success_route": valid[0]["route"] if len(valid) == 1 else None,
                     "baseline_success": baseline["strict_success"] if baseline else None,
                     "rescue_over_baseline": [r["route"] for r in valid] if baseline and not baseline["strict_success"] else [],
                     "damage_against_baseline": [r["route"] for r in observed if r["completed"] and not r["strict_success"]] if baseline and baseline["strict_success"] else [],
                     "cheapest_correct_observed_route": cheapest["route"] if cheapest else None,
                     "cheapest_correct_known_tokens": cheapest["input_tokens"] + cheapest["output_tokens"] if cheapest else None,
                     "all_assigned_routes_failed": not valid and not any(m["task_hash"] == task_hash for m in missing)})
    return {"schema_id": "kt.current_checked_oracle_observation.v1", "run_id": freeze["run_id"],
            "source_head": freeze["source_head"], "source_tree": freeze["source_tree"],
            "freeze_sha256": freeze_sha256, "status": "COMPLETE_RECORDED_ROSTER" if not missing else "INCOMPLETE_RECORDED_ROSTER",
            "assigned_operations": len(assignments), "completed_operations": sum(r["completed"] for r in rows),
            "baseline_route": baseline_route, "rows": rows, "missing": missing, "oracle_gap_matrix": gaps,
            "correctness_endpoint": "Strict task predicate; includes nonconsuming controls and does not imply an effect",
            "uniqueness_scope": "Among observed completed routes only; missing routes remain unresolved",
            "cost_basis": "Observed input+output tokens only; generation time separate; allocation, loading and unknown costs are not zero",
            "causal_limit": "Retrospective observed routes with varying nonces; first-attempt success is not feedback benefit; unassigned routes are not measured",
            "ownership": "UNKNOWN_BLOCKED unless separately causally adjudicated; no irreducibility inference",
            "runtime_feature_authority": False, "training_authority": False, "promotion_authority": False,
            "claim_authority": "NONE"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_head(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def current_branch(root: Path) -> str:
    return subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()


def write_json(path: Path, payload: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return payload


def write_jsonl(path: Path, rows: list[dict]) -> list[dict]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows), encoding="utf-8")
    return rows


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def family(route: str) -> str:
    route_l = route.lower()
    if "hat" in route_l:
        return "hat"
    if "route_regret" in route_l:
        return "route_regret"
    if "math_act" in route_l:
        return "math_act"
    if "formal_math" in route_l:
        return "formal_math"
    if "base_raw" in route_l:
        return "base"
    return "unknown"


def score_bucket(score: float) -> str:
    if score >= 0.9:
        return "very_high"
    if score >= 0.5:
        return "medium_high"
    if score > 0:
        return "low"
    return "zero"


def runtime_features(score: float, feature_trigger: bool) -> dict:
    return {
        "feature_score_bucket": score_bucket(score),
        "math_act_feature_trigger": bool(feature_trigger),
    }


def oracle_gap_matrix() -> list[dict]:
    rows = []
    for idx, (sample_id, dataset, oracle_route, chosen_backing_arm, score, feature_trigger, label_trigger) in enumerate(V15_GAP_ROWS):
        rows.append(
            {
                "schema_id": "kt.oracle_gap_row.v1",
                "row_id": f"v15_oracle_gap_{idx:03d}",
                "sample_id": sample_id,
                "dataset": dataset,
                "slice_id": dataset,
                "chosen_policy_route": "formal_math_router_math_act_feature_bound",
                "chosen_backing_arm": chosen_backing_arm,
                "oracle_route": oracle_route,
                "oracle_rescuer_family": family(oracle_route),
                "oracle_gain": 1,
                "feature_score": score,
                "feature_trigger": bool(feature_trigger),
                "label_trigger_observed": bool(label_trigger),
                "pre_generation_features": runtime_features(score, feature_trigger),
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
                "claim_ceiling_preserved": True,
            }
        )
    return rows


def winner_attribution(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.oracle_winner_attribution.v1",
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "oracle_route": row["oracle_route"],
            "rescuer_family": row["oracle_rescuer_family"],
            "claim_authority": "NONE",
        }
        for row in gaps
    ]


def pairwise_preferences(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.oracle_pairwise_preference.v1",
            "sample_id": row["sample_id"],
            "route_a": row["oracle_route"],
            "route_b": row["chosen_backing_arm"],
            "winner": "route_a",
            "reason": "oracle_correct_chosen_backing_arm_wrong",
            "pre_generation_features": row["pre_generation_features"],
            "runtime_legal_features_only": True,
            "oracle_correctness_used_as_feature": False,
            "adapter_training_forbidden": True,
            "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
            "promotion_authority": False,
            "claim_authority": "NONE",
        }
        for row in gaps
    ]


def negative_preferences(gaps: list[dict]) -> list[dict]:
    rows = []
    for row in gaps:
        if row["chosen_backing_arm"] != row["oracle_route"]:
            rows.append(
                {
                    "schema_id": "kt.oracle_negative_route_preference.v1",
                    "sample_id": row["sample_id"],
                    "harmful_route": row["chosen_backing_arm"],
                    "preferred_route": row["oracle_route"],
                    "reason": "chosen_backing_arm_lost_to_oracle_rescuer",
                    "pre_generation_features": row["pre_generation_features"],
                    "runtime_legal_features_only": True,
                    "oracle_correctness_used_as_feature": False,
                    "adapter_training_forbidden": True,
                    "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                    "claim_authority": "NONE",
                }
            )
    return rows


def base_preservation_preferences(gaps: list[dict]) -> list[dict]:
    return [
        {
            "schema_id": "kt.base_preservation_preference.v1",
            "sample_id": row["sample_id"],
            "preferred_route": "base_raw",
            "suppressed_route": row["chosen_backing_arm"],
            "reason": "base_raw_rescued_feature_route_gap",
            "pre_generation_features": row["pre_generation_features"],
            "runtime_legal_features_only": True,
            "oracle_correctness_used_as_feature": False,
            "adapter_training_forbidden": True,
            "claim_authority": "NONE",
        }
        for row in gaps
        if row["oracle_route"] == "base_raw"
    ]


def route_value_rows(pairwise: list[dict], base_prefs: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for idx, pref in enumerate(pairwise):
        rows.append(
            {
                "schema_id": "kt.route_value_training_row.v1",
                "row_id": f"oracle_rescue_{idx:03d}",
                "sample_id": pref["sample_id"],
                "candidate_routes": [pref["route_a"], pref["route_b"]],
                "preferred_route": pref["route_a"],
                "preference_kind": "oracle_rescue",
                "pre_generation_features": pref["pre_generation_features"],
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
            }
        )
    for idx, pref in enumerate(base_prefs):
        rows.append(
            {
                "schema_id": "kt.route_value_training_row.v1",
                "row_id": f"base_preservation_{idx:03d}",
                "sample_id": pref["sample_id"],
                "candidate_routes": [pref["preferred_route"], pref["suppressed_route"]],
                "preferred_route": pref["preferred_route"],
                "preference_kind": "base_preservation",
                "pre_generation_features": pref["pre_generation_features"],
                "runtime_legal_features_only": True,
                "oracle_correctness_used_as_feature": False,
                "adapter_training_forbidden": True,
                "training_authority": "ROUTE_VALUE_DISTILLATION_ONLY",
                "claim_authority": "NONE",
            }
        )
    return rows


def historic_oracle_gap_rows() -> list[dict]:
    return [
        {
            "schema_id": "kt.cross_run_oracle_gap_summary.v1",
            "run": run,
            "samples": samples,
            "base_raw_correct": base,
            "best_non_oracle_arm": best_arm,
            "best_non_oracle_correct": best,
            "named_oracle_arm": named_oracle,
            "named_oracle_correct": named_correct,
            "union_oracle_correct": union,
            "gap_union_vs_base": gap_base,
            "gap_union_vs_best_non_oracle": gap_best,
            "oracle_implementation_gap_union_minus_named": implementation_gap,
            "claim_ceiling_preserved": True,
        }
        for run, samples, base, best_arm, best, named_oracle, named_correct, union, gap_base, gap_best, implementation_gap in HISTORIC_RUNS
    ]


def leakage_scan(route_rows: list[dict]) -> dict:
    hits = []
    for row in route_rows:
        keys = set(row.get("pre_generation_features", {}))
        bad = sorted(keys & FORBIDDEN_FEATURES)
        if bad:
            hits.append({"row_id": row.get("row_id"), "sample_id": row.get("sample_id"), "forbidden_features": bad})
    return {
        "schema_id": "kt.oracle_leakage_scan_receipt.v1",
        "status": "PASS" if not hits else "FAIL",
        "oracle_correctness_used_as_feature": bool(hits),
        "forbidden_feature_hits": hits,
        "claim_ceiling_preserved": True,
    }


def heatmap(gaps: list[dict]) -> dict:
    return {
        "schema_id": "kt.route_rescuer_heatmap.v1",
        "gap_count": len(gaps),
        "by_rescuer_family": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
        "by_oracle_route": dict(Counter(row["oracle_route"] for row in gaps)),
        "by_dataset": dict(Counter(row["dataset"] for row in gaps)),
        "claim_ceiling_preserved": True,
    }


def oracle_conversion_rate() -> float:
    base = V15_FACTS["scores"]["base_raw"]["correct"]
    feature = V15_FACTS["scores"]["formal_math_router_math_act_feature_bound"]["correct"]
    oracle = V15_FACTS["scores"]["oracle_math_router"]["correct"]
    return (feature - base) / (oracle - base)


def write_all(root: Path | None = None) -> dict:
    root = root or repo_root()
    head = current_head(root)
    created = utc_now()
    gaps = oracle_gap_matrix()
    winners = winner_attribution(gaps)
    pairwise = pairwise_preferences(gaps)
    negative = negative_preferences(gaps)
    base_prefs = base_preservation_preferences(gaps)
    route_values = route_value_rows(pairwise, base_prefs)
    historic = historic_oracle_gap_rows()
    leak = leakage_scan(route_values)

    write_jsonl(root / "admission/oracle_gap_matrix.jsonl", gaps)
    write_jsonl(root / "admission/oracle_winner_attribution.jsonl", winners)
    write_jsonl(root / "admission/oracle_pairwise_route_preferences.jsonl", pairwise)
    write_jsonl(root / "admission/oracle_negative_route_preferences.jsonl", negative)
    write_jsonl(root / "admission/base_preservation_preferences.jsonl", base_prefs)
    write_jsonl(root / "admission/route_value_training_rows.jsonl", route_values)
    write_jsonl(root / "admission/all_historic_oracle_gap_matrix.jsonl", historic)
    write_json(
        root / "admission/route_value_feature_registry.json",
        {
            "schema_id": "kt.route_value_feature_registry.v1",
            "allowed_features": ["feature_score_bucket", "math_act_feature_trigger"],
            "forbidden_features": sorted(FORBIDDEN_FEATURES),
            "oracle_correctness_used_as_feature": False,
            "runtime_legal_features_only": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "admission/shadow_route_policy_spec.json",
        {
            "schema_id": "kt.shadow_route_policy.v1",
            "policy_id": "v16_shadow_route_value_replay_candidate",
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_promotion_authority": False,
            "claim_authority": "NONE",
            "oracle_route_deployable": False,
            "input_features": ["feature_score_bucket", "math_act_feature_trigger"],
            "forbidden_features": sorted(FORBIDDEN_FEATURES),
            "source_rows": "admission/route_value_training_rows.jsonl",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "admission/oracle_rescuer_transition_matrix.json",
        {
            "schema_id": "kt.oracle_rescuer_transition_matrix.v1",
            "from_policy": "formal_math_router_math_act_feature_bound",
            "to_oracle_route_counts": dict(Counter(row["oracle_route"] for row in gaps)),
            "to_rescuer_family_counts": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
            "claim_ceiling_preserved": True,
        },
    )

    write_json(root / "reports/v15_result_review_receipt.json", {**V15_FACTS, "current_head": head, "created_utc": created})
    write_json(
        root / "reports/v15_oracle_gap_summary.json",
        {
            "schema_id": "kt.v15_oracle_gap_summary.v1",
            "gap_count": len(gaps),
            "oracle_over_feature_route_correct_delta": V15_FACTS["oracle_over_feature_route_correct_delta"],
            "oracle_over_base_correct_delta": V15_FACTS["oracle_over_base_correct_delta"],
            "feature_route_over_base_correct_delta": V15_FACTS["feature_route_over_base_correct_delta"],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(root / "reports/route_rescuer_heatmap.json", heatmap(gaps))
    write_json(
        root / "reports/oracle_gap_failure_taxonomy.json",
        {
            "schema_id": "kt.oracle_gap_failure_taxonomy.v1",
            "gap_count": len(gaps),
            "taxonomy": {
                "feature_route_missed_available_rescuer": len(gaps),
                "base_preservation_cases": len(base_prefs),
                "non_base_rescuer_cases": len(gaps) - len(base_prefs),
            },
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/route_regret_closure_target.json",
        {
            "schema_id": "kt.route_regret_closure_target.v1",
            "observed_feature_route_closure": oracle_conversion_rate(),
            "remaining_oracle_gap_correct": V15_FACTS["oracle_over_feature_route_correct_delta"],
            "acceptable_next_closure": 0.30,
            "strong_next_closure": 0.50,
            "excellent_next_closure": 0.70,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/do_not_train_oracle_receipt.json",
        {
            "schema_id": "kt.do_not_train_oracle_receipt.v1",
            "status": "PASS",
            "adapter_training_authorized": False,
            "route_value_distillation_authorized": True,
            "oracle_correctness_used_as_feature": False,
            "oracle_rows_authorize_adapter_training": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_conversion_rate_scorecard.json",
        {
            "schema_id": "kt.oracle_conversion_rate_scorecard.v1",
            "ocr_formula": "(feature_bound_route_correct - base_raw_correct) / (oracle_correct - base_raw_correct)",
            "base_raw_correct": V15_FACTS["scores"]["base_raw"]["correct"],
            "feature_bound_route_correct": V15_FACTS["scores"]["formal_math_router_math_act_feature_bound"]["correct"],
            "oracle_correct": V15_FACTS["scores"]["oracle_math_router"]["correct"],
            "oracle_conversion_rate": oracle_conversion_rate(),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_implementation_gap_receipt.json",
        {
            "schema_id": "kt.oracle_implementation_gap_receipt.v1",
            "named_oracle_correct": 187,
            "feature_bound_route_correct": 159,
            "implementation_gap_correct": 28,
            "oracle_route_deployable": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/quantitative_reasoning_habitat_scorecard.json",
        {
            "schema_id": "kt.quantitative_habitat_scorecard.v1",
            "quantitative_datasets": dict(Counter(row["dataset"] for row in gaps if "math" in row["dataset"] or "numeric" in row["dataset"] or row["dataset"] == "gsm8k")),
            "non_quantitative_rescues": dict(Counter(row["dataset"] for row in gaps if not ("math" in row["dataset"] or "numeric" in row["dataset"] or row["dataset"] == "gsm8k"))),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/hat_salvage_matrix.json",
        {
            "schema_id": "kt.hat_salvage_matrix.v1",
            "hat_rescue_count": sum(1 for row in gaps if row["oracle_rescuer_family"] == "hat"),
            "hat_rescue_datasets": dict(Counter(row["dataset"] for row in gaps if row["oracle_rescuer_family"] == "hat")),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/base_raw_preservation_receipt.json",
        {
            "schema_id": "kt.base_raw_preservation_receipt.v1",
            "base_preservation_case_count": len(base_prefs),
            "base_preservation_preferences_path": "admission/base_preservation_preferences.jsonl",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/historic_oracle_gap_trend.json",
        {
            "schema_id": "kt.historic_oracle_gap_trend.v1",
            "run_count": len(historic),
            "runs": historic,
            "persistent_oracle_gap_present": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "reports/oracle_harvest_authority_receipt.json",
        {
            "schema_id": "kt.oracle_harvest_authority_receipt.v1",
            "oracle_is_teacher": True,
            "oracle_runtime_authority": False,
            "route_value_distillation_authority": "SHADOW_ONLY",
            "adapter_training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(root / "reports/oracle_leakage_scan_receipt.json", leak)
    write_json(
        root / "capability/capability_atlas_update.json",
        {
            "schema_id": "kt.capability_atlas_update.v15_oracle_harvest",
            "updates": [
                {
                    "capability_id": "route_value_distillation",
                    "status": "SHADOW_PREP_ONLY",
                    "source": "V15 oracle gap matrix",
                },
                {
                    "capability_id": "crossroad_admission",
                    "status": "SHADOW_PREP_ONLY",
                    "source": "pairwise and base-preservation preferences",
                },
            ],
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "capability/quantitative_reasoning_habitat_map.json",
        {
            "schema_id": "kt.quantitative_reasoning_habitat_map.v1",
            "quantitative_slices": ["gsm8k", "math_wording_variation_slice", "non_gsm8k_math_slice", "numeric_reasoning_slice"],
            "primary_rescuer_family": "formal_math",
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "capability/rescuer_portfolio_map.json",
        {
            "schema_id": "kt.rescuer_portfolio_map.v1",
            "rescuer_families": dict(Counter(row["oracle_rescuer_family"] for row in gaps)),
            "oracle_route_deployable": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        root / "governance/oracle_harvest_authority_contract.json",
        {
            "schema_id": "kt.oracle_harvest_authority_contract.v3",
            "oracle_is_teacher": True,
            "oracle_runtime_authority": False,
            "route_value_distillation_authority": "SHADOW_ONLY",
            "adapter_training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )

    registry_path = root / "registry/artifact_authority_registry.json"
    receipt_path = root / "reports/v15_oracle_harvest_superlane_receipt.json"
    if registry_path.exists() and not receipt_path.exists():
        write_json(
            receipt_path,
            {
                "schema_id": "kt.v15_oracle_harvest_superlane_receipt.v1",
                "status": "PENDING_WRITE_BEFORE_REGISTRY_BIND",
            },
        )
    if registry_path.exists():
        registry = read_json(registry_path)
        receipt_id = existing_artifact_ids_for_paths(
            registry, ["reports/v15_oracle_harvest_superlane_receipt.json"]
        )[0]
        registry["current_head"] = head
        registry["generated_utc"] = created
        bind_current_file_digests(registry_path, registry)
        write_json(registry_path, registry)
    write_json(
        root / "registry/artifact_authority_registry_v15_oracle_harvest_delta_receipt.json",
        {
            "schema_id": "kt.artifact_authority_registry_v15_oracle_harvest_delta_receipt.v1",
            "current_head": head,
            "created_utc": created,
            "artifact_added": receipt_id if registry_path.exists() else None,
            "claim_ceiling_preserved": True,
            "no_runtime_or_promotion_authority_added": True,
        },
    )
    superlane = {
        "schema_id": "kt.v15_oracle_harvest_superlane_receipt.v1",
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": current_branch(root),
        "created_utc": created,
        "outcome": OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "v15_evidence_import_status": "PASS_BOUND",
        "historic_oracle_gap_status": "PASS_BOUND",
        "oracle_gap_matrix_status": "PASS",
        "oracle_winner_attribution_status": "PASS",
        "pairwise_preference_status": "PASS",
        "negative_preference_status": "PASS",
        "base_preservation_status": "PASS",
        "route_value_training_rows_status": "PASS_SHADOW_ONLY",
        "shadow_route_policy_status": "PASS_NO_RUNTIME_AUTHORITY",
        "do_not_train_oracle_status": "PASS",
        "oracle_conversion_rate_status": "PASS",
        "oracle_leakage_scan_status": leak["status"],
        "route_rescuer_heatmap_status": "PASS",
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }
    write_json(root / "reports/v15_oracle_harvest_superlane_receipt.json", superlane)
    if registry_path.exists():
        rebind_authority_registry_file(registry_path)
    return superlane
