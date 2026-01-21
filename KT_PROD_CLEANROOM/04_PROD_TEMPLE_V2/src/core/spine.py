from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict

from core.import_truth_guard import ImportTruthGuard
from core.invariants_gate import InvariantsGate
from core.runtime_registry import RuntimeRegistryError, load_runtime_registry


@dataclass(frozen=True)
class SpineError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _runtime_registry_hash(registry: Any) -> str:
    # Deterministic registry fingerprint for temporal binding (no silent discovery).
    # The RuntimeRegistry dataclass is JSON-shaped; we re-encode it canonically.
    try:
        obj = {
            "registry_version": registry.registry_version,
            "canonical_entry": {"module": registry.canonical_entry.module, "callable": registry.canonical_entry.callable},
            "canonical_spine": {"module": registry.canonical_spine.module, "callable": registry.canonical_spine.callable},
            "state_vault": {"jsonl_path": registry.state_vault.jsonl_path},
            "runtime_import_roots": list(registry.runtime_import_roots),
            "organs_by_root": dict(registry.organs_by_root),
            "import_truth_matrix": {k: list(v) for k, v in registry.import_truth_matrix.items()},
            "dry_run": {"no_network": registry.dry_run.no_network, "providers_enabled": registry.dry_run.providers_enabled},
        }
    except Exception as exc:  # noqa: BLE001
        raise SpineError(f"Unable to fingerprint runtime registry (fail-closed): {exc.__class__.__name__}")
    return _sha256_text(_canonical_json(obj))


def run(context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        registry = load_runtime_registry()
    except RuntimeRegistryError as exc:
        raise SpineError(str(exc))

    # Install Import Truth before importing any non-core organs.
    ImportTruthGuard.install(registry)

    # Belt-and-suspenders: re-assert invariants at Spine boundary.
    InvariantsGate.assert_runtime_invariants(context)

    vault_path = registry.resolve_state_vault_jsonl_path()

    # Imports deferred until after Import Truth guard is installed.
    from cognition.cognitive_engine import CognitiveEngine  # noqa: E402
    from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema  # noqa: E402
    from council.council_router import CouncilRouter  # noqa: E402
    from council.council_schemas import CouncilPlanSchema, CouncilRequestSchema  # noqa: E402
    from curriculum.curriculum_ingest import CurriculumIngest  # noqa: E402
    from curriculum.curriculum_schemas import CurriculumPackageSchema  # noqa: E402
    from governance.event_logger import log_governance_event  # noqa: E402
    from governance.events import build_inputs_envelope, build_outputs_envelope  # noqa: E402
    from memory.replay import validate_state_vault_chain  # noqa: E402
    from memory.state_vault import StateVault  # noqa: E402
    from multiverse.multiverse_engine import MultiverseEngine  # noqa: E402
    from multiverse.multiverse_schemas import MAX_TOTAL_TOKENS, MultiverseEvaluationRequestSchema  # noqa: E402
    from paradox.paradox_engine import ParadoxEngine  # noqa: E402
    from paradox.paradox_schemas import ParadoxTriggerSchema  # noqa: E402
    from schemas.base_schema import SchemaValidationError  # noqa: E402
    from thermodynamics.budget_engine import BudgetEngine  # noqa: E402
    from thermodynamics.budget_schemas import BudgetConsumptionSchema, BudgetRequestSchema  # noqa: E402
    from temporal.temporal_engine import TemporalEngine  # noqa: E402
    from temporal.temporal_schemas import TemporalForkRequestSchema, TemporalReplayRequestSchema  # noqa: E402

    vault = StateVault(path=vault_path)

    vault.append(event_type="V2_PULSE", organ_id="Spine")

    # Hash-only governance pulse (no policy internals; no raw content persisted).
    ctx_hash = _sha256_text(_canonical_json(context))
    inputs = build_inputs_envelope(
        policy_id="p.v2.pulse",
        policy_version_hash=ctx_hash,
        subject_hash=("0" * 64),
        context_hash=ctx_hash,
        rule_id="r.v2.pulse",
    )
    outputs = build_outputs_envelope(decision="ALLOW", obligations_hash=ctx_hash)
    log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    input_text = context.get("envelope", {}).get("input")
    candidate_obj: Any = None
    if isinstance(input_text, str) and input_text.strip().startswith("{"):
        try:
            candidate_obj = json.loads(input_text)
        except Exception:
            candidate_obj = None

    registry_hash = _runtime_registry_hash(registry)

    # C017: Budget domain allocation (fail-closed). This establishes global ceilings for this Spine run.
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == BudgetRequestSchema.SCHEMA_ID:
        try:
            budget_request = BudgetRequestSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Budget request invalid (fail-closed): {exc}")
        if budget_request.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Budget request runtime_registry_hash mismatch (fail-closed)")
        budget_allocation = BudgetEngine.allocate(context=context, request=budget_request)
    else:
        budget_allocation = BudgetEngine.allocate_default(context=context, runtime_registry_hash=registry_hash)

    alloc = budget_allocation.to_dict()
    thermodynamics_summary: Dict[str, Any] = {
        "status": alloc["status"],
        "allocation_hash": alloc["allocation_hash"],
        "refusal_code": alloc.get("refusal_code"),
        "token_ceiling": alloc["token_ceiling"],
        "step_ceiling": alloc["step_ceiling"],
        "branch_ceiling": alloc["branch_ceiling"],
        "memory_ceiling_bytes": alloc["memory_ceiling_bytes"],
        "duration_ceiling_millis": alloc["duration_ceiling_millis"],
    }
    if alloc["status"] != "OK":
        inputs = build_inputs_envelope(
            policy_id="p.v2.thermodynamics.allocate",
            policy_version_hash=alloc["allocation_hash"],
            subject_hash=_sha256_text("thermodynamics.allocate"),
            context_hash=alloc["allocation_hash"],
            rule_id="r.v2.thermodynamics.allocate.v1",
        )
        outputs = build_outputs_envelope(decision="DENY", obligations_hash=_sha256_text(str(alloc.get("refusal_code", ""))))
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)
        raise SpineError(f"Thermodynamics allocation refused (fail-closed): {alloc.get('refusal_code')}")

    tokens_used = 0
    steps_used = 0
    branches_used = 0
    memory_bytes_used = 0
    duration_millis_used = 0

    def _budget_precheck(*, add_tokens: int = 0, add_steps: int = 0, add_branches: int = 0, policy_label: str) -> None:
        nonlocal tokens_used, steps_used, branches_used, memory_bytes_used, duration_millis_used
        usage_payload = {
            "schema_id": BudgetConsumptionSchema.SCHEMA_ID,
            "schema_version_hash": BudgetConsumptionSchema.SCHEMA_VERSION_HASH,
            "allocation_hash": alloc["allocation_hash"],
            "tokens_used": tokens_used + int(add_tokens),
            "steps_used": steps_used + int(add_steps),
            "branches_used": branches_used + int(add_branches),
            "memory_bytes_used": memory_bytes_used,
            "duration_millis_used": duration_millis_used,
        }
        try:
            usage = BudgetConsumptionSchema.from_dict(usage_payload)
        except SchemaValidationError as exc:
            raise SpineError(f"Thermodynamics usage invalid (fail-closed): {exc}")
        result = BudgetEngine.consume(context=context, allocation=budget_allocation, usage=usage).to_dict()
        if result["status"] != "OK":
            inputs = build_inputs_envelope(
                policy_id=f"p.v2.thermodynamics.enforce.{policy_label}",
                policy_version_hash=alloc["allocation_hash"],
                subject_hash=_sha256_text(policy_label),
                context_hash=alloc["allocation_hash"],
                rule_id=f"r.v2.thermodynamics.enforce.{policy_label}.v1",
            )
            outputs = build_outputs_envelope(
                decision="DENY",
                obligations_hash=_sha256_text(str(result.get("refusal_code", ""))),
            )
            log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)
            raise SpineError(f"Thermodynamics refusal (fail-closed): {result.get('refusal_code')}")
        tokens_used += int(add_tokens)
        steps_used += int(add_steps)
        branches_used += int(add_branches)

    paradox_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == ParadoxTriggerSchema.SCHEMA_ID:
        try:
            trigger = ParadoxTriggerSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Paradox trigger invalid (fail-closed): {exc}")

        _budget_precheck(add_steps=1, policy_label="paradox.run")
        result = ParadoxEngine.run(context=context, trigger=trigger)
        r = result.to_dict()
        paradox_summary = {
            "status": r["status"],
            "eligible": r["eligible"],
            "trigger_hash": r["trigger_hash"],
            "task_hash": r["task_hash"],
        }

        if r["eligible"]:
            # Hash-only governance event (no raw task data persisted).
            inputs = build_inputs_envelope(
                policy_id="p.v2.paradox.inject",
                policy_version_hash=r["trigger_hash"],
                subject_hash=trigger.data["subject_hash"],
                context_hash=r["trigger_hash"],
                rule_id="r.v2.paradox.inject.v1",
            )
            outputs = build_outputs_envelope(decision="ALLOW", obligations_hash=r["task_hash"])
            log_governance_event(
                vault=vault,
                event_type="GOV_POLICY_APPLY",
                inputs_envelope=inputs,
                outputs_envelope=outputs,
            )

    temporal_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict):
        schema_id = candidate_obj.get("schema_id")

        if schema_id == TemporalForkRequestSchema.SCHEMA_ID:
            try:
                req = TemporalForkRequestSchema.from_dict(candidate_obj)
            except SchemaValidationError as exc:
                raise SpineError(f"Temporal fork request invalid (fail-closed): {exc}")

            if req.data["runtime_registry_hash"] != registry_hash:
                raise SpineError("Temporal fork request runtime_registry_hash mismatch (fail-closed)")

            _budget_precheck(add_steps=1, policy_label="temporal.fork")
            fork = TemporalEngine.create_fork(context=context, request=req)
            f = fork.to_dict()
            temporal_summary = {
                "status": "OK",
                "mode": "FORK",
                "fork_hash": f["fork_hash"],
                "request_hash": f["request_hash"],
                "context_identity_hash": f["context_identity_hash"],
            }

            inputs = build_inputs_envelope(
                policy_id="p.v2.temporal.fork",
                policy_version_hash=f["request_hash"],
                subject_hash=f["anchor_hash"],
                context_hash=f["fork_hash"],
                rule_id="r.v2.temporal.fork.v1",
            )
            outputs = build_outputs_envelope(decision="ALLOW", obligations_hash=f["fork_hash"])
            log_governance_event(
                vault=vault,
                event_type="GOV_POLICY_APPLY",
                inputs_envelope=inputs,
                outputs_envelope=outputs,
            )

        elif schema_id == TemporalReplayRequestSchema.SCHEMA_ID:
            try:
                req = TemporalReplayRequestSchema.from_dict(candidate_obj)
            except SchemaValidationError as exc:
                raise SpineError(f"Temporal replay request invalid (fail-closed): {exc}")

            if req.data["runtime_registry_hash"] != registry_hash:
                raise SpineError("Temporal replay request runtime_registry_hash mismatch (fail-closed)")

            _budget_precheck(add_steps=int(req.data["max_steps"]), policy_label="temporal.replay")
            result = TemporalEngine.replay(context=context, request=req)
            r = result.to_dict()
            temporal_summary = {
                "status": r["status"],
                "mode": "REPLAY",
                "fork_hash": r["fork_hash"],
                "replay_hash": r["replay_hash"],
                "outcome_hash": r["outcome_hash"],
                "steps_executed": r["steps_executed"],
                "rejection_code": r["rejection_code"],
            }

            inputs = build_inputs_envelope(
                policy_id="p.v2.temporal.replay",
                policy_version_hash=r["replay_hash"],
                subject_hash=r["fork_hash"],
                context_hash=r["replay_hash"],
                rule_id="r.v2.temporal.replay.v1",
            )
            outputs = build_outputs_envelope(decision="ALLOW", obligations_hash=r["outcome_hash"])
            log_governance_event(
                vault=vault,
                event_type="GOV_POLICY_APPLY",
                inputs_envelope=inputs,
                outputs_envelope=outputs,
            )

    multiverse_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == MultiverseEvaluationRequestSchema.SCHEMA_ID:
        try:
            req = MultiverseEvaluationRequestSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Multiverse evaluation request invalid (fail-closed): {exc}")

        if req.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Multiverse runtime_registry_hash mismatch (fail-closed)")

        total_tokens = 0
        for c in req.data["candidates"]:
            if isinstance(c, dict) and isinstance(c.get("token_count"), int):
                total_tokens += int(c["token_count"])
        if total_tokens > MAX_TOTAL_TOKENS:
            raise SpineError("Multiverse total candidate tokens exceed threshold (fail-closed)")

        _budget_precheck(add_tokens=total_tokens, add_steps=1, add_branches=len(req.data["candidates"]), policy_label="multiverse.evaluate")
        result = MultiverseEngine.evaluate(context=context, request=req)
        r = result.to_dict()
        multiverse_summary = {
            "status": "OK",
            "evaluation_id": r["evaluation_id"],
            "result_hash": r["result_hash"],
            "coherence_score": r["coherence_score"],
            "ranking": r["ranking"],
            "candidates": [{"candidate_id": c["candidate_id"], "aggregate_score": c["aggregate_score"]} for c in r["candidates"]],
        }

    council_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == CouncilRequestSchema.SCHEMA_ID:
        try:
            req = CouncilRequestSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Council request invalid (fail-closed): {exc}")

        if req.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Council request runtime_registry_hash mismatch (fail-closed)")

        _budget_precheck(
            add_tokens=int(req.data["total_token_cap"]),
            add_steps=1,
            add_branches=len(req.data["provider_ids"]),
            policy_label="council.plan",
        )
        plan = CouncilRouter.plan(context=context, request=req)
        p = plan.to_dict()
        council_summary = {
            "status": p["status"],
            "mode": p["mode"],
            "plan_hash": p["plan_hash"],
            "request_hash": p["request_hash"],
            "refusal_code": p.get("refusal_code"),
            "providers": [c["provider_id"] for c in p["provider_calls"]],
        }

        decision = "ALLOW" if p["status"] == "OK" else "DENY"
        inputs = build_inputs_envelope(
            policy_id="p.v2.council.plan",
            policy_version_hash=p["request_hash"],
            subject_hash=req.data["input_hash"],
            context_hash=p["plan_hash"],
            rule_id="r.v2.council.plan.v1",
        )
        outputs = build_outputs_envelope(decision=decision, obligations_hash=p["plan_hash"])
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    elif isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == CouncilPlanSchema.SCHEMA_ID:
        try:
            plan = CouncilPlanSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Council plan invalid (fail-closed): {exc}")

        if plan.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Council plan runtime_registry_hash mismatch (fail-closed)")

        planned_tokens = 0
        for c in plan.data["provider_calls"]:
            if isinstance(c, dict) and isinstance(c.get("max_tokens"), int):
                planned_tokens += int(c["max_tokens"])

        _budget_precheck(
            add_tokens=planned_tokens,
            add_steps=1,
            add_branches=len(plan.data["provider_calls"]),
            policy_label="council.execute",
        )
        result = CouncilRouter.execute(context=context, plan=plan)
        r = result.to_dict()
        council_summary = {
            "status": r["status"],
            "plan_hash": r["plan_hash"],
            "result_hash": r["result_hash"],
            "refusal_code": r.get("refusal_code"),
            "error_code": r.get("error_code"),
        }

        decision = "ALLOW" if r["status"] in {"OK", "DRY_RUN"} else "DENY"
        inputs = build_inputs_envelope(
            policy_id="p.v2.council.execute",
            policy_version_hash=r["result_hash"],
            subject_hash=r["plan_hash"],
            context_hash=r["result_hash"],
            rule_id="r.v2.council.execute.v1",
        )
        outputs = build_outputs_envelope(decision=decision, obligations_hash=r["result_hash"])
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    cognition_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == CognitiveRequestSchema.SCHEMA_ID:
        try:
            req = CognitiveRequestSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Cognitive request invalid (fail-closed): {exc}")

        if req.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Cognitive request runtime_registry_hash mismatch (fail-closed)")

        _budget_precheck(
            add_steps=int(req.data["max_steps"]),
            add_branches=int(req.data["max_branching"]),
            policy_label="cognition.plan",
        )
        plan = CognitiveEngine.plan(context=context, request=req)
        p = plan.to_dict()
        cognition_summary = {
            "status": p["status"],
            "mode": p["mode"],
            "plan_hash": p["plan_hash"],
            "request_hash": p["request_hash"],
            "refusal_code": p.get("refusal_code"),
            "steps": len(p["steps"]),
        }

        decision = "ALLOW" if p["status"] == "OK" else "DENY"
        inputs = build_inputs_envelope(
            policy_id="p.v2.cognition.plan",
            policy_version_hash=p["request_hash"],
            subject_hash=req.data["input_hash"],
            context_hash=p["plan_hash"],
            rule_id="r.v2.cognition.plan.v1",
        )
        outputs = build_outputs_envelope(decision=decision, obligations_hash=p["plan_hash"])
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    elif isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == CognitivePlanSchema.SCHEMA_ID:
        try:
            plan = CognitivePlanSchema.from_dict(candidate_obj)
        except SchemaValidationError as exc:
            raise SpineError(f"Cognitive plan invalid (fail-closed): {exc}")

        if plan.data["runtime_registry_hash"] != registry_hash:
            raise SpineError("Cognitive plan runtime_registry_hash mismatch (fail-closed)")

        _budget_precheck(add_steps=len(plan.data["steps"]), policy_label="cognition.execute")
        result = CognitiveEngine.execute(context=context, plan=plan)
        r = result.to_dict()
        cognition_summary = {
            "status": r["status"],
            "plan_hash": r["plan_hash"],
            "result_hash": r["result_hash"],
            "refusal_code": r.get("refusal_code"),
            "error_code": r.get("error_code"),
            "steps": len(r["steps"]),
        }

        decision = "ALLOW" if r["status"] == "OK" else "DENY"
        inputs = build_inputs_envelope(
            policy_id="p.v2.cognition.execute",
            policy_version_hash=r["result_hash"],
            subject_hash=r["plan_hash"],
            context_hash=r["result_hash"],
            rule_id="r.v2.cognition.execute.v1",
        )
        outputs = build_outputs_envelope(decision=decision, obligations_hash=r["result_hash"])
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    curriculum_summary: Dict[str, Any] = {"status": "SKIPPED"}
    if isinstance(candidate_obj, dict) and candidate_obj.get("schema_id") == CurriculumPackageSchema.SCHEMA_ID:
        rrh = candidate_obj.get("runtime_registry_hash")
        if rrh != registry_hash:
            raise SpineError("Curriculum package runtime_registry_hash mismatch (fail-closed)")

        _budget_precheck(add_steps=1, policy_label="curriculum.ingest")
        ingest_result = CurriculumIngest.accept_payload(context=context, package_payload=candidate_obj)
        receipt = ingest_result.receipt.to_dict()
        curriculum_summary = {
            "status": receipt["status"],
            "package_hash": receipt["package_hash"],
            "receipt_hash": receipt["receipt_hash"],
            "refusal_code": receipt.get("refusal_code"),
        }

        decision = "ALLOW" if receipt["status"] == "OK" else "DENY"
        inputs = build_inputs_envelope(
            policy_id="p.v2.curriculum.ingest",
            policy_version_hash=receipt["package_hash"],
            subject_hash=receipt["package_hash"],
            context_hash=receipt["receipt_hash"],
            rule_id="r.v2.curriculum.ingest.v1",
        )
        outputs = build_outputs_envelope(decision=decision, obligations_hash=receipt["receipt_hash"])
        log_governance_event(vault=vault, event_type="GOV_POLICY_APPLY", inputs_envelope=inputs, outputs_envelope=outputs)

    replay = validate_state_vault_chain(vault_path)

    # --- Emit governance_verdict.json artifact (canonical, always, one per run) ---


    from governance.verdict import emit_governance_verdict  # noqa: E402
    from pathlib import Path
    artifact_root_value = context.get("artifact_root")
    if artifact_root_value is None:
        artifact_root = vault_path.parent
    else:
        artifact_root = Path(artifact_root_value).resolve()

    # Unconditional, fail-closed governance verdict emission
    verdict = context.get("governance_verdict", "FAIL")
    rationale = context.get("governance_rationale", "NO_VERDICT_EMITTED")
    emit_governance_verdict(
        artifact_dir=artifact_root,
        verdict=verdict,
        rationale=rationale,
    )
    artifact_dir = artifact_root
    verdict = "FAIL"  # Kernel phase 1: always FAIL, runner will still mark governance_pass = false
    rationale = "Governance verdict emission: phase 1 kernel test (always FAIL)."
    emit_governance_verdict(
        artifact_dir=artifact_dir,
        verdict=verdict,
        rationale=rationale,
    )

    return {
        "status": "OK",
        "record_count": replay.record_count,
        "head_hash": replay.head_hash,
        "thermodynamics": thermodynamics_summary,
        "paradox": paradox_summary,
        "temporal": temporal_summary,
        "multiverse": multiverse_summary,
        "council": council_summary,
        "cognition": cognition_summary,
        "curriculum": curriculum_summary,
    }
