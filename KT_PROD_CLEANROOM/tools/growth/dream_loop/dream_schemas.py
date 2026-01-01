from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class DreamSchemaError(ValueError):
    pass


_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(_canonical_json(obj))


def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Iterable[str], name: str) -> None:
    extra = set(payload.keys()) - set(allowed)
    if extra:
        raise DreamSchemaError(f"{name} contains unknown keys: {sorted(extra)} (fail-closed)")


def _require_dict(value: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise DreamSchemaError(f"{name} must be an object (fail-closed)")
    return dict(value)


def _require_list(value: Any, *, name: str) -> List[Any]:
    if not isinstance(value, list):
        raise DreamSchemaError(f"{name} must be a list (fail-closed)")
    return list(value)


def _require_str(value: Any, *, name: str, min_len: int = 1, max_len: int = 4_000) -> str:
    if not isinstance(value, str):
        raise DreamSchemaError(f"{name} must be a string (fail-closed)")
    if not (min_len <= len(value) <= max_len):
        raise DreamSchemaError(f"{name} length out of bounds (fail-closed)")
    return value


def _require_int(value: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise DreamSchemaError(f"{name} must be an integer (fail-closed)")
    if not (lo <= value <= hi):
        raise DreamSchemaError(f"{name} out of bounds (fail-closed)")
    return value


def _validate_hex64(value: str, *, name: str) -> None:
    if not _HEX64_RE.match(value):
        raise DreamSchemaError(f"{name} must be 64 lowercase hex chars (fail-closed)")


def _validate_id(value: str, *, name: str) -> None:
    if not _ID_RE.match(value):
        raise DreamSchemaError(f"{name} invalid id format (fail-closed)")


def _reject_raw_content_fields(payload: Mapping[str, Any], *, name: str) -> None:
    lowered = " ".join(sorted(k.lower() for k in payload.keys()))
    if any(tok in lowered for tok in ("stdout", "stderr", "trace", "cot", "chain", "prompt", "output", "log")):
        raise DreamSchemaError(f"{name} contains raw-content field markers (fail-closed)")


@dataclass(frozen=True)
class DreamCandidateBounds:
    max_candidates: int
    max_hypothesis_chars: int
    max_prompt_chars: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "DreamCandidateBounds":
        payload = _require_dict(data, name="candidate_bounds")
        _reject_unknown_keys(payload, allowed={"max_candidates", "max_hypothesis_chars", "max_prompt_chars"}, name="candidate_bounds")
        max_candidates = _require_int(payload.get("max_candidates", 2), name="max_candidates", lo=2, hi=16)
        max_hypothesis_chars = _require_int(payload.get("max_hypothesis_chars", 1024), name="max_hypothesis_chars", lo=1, hi=4096)
        max_prompt_chars = _require_int(payload.get("max_prompt_chars", 32768), name="max_prompt_chars", lo=128, hi=32768)
        return DreamCandidateBounds(
            max_candidates=max_candidates,
            max_hypothesis_chars=max_hypothesis_chars,
            max_prompt_chars=max_prompt_chars,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_candidates": self.max_candidates,
            "max_hypothesis_chars": self.max_hypothesis_chars,
            "max_prompt_chars": self.max_prompt_chars,
        }


@dataclass(frozen=True)
class DreamBudgetCaps:
    time_ms: int
    stdout_max_bytes: int
    stderr_max_bytes: int
    runner_memory_max_mb: int
    kernel_timeout_kill_ms: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "DreamBudgetCaps":
        payload = _require_dict(data, name="budget_caps")
        _reject_unknown_keys(
            payload,
            allowed={"time_ms", "stdout_max_bytes", "stderr_max_bytes", "runner_memory_max_mb", "kernel_timeout_kill_ms"},
            name="budget_caps",
        )
        time_ms = _require_int(payload.get("time_ms", 20_000), name="time_ms", lo=50, hi=300_000)
        stdout_max_bytes = _require_int(payload.get("stdout_max_bytes", 200_000), name="stdout_max_bytes", lo=256, hi=1_048_576)
        stderr_max_bytes = _require_int(payload.get("stderr_max_bytes", 200_000), name="stderr_max_bytes", lo=0, hi=1_048_576)
        runner_memory_max_mb = _require_int(payload.get("runner_memory_max_mb", 1024), name="runner_memory_max_mb", lo=32, hi=4096)
        kernel_timeout_kill_ms = _require_int(payload.get("kernel_timeout_kill_ms", time_ms + 500), name="kernel_timeout_kill_ms", lo=50, hi=300_000)
        return DreamBudgetCaps(
            time_ms=time_ms,
            stdout_max_bytes=stdout_max_bytes,
            stderr_max_bytes=stderr_max_bytes,
            runner_memory_max_mb=runner_memory_max_mb,
            kernel_timeout_kill_ms=kernel_timeout_kill_ms,
        )

    def to_crucible_budgets(self) -> Dict[str, Any]:
        return {
            "time_ms": self.time_ms,
            "stdout_max_bytes": self.stdout_max_bytes,
            "stderr_max_bytes": self.stderr_max_bytes,
            "runner_memory_max_mb": self.runner_memory_max_mb,
            "kernel_timeout_kill_ms": self.kernel_timeout_kill_ms,
            "token_cap": 0,
            "step_cap": 0,
            "branch_cap": 0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time_ms": self.time_ms,
            "stdout_max_bytes": self.stdout_max_bytes,
            "stderr_max_bytes": self.stderr_max_bytes,
            "runner_memory_max_mb": self.runner_memory_max_mb,
            "kernel_timeout_kill_ms": self.kernel_timeout_kill_ms,
        }


@dataclass(frozen=True)
class DreamSpecSchema:
    schema: str
    schema_version: int
    dream_id: str
    hypothesis: str
    kernel_target: str
    seed: int
    candidate_bounds: DreamCandidateBounds
    budget_caps: DreamBudgetCaps

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "DreamSpecSchema":
        payload = _require_dict(data, name="DreamSpec")
        _reject_unknown_keys(
            payload,
            allowed={"schema", "schema_version", "dream_id", "hypothesis", "kernel_target", "seed", "candidate_bounds", "budget_caps"},
            name="DreamSpec",
        )
        schema = _require_str(payload.get("schema"), name="schema", max_len=64)
        if schema != "kt.dream.spec":
            raise DreamSchemaError("DreamSpec schema mismatch (fail-closed)")
        schema_version = _require_int(payload.get("schema_version", 1), name="schema_version", lo=1, hi=1)
        dream_id = _require_str(payload.get("dream_id"), name="dream_id", max_len=80)
        _validate_id(dream_id, name="dream_id")
        hypothesis = _require_str(payload.get("hypothesis"), name="hypothesis", max_len=4096)
        kernel_target = _require_str(payload.get("kernel_target"), name="kernel_target", max_len=32)
        if kernel_target not in {"V2_SOVEREIGN", "V1_ARCHIVAL"}:
            raise DreamSchemaError("kernel_target invalid (fail-closed)")
        seed = _require_int(payload.get("seed", 0), name="seed", lo=0, hi=2_000_000_000)
        candidate_bounds = DreamCandidateBounds.from_dict(_require_dict(payload.get("candidate_bounds"), name="candidate_bounds"))
        if len(hypothesis) > candidate_bounds.max_hypothesis_chars:
            raise DreamSchemaError("hypothesis exceeds candidate_bounds.max_hypothesis_chars (fail-closed)")
        budget_caps = DreamBudgetCaps.from_dict(_require_dict(payload.get("budget_caps"), name="budget_caps"))
        return DreamSpecSchema(
            schema=schema,
            schema_version=schema_version,
            dream_id=dream_id,
            hypothesis=hypothesis,
            kernel_target=kernel_target,
            seed=seed,
            candidate_bounds=candidate_bounds,
            budget_caps=budget_caps,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "dream_id": self.dream_id,
            "hypothesis": self.hypothesis,
            "kernel_target": self.kernel_target,
            "seed": self.seed,
            "candidate_bounds": self.candidate_bounds.to_dict(),
            "budget_caps": self.budget_caps.to_dict(),
        }

    def spec_hash(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class DreamCandidateSchema:
    candidate_id: str
    scenario_descriptor: Dict[str, Any]
    bounded_payload: Dict[str, Any]

    @staticmethod
    def build(*, dream_spec_hash: str, index: int, hypothesis_hash: str, kernel_target: str) -> "DreamCandidateSchema":
        _validate_hex64(dream_spec_hash, name="dream_spec_hash")
        _validate_hex64(hypothesis_hash, name="hypothesis_hash")
        candidate_id = sha256_text(f"{dream_spec_hash}|{index}")[:32]
        # Keep candidate_id small but stable; still content-addressed.
        scenario_descriptor = {
            "candidate_index": index,
            "hypothesis_hash": hypothesis_hash,
            "kernel_target": kernel_target,
        }
        bounded_payload = {
            "template_id": "C019_CRUCIBLE_V1",
            "candidate_index": index,
        }
        _reject_raw_content_fields(scenario_descriptor, name="scenario_descriptor")
        _reject_raw_content_fields(bounded_payload, name="bounded_payload")
        return DreamCandidateSchema(candidate_id=candidate_id, scenario_descriptor=scenario_descriptor, bounded_payload=bounded_payload)

    def to_dict(self) -> Dict[str, Any]:
        return {"candidate_id": self.candidate_id, "scenario_descriptor": self.scenario_descriptor, "bounded_payload": self.bounded_payload}


@dataclass(frozen=True)
class DreamRunResultSchema:
    dream_id: str
    dream_spec_hash: str
    candidate_ids: Tuple[str, ...]
    candidate_hashes: Tuple[str, ...]
    evaluation_receipt_refs: Tuple[str, ...]
    curriculum_draft_refs: Tuple[str, ...]
    determinism_proof: str
    failure_state: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dream_id": self.dream_id,
            "dream_spec_hash": self.dream_spec_hash,
            "candidate_ids": list(self.candidate_ids),
            "candidate_hashes": list(self.candidate_hashes),
            "evaluation_receipt_refs": list(self.evaluation_receipt_refs),
            "curriculum_draft_refs": list(self.curriculum_draft_refs),
            "determinism_proof": self.determinism_proof,
            "failure_state": self.failure_state,
        }

