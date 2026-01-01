from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Mapping, Sequence, Tuple

from multiverse.multiverse_schemas import MultiverseEvaluationRequestSchema, MultiverseEvaluationResultSchema
from schemas.schema_hash import sha256_json


RuntimeContext = Dict[str, Any]


@dataclass(frozen=True)
class ConstitutionalViolationError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class MultiverseEngineError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


class _FrozenList(Sequence[Any]):
    def __init__(self, items: Tuple[Any, ...]) -> None:
        self._items = items

    def __getitem__(self, idx: int) -> Any:
        return self._items[idx]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __setitem__(self, _k: Any, _v: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def append(self, _v: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def extend(self, _v: Iterable[Any]) -> None:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def insert(self, _i: int, _v: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def pop(self, _i: int = -1) -> Any:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def remove(self, _v: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def clear(self) -> None:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def reverse(self) -> None:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def sort(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")


class _FrozenDict(Mapping[str, Any]):
    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    def __getitem__(self, k: str) -> Any:
        return self._data[k]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __setitem__(self, _k: str, _v: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def __delitem__(self, _k: str) -> None:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def pop(self, _k: str, _default: Any = None) -> Any:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def popitem(self) -> Tuple[str, Any]:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def clear(self) -> None:
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def setdefault(self, _k: str, _default: Any = None) -> Any:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")

    def update(self, _other: Mapping[str, Any] | None = None, **kwargs: Any) -> None:  # noqa: ANN401
        raise ConstitutionalViolationError("RuntimeContext is read-only (fail-closed)")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        frozen: Dict[str, Any] = {}
        for k, v in value.items():
            frozen[str(k)] = _freeze_json(v)
        return _FrozenDict(frozen)
    if isinstance(value, list):
        return _FrozenList(tuple(_freeze_json(v) for v in value))
    return value


def _context_identity_hash(context: Mapping[str, Any]) -> str:
    schema_id = context.get("schema_id")
    schema_version_hash = context.get("schema_version_hash")
    constitution_version_hash = context.get("constitution_version_hash")
    if not isinstance(schema_id, str) or not isinstance(schema_version_hash, str) or not isinstance(constitution_version_hash, str):
        raise MultiverseEngineError("context missing schema/constitution identifiers (fail-closed)")
    return sha256_json(
        {
            "schema_id": schema_id,
            "schema_version_hash": schema_version_hash,
            "constitution_version_hash": constitution_version_hash,
        }
    )


def _metric_to_micro(value: Any) -> int:  # noqa: ANN401
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MultiverseEngineError("metric value must be numeric (fail-closed)")
    f = float(value)
    if f < 0.0 or f > 1.0:
        raise MultiverseEngineError("metric value must be in [0.0, 1.0] (fail-closed)")
    return int(round(f * 1_000_000))


def _evaluate_candidate(*, candidate: Dict[str, Any], metric_names: Sequence[str]) -> Tuple[Dict[str, float], int]:
    metrics = candidate.get("metrics")
    if not isinstance(metrics, dict):
        raise MultiverseEngineError("candidate.metrics must be an object (fail-closed)")

    micros: Dict[str, int] = {}
    for m in metric_names:
        micros[m] = _metric_to_micro(metrics.get(m))

    sum_micro = sum(micros.values())
    avg_micro = int(round(sum_micro / len(micros)))
    scores = {k: (v / 1_000_000.0) for k, v in micros.items()}
    return scores, avg_micro


class MultiverseEngine:
    @staticmethod
    def _freeze_context_for_tests(context: RuntimeContext) -> Mapping[str, Any]:
        return MultiverseEngine._freeze_context(context)

    @staticmethod
    def _freeze_context(context: RuntimeContext) -> Mapping[str, Any]:
        if not isinstance(context, dict):
            raise MultiverseEngineError("context must be a dict (fail-closed)")
        return _freeze_json(context)

    @staticmethod
    def evaluate(*, context: RuntimeContext, request: MultiverseEvaluationRequestSchema) -> MultiverseEvaluationResultSchema:
        frozen_context = MultiverseEngine._freeze_context(context)
        ctx_hash = _context_identity_hash(frozen_context)

        req = request.to_dict()
        metric_names = list(req["metric_names"])
        candidates = req["candidates"]
        if not isinstance(candidates, list):
            raise MultiverseEngineError("candidates must be a list (fail-closed)")

        canonical_candidates = sorted(candidates, key=lambda c: str(c.get("candidate_id", "")))

        canonical_request_for_hash = {
            "schema_id": req["schema_id"],
            "schema_version_hash": req["schema_version_hash"],
            "evaluation_id": req["evaluation_id"],
            "runtime_registry_hash": req["runtime_registry_hash"],
            "metric_names": list(metric_names),
            "candidates": list(canonical_candidates),
        }
        request_hash = sha256_json(canonical_request_for_hash)

        candidate_results: list[tuple[str, Dict[str, float], int]] = []
        for cand in canonical_candidates:
            if not isinstance(cand, dict):
                raise MultiverseEngineError("candidate must be an object (fail-closed)")
            cid = cand.get("candidate_id")
            if not isinstance(cid, str):
                raise MultiverseEngineError("candidate_id must be a string (fail-closed)")
            scores, aggregate_micro = _evaluate_candidate(candidate=cand, metric_names=metric_names)
            candidate_results.append((cid, scores, aggregate_micro))

        candidate_results.sort(key=lambda t: t[0])

        candidates_out: list[Dict[str, Any]] = []
        for cid, scores, aggregate_micro in candidate_results:
            candidates_out.append(
                {
                    "candidate_id": cid,
                    "metric_scores": dict(scores),
                    "aggregate_score": aggregate_micro / 1_000_000.0,
                }
            )

        ranking = [
            cid
            for cid, _scores, _micro in sorted(
                candidate_results,
                key=lambda t: (-t[2], t[0]),
            )
        ]

        coherence_score = 1.0
        result_hash = MultiverseEvaluationResultSchema.compute_result_hash(
            evaluation_id=req["evaluation_id"],
            runtime_registry_hash=req["runtime_registry_hash"],
            request_hash=request_hash,
            context_identity_hash=ctx_hash,
            metric_names=metric_names,
            candidates=candidates_out,
            ranking=ranking,
            coherence_score=coherence_score,
        )

        return MultiverseEvaluationResultSchema.from_dict(
            {
                "schema_id": MultiverseEvaluationResultSchema.SCHEMA_ID,
                "schema_version_hash": MultiverseEvaluationResultSchema.SCHEMA_VERSION_HASH,
                "evaluation_id": req["evaluation_id"],
                "runtime_registry_hash": req["runtime_registry_hash"],
                "request_hash": request_hash,
                "context_identity_hash": ctx_hash,
                "metric_names": metric_names,
                "candidates": candidates_out,
                "ranking": ranking,
                "coherence_score": coherence_score,
                "result_hash": result_hash,
            }
        )

