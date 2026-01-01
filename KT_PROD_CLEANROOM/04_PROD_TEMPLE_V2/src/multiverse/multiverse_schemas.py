from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_hash import sha256_json


MULTIVERSE_MAX_DEPTH = 6
MULTIVERSE_MAX_STRING_LEN = 256
MULTIVERSE_MAX_LIST_LEN = 64

MAX_CANDIDATES = 8
MAX_METRICS = 8
MAX_TOKENS_PER_CANDIDATE = 4096
MAX_TOTAL_TOKENS = 8192

_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_METRIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")


@dataclass(frozen=True)
class BaseSchema:
    data: Dict[str, Any]

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "BaseSchema":
        require_dict(payload, name="Schema payload")
        cls.validate(payload)
        return cls(data=dict(payload))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def _require_id(payload: Dict[str, Any], field: str, *, pattern: re.Pattern[str] = _ID_RE) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise SchemaValidationError(f"{field} must be a string")
    if not pattern.match(value):
        raise SchemaValidationError(f"{field} must match {pattern.pattern} (fail-closed)")
    return value


def _require_int_range(payload: Dict[str, Any], field: str, *, lo: int, hi: int) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchemaValidationError(f"{field} must be an integer")
    if value < lo or value > hi:
        raise SchemaValidationError(f"{field} must be in range {lo}..{hi} (fail-closed)")
    return value


def _require_sorted_unique_str_list(payload: Dict[str, Any], field: str, *, max_items: int) -> Tuple[str, ...]:
    value = payload.get(field)
    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
        raise SchemaValidationError(f"{field} must be a non-empty list of strings (fail-closed)")
    if len(value) > max_items:
        raise SchemaValidationError(f"{field} exceeds max length {max_items} (fail-closed)")
    normalized = [x.strip() for x in value]
    if any(not x for x in normalized):
        raise SchemaValidationError(f"{field} contains empty strings (fail-closed)")
    if normalized != sorted(normalized):
        raise SchemaValidationError(f"{field} must be sorted lexicographically (fail-closed)")
    if len(set(normalized)) != len(normalized):
        raise SchemaValidationError(f"{field} contains duplicates (fail-closed)")
    return tuple(normalized)


def _require_unit_float(value: Any, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaValidationError(f"{name} must be a number")
    f = float(value)
    if not math.isfinite(f):
        raise SchemaValidationError(f"{name} must be finite (fail-closed)")
    if f < 0.0 or f > 1.0:
        raise SchemaValidationError(f"{name} must be in [0.0, 1.0] (fail-closed)")
    return f


class MultiverseCandidateSchema(BaseSchema):
    SCHEMA_ID = "multiverse.candidate"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "candidate_id",
        "token_count",
        "metrics",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 8
    MAX_BYTES = 4096

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="MultiverseCandidate")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        _require_id(payload, "candidate_id", pattern=_ID_RE)
        _require_int_range(payload, "token_count", lo=0, hi=MAX_TOKENS_PER_CANDIDATE)

        metrics = require_dict(payload.get("metrics"), name="metrics")
        if len(metrics) == 0 or len(metrics) > MAX_METRICS:
            raise SchemaValidationError("metrics must contain 1..MAX_METRICS entries (fail-closed)")
        for k, v in metrics.items():
            if not isinstance(k, str) or not _METRIC_ID_RE.match(k):
                raise SchemaValidationError(f"metric name must match {_METRIC_ID_RE.pattern} (fail-closed)")
            _ = _require_unit_float(v, name=f"metric:{k}")

        validate_bounded_json_value(
            payload,
            max_depth=MULTIVERSE_MAX_DEPTH,
            max_string_len=MULTIVERSE_MAX_STRING_LEN,
            max_list_len=MULTIVERSE_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class MultiverseEvaluationRequestSchema(BaseSchema):
    SCHEMA_ID = "multiverse.eval_request"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "evaluation_id",
        "runtime_registry_hash",
        "metric_names",
        "candidates",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 10
    MAX_BYTES = 16384

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="MultiverseEvaluationRequest")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        _require_id(payload, "evaluation_id", pattern=_ID_RE)
        validate_hex_64(payload, "runtime_registry_hash")

        metric_names = _require_sorted_unique_str_list(payload, "metric_names", max_items=MAX_METRICS)
        for m in metric_names:
            if not _METRIC_ID_RE.match(m):
                raise SchemaValidationError("metric_names contain invalid metric identifiers (fail-closed)")

        candidates_raw = payload.get("candidates")
        if not isinstance(candidates_raw, list) or not candidates_raw:
            raise SchemaValidationError("candidates must be a non-empty list (fail-closed)")
        if len(candidates_raw) > MAX_CANDIDATES:
            raise SchemaValidationError("candidates exceeds max candidate count (fail-closed)")

        seen_ids: Set[str] = set()
        total_tokens = 0
        for idx, c in enumerate(candidates_raw):
            c_obj = require_dict(c, name=f"candidate[{idx}]")
            MultiverseCandidateSchema.validate(c_obj)
            cid = _require_id(c_obj, "candidate_id", pattern=_ID_RE)
            if cid in seen_ids:
                raise SchemaValidationError("Duplicate candidate_id (fail-closed)")
            seen_ids.add(cid)

            total_tokens += _require_int_range(c_obj, "token_count", lo=0, hi=MAX_TOKENS_PER_CANDIDATE)

            metrics = require_dict(c_obj.get("metrics"), name="metrics")
            if set(metrics.keys()) != set(metric_names):
                raise SchemaValidationError("candidate metrics must match metric_names exactly (fail-closed)")

        if total_tokens > MAX_TOTAL_TOKENS:
            raise SchemaValidationError("Total candidate tokens exceed threshold (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=MULTIVERSE_MAX_DEPTH,
            max_string_len=MULTIVERSE_MAX_STRING_LEN,
            max_list_len=MULTIVERSE_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


class MultiverseEvaluationResultSchema(BaseSchema):
    SCHEMA_ID = "multiverse.eval_result"
    SCHEMA_VERSION = "1.0"
    SCHEMA_VERSION_HASH = ""

    _REQUIRED_FIELDS_ORDER = (
        "schema_id",
        "schema_version_hash",
        "evaluation_id",
        "runtime_registry_hash",
        "request_hash",
        "context_identity_hash",
        "metric_names",
        "candidates",
        "ranking",
        "coherence_score",
        "result_hash",
    )
    _REQUIRED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)
    _ALLOWED_FIELDS: Set[str] = set(_REQUIRED_FIELDS_ORDER)

    MAX_FIELDS = 14
    MAX_BYTES = 32768

    @classmethod
    def compute_result_hash(
        cls,
        *,
        evaluation_id: str,
        runtime_registry_hash: str,
        request_hash: str,
        context_identity_hash: str,
        metric_names: List[str],
        candidates: List[Dict[str, Any]],
        ranking: List[str],
        coherence_score: float,
    ) -> str:
        return sha256_json(
            {
                "schema_id": cls.SCHEMA_ID,
                "schema_version_hash": cls.SCHEMA_VERSION_HASH,
                "evaluation_id": evaluation_id,
                "runtime_registry_hash": runtime_registry_hash,
                "request_hash": request_hash,
                "context_identity_hash": context_identity_hash,
                "metric_names": list(metric_names),
                "candidates": list(candidates),
                "ranking": list(ranking),
                "coherence_score": coherence_score,
            }
        )

    @classmethod
    def validate(cls, payload: Dict[str, Any]) -> None:
        require_dict(payload, name="MultiverseEvaluationResult")
        enforce_max_fields(payload, max_fields=cls.MAX_FIELDS)
        require_keys(payload, required=cls._REQUIRED_FIELDS)
        reject_unknown_keys(payload, allowed=cls._ALLOWED_FIELDS)

        validate_short_string(payload, "schema_id", max_len=64)
        if payload["schema_id"] != cls.SCHEMA_ID:
            raise SchemaValidationError("schema_id mismatch (fail-closed)")
        validate_hex_64(payload, "schema_version_hash")
        if payload["schema_version_hash"] != cls.SCHEMA_VERSION_HASH:
            raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

        _require_id(payload, "evaluation_id", pattern=_ID_RE)
        validate_hex_64(payload, "runtime_registry_hash")
        validate_hex_64(payload, "request_hash")
        validate_hex_64(payload, "context_identity_hash")

        metric_names = list(_require_sorted_unique_str_list(payload, "metric_names", max_items=MAX_METRICS))
        for m in metric_names:
            if not _METRIC_ID_RE.match(m):
                raise SchemaValidationError("metric_names contain invalid metric identifiers (fail-closed)")

        candidates_raw = payload.get("candidates")
        if not isinstance(candidates_raw, list) or not candidates_raw:
            raise SchemaValidationError("candidates must be a non-empty list (fail-closed)")
        if len(candidates_raw) > MAX_CANDIDATES:
            raise SchemaValidationError("candidates exceeds max candidate count (fail-closed)")

        seen_ids: Set[str] = set()
        normalized_candidates: List[Dict[str, Any]] = []
        for idx, c in enumerate(candidates_raw):
            c_obj = require_dict(c, name=f"candidate_result[{idx}]")
            reject_unknown_keys(c_obj, allowed={"candidate_id", "metric_scores", "aggregate_score"})

            cid = _require_id(c_obj, "candidate_id", pattern=_ID_RE)
            if cid in seen_ids:
                raise SchemaValidationError("Duplicate candidate_id in result (fail-closed)")
            seen_ids.add(cid)

            metric_scores = require_dict(c_obj.get("metric_scores"), name="metric_scores")
            if set(metric_scores.keys()) != set(metric_names):
                raise SchemaValidationError("metric_scores must match metric_names exactly (fail-closed)")

            micros: List[int] = []
            for m in metric_names:
                micros.append(int(round(_require_unit_float(metric_scores[m], name=f"metric:{m}") * 1_000_000)))

            expected_micro = int(round(sum(micros) / len(micros)))
            expected_agg = expected_micro / 1_000_000.0
            agg = _require_unit_float(c_obj.get("aggregate_score"), name="aggregate_score")
            if abs(agg - expected_agg) > 1e-6:
                raise SchemaValidationError("aggregate_score mismatch vs metric_scores (fail-closed)")

            normalized_candidates.append(
                {
                    "candidate_id": cid,
                    "metric_scores": {m: (int(round(_require_unit_float(metric_scores[m], name=f'metric:{m}') * 1_000_000)) / 1_000_000.0) for m in metric_names},
                    "aggregate_score": expected_agg,
                }
            )

        ranking_raw = payload.get("ranking")
        if not isinstance(ranking_raw, list) or len(ranking_raw) != len(normalized_candidates):
            raise SchemaValidationError("ranking must be a list matching candidate count (fail-closed)")
        if not all(isinstance(x, str) and _ID_RE.match(x) for x in ranking_raw):
            raise SchemaValidationError("ranking must contain only candidate_id identifiers (fail-closed)")
        if set(ranking_raw) != {c["candidate_id"] for c in normalized_candidates}:
            raise SchemaValidationError("ranking must reference exactly the candidate_id set (fail-closed)")

        coherence_score = _require_unit_float(payload.get("coherence_score"), name="coherence_score")

        expected_ranking = [
            c["candidate_id"]
            for c in sorted(normalized_candidates, key=lambda c: (-c["aggregate_score"], c["candidate_id"]))
        ]
        if ranking_raw != expected_ranking:
            raise SchemaValidationError("ranking mismatch vs candidate scores (fail-closed)")

        validate_hex_64(payload, "result_hash")
        expected_hash = cls.compute_result_hash(
            evaluation_id=payload["evaluation_id"],
            runtime_registry_hash=payload["runtime_registry_hash"],
            request_hash=payload["request_hash"],
            context_identity_hash=payload["context_identity_hash"],
            metric_names=metric_names,
            candidates=normalized_candidates,
            ranking=expected_ranking,
            coherence_score=coherence_score,
        )
        if payload["result_hash"] != expected_hash:
            raise SchemaValidationError("result_hash mismatch (fail-closed)")

        validate_bounded_json_value(
            payload,
            max_depth=MULTIVERSE_MAX_DEPTH,
            max_string_len=MULTIVERSE_MAX_STRING_LEN,
            max_list_len=MULTIVERSE_MAX_LIST_LEN,
        )
        enforce_max_canonical_json_bytes(payload, max_bytes=cls.MAX_BYTES)


def _compute_candidate_schema_version_hash() -> str:
    spec = {
        "schema_id": MultiverseCandidateSchema.SCHEMA_ID,
        "schema_version": MultiverseCandidateSchema.SCHEMA_VERSION,
        "required_fields": list(MultiverseCandidateSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(MultiverseCandidateSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": MultiverseCandidateSchema.MAX_FIELDS,
            "max_bytes": MultiverseCandidateSchema.MAX_BYTES,
            "max_metrics": MAX_METRICS,
            "max_tokens_per_candidate": MAX_TOKENS_PER_CANDIDATE,
        },
    }
    return sha256_json(spec)


def _compute_request_schema_version_hash() -> str:
    spec = {
        "schema_id": MultiverseEvaluationRequestSchema.SCHEMA_ID,
        "schema_version": MultiverseEvaluationRequestSchema.SCHEMA_VERSION,
        "required_fields": list(MultiverseEvaluationRequestSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(MultiverseEvaluationRequestSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": MultiverseEvaluationRequestSchema.MAX_FIELDS,
            "max_bytes": MultiverseEvaluationRequestSchema.MAX_BYTES,
            "max_candidates": MAX_CANDIDATES,
            "max_total_tokens": MAX_TOTAL_TOKENS,
            "max_metrics": MAX_METRICS,
        },
    }
    return sha256_json(spec)


def _compute_result_schema_version_hash() -> str:
    spec = {
        "schema_id": MultiverseEvaluationResultSchema.SCHEMA_ID,
        "schema_version": MultiverseEvaluationResultSchema.SCHEMA_VERSION,
        "required_fields": list(MultiverseEvaluationResultSchema._REQUIRED_FIELDS_ORDER),
        "allowed_fields": sorted(MultiverseEvaluationResultSchema._ALLOWED_FIELDS),
        "limits": {
            "max_fields": MultiverseEvaluationResultSchema.MAX_FIELDS,
            "max_bytes": MultiverseEvaluationResultSchema.MAX_BYTES,
            "max_candidates": MAX_CANDIDATES,
            "max_metrics": MAX_METRICS,
        },
    }
    return sha256_json(spec)


setattr(MultiverseCandidateSchema, "SCHEMA_VERSION_HASH", _compute_candidate_schema_version_hash())
setattr(MultiverseEvaluationRequestSchema, "SCHEMA_VERSION_HASH", _compute_request_schema_version_hash())
setattr(MultiverseEvaluationResultSchema, "SCHEMA_VERSION_HASH", _compute_result_schema_version_hash())

