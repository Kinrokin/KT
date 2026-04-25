from __future__ import annotations

import os
from time import time
from dataclasses import dataclass
from typing import Dict

from council.providers.dry_run_provider import DryRunProvider
from council.providers.live_provider_openai import OpenAIProvider
from council.providers.provider_interface import ProviderClient
from council.providers.provider_resilience import (
    LANE_LIVE_HASHED,
    LANE_REQUEST,
    backoff_schedule_ms,
    classify_exception,
    policy_for,
    preflight_error_code,
    record_attempt,
    record_failure,
    record_success,
    retryable_exception,
    sleep_backoff,
)
from council.providers.provider_schemas import ProviderRequestSchema, ProviderResponseSchema, make_disabled_response, make_fail_closed_response
from council.providers.provider_schemas import ProviderCallReceipt
from schemas.telemetry_runtime import emit_runtime_telemetry


def _live_receipt_fail_reason(receipt: ProviderCallReceipt) -> str:
    payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
    verdict = payload.get("verdict")
    if isinstance(verdict, dict):
        fail_reason = str(verdict.get("fail_reason", "")).strip()
        if fail_reason:
            return fail_reason
        if verdict.get("pass") is True:
            return ""
    transport = payload.get("transport")
    if isinstance(transport, dict):
        http_status = transport.get("http_status")
        if isinstance(http_status, int) and http_status > 0:
            return f"http_status={http_status}"
    return "provider_verdict_fail_closed"


def _live_receipt_is_success(receipt: ProviderCallReceipt) -> bool:
    payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
    verdict = payload.get("verdict")
    return isinstance(verdict, dict) and verdict.get("pass") is True


@dataclass(frozen=True)
class ProviderRegistry:
    # Deterministic allowlist map provider_id -> implementation
    providers: Dict[str, ProviderClient]

    @staticmethod
    def build_default() -> "ProviderRegistry":
        # Note: live providers are registered but remain disabled by default.
        providers: Dict[str, ProviderClient] = {
            "dry_run": DryRunProvider(),
            # Live-enabled provider implementations (registered but disabled by default).
            "openai": OpenAIProvider(),
            # Inventory-only providers: declared here but default to dry-run behavior until implemented.
            "gemini": DryRunProvider(),
            "cerebras": DryRunProvider(),
            "groq": DryRunProvider(),
            "deepseek": DryRunProvider(),
            "openrouter": DryRunProvider(),
            "huggingface": DryRunProvider(),
            "together": DryRunProvider(),
            "sambacloud": DryRunProvider(),
            "cloudflare": DryRunProvider(),
            "tavily": DryRunProvider(),
        }
        return ProviderRegistry(providers=providers)

    @staticmethod
    def live_enabled() -> bool:
        # Explicit off-switch (default false). Any non-empty "1/true/yes" enables.
        raw = os.environ.get("KT_PROVIDERS_ENABLED", "").strip().lower()
        return raw in {"1", "true", "yes"}

    def resolve(self, *, provider_id: str) -> ProviderClient:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise ValueError("unknown_provider_id (fail-closed)")
        return provider

    def invoke(self, *, request: ProviderRequestSchema) -> ProviderResponseSchema:
        started_ms = int(time() * 1000)
        req = request.to_dict()
        ProviderRequestSchema.validate(req)
        provider_id = str(req["provider_id"])
        request_id = str(req["request_id"])

        if provider_id != "dry_run" and not self.live_enabled():
            response = make_disabled_response(request=request, error_code="PROVIDERS_DISABLED")
            emit_runtime_telemetry(
                surface_id="council.providers.provider_registry.invoke",
                zone="CANONICAL",
                event_type="provider.invoke",
                start_ts=started_ms,
                end_ts=int(time() * 1000),
                result_status=response.to_dict()["status"],
                provider_id=provider_id,
                policy_applied="providers_enabled_gate",
                receipt_ref="provider.response",
                request_id=request_id,
            )
            return response

        try:
            provider = self.resolve(provider_id=provider_id)
        except ValueError:
            response = make_fail_closed_response(request=request, error_code="UNKNOWN_PROVIDER")
            emit_runtime_telemetry(
                surface_id="council.providers.provider_registry.invoke",
                zone="CANONICAL",
                event_type="provider.invoke",
                start_ts=started_ms,
                end_ts=int(time() * 1000),
                result_status=response.to_dict()["status"],
                provider_id=provider_id,
                policy_applied="provider_resolution_gate",
                failure_artifact_ref="UNKNOWN_PROVIDER",
                receipt_ref="provider.response",
                request_id=request_id,
            )
            return response

        if provider_id != "dry_run":
            blocked = preflight_error_code(provider_id=provider_id, lane=LANE_REQUEST)
            if blocked is not None:
                response = make_fail_closed_response(request=request, error_code=blocked)
                emit_runtime_telemetry(
                    surface_id="council.providers.provider_registry.invoke",
                    zone="CANONICAL",
                    event_type="provider.invoke",
                    start_ts=started_ms,
                    end_ts=int(time() * 1000),
                    result_status=response.to_dict()["status"],
                    provider_id=provider_id,
                    policy_applied="provider_resilience_gate",
                    failure_artifact_ref=blocked,
                    receipt_ref="provider.response",
                    request_id=request_id,
                )
                return response

        delays_ms = backoff_schedule_ms(provider_id=provider_id, lane=LANE_REQUEST)
        attempts = max(1, policy_for(provider_id=provider_id, lane=LANE_REQUEST).max_attempts) if provider_id != "dry_run" else 1
        last_error = ""
        for attempt in range(attempts):
            if provider_id != "dry_run":
                record_attempt(provider_id=provider_id, lane=LANE_REQUEST)
            try:
                response = provider.invoke(request=request)
                response_dict = response.to_dict()
                if provider_id != "dry_run" and response_dict.get("status") == "OK":
                    record_success(provider_id=provider_id, lane=LANE_REQUEST)
                emit_runtime_telemetry(
                    surface_id="council.providers.provider_registry.invoke",
                    zone="CANONICAL",
                    event_type="provider.invoke",
                    start_ts=started_ms,
                    end_ts=int(time() * 1000),
                    result_status=str(response_dict.get("status", "")),
                    provider_id=provider_id,
                    policy_applied="provider_resilience_request_lane" if provider_id != "dry_run" else "dry_run_provider_gate",
                    failure_artifact_ref=last_error,
                    receipt_ref="provider.response",
                    request_id=request_id,
                )
                return response
            except Exception as exc:
                last_error = classify_exception(exc)
                if provider_id != "dry_run":
                    record_failure(provider_id=provider_id, lane=LANE_REQUEST)
                if provider_id != "dry_run" and attempt < (attempts - 1) and retryable_exception(exc):
                    sleep_backoff(delays_ms[attempt] if attempt < len(delays_ms) else 0)
                    continue
                response = make_fail_closed_response(request=request, error_code=last_error)
                emit_runtime_telemetry(
                    surface_id="council.providers.provider_registry.invoke",
                    zone="CANONICAL",
                    event_type="provider.invoke",
                    start_ts=started_ms,
                    end_ts=int(time() * 1000),
                    result_status=response.to_dict()["status"],
                    provider_id=provider_id,
                    policy_applied="provider_resilience_request_lane" if provider_id != "dry_run" else "dry_run_provider_gate",
                    failure_artifact_ref=last_error,
                    receipt_ref="provider.response",
                    request_id=request_id,
                )
                return response
        return make_fail_closed_response(request=request, error_code="PROVIDER_ERROR")

    def invoke_live_hashed(
        self,
        *,
        provider_id: str,
        model: str,
        prompt: str,
        timeout_ms: int,
        temperature: float,
        kt_node_id: str,
        trace_id: str | None = None,
        ) -> ProviderCallReceipt:
        started_ms = int(time() * 1000)
        blocked = preflight_error_code(provider_id=provider_id, lane=LANE_LIVE_HASHED)
        if blocked is not None:
            emit_runtime_telemetry(
                surface_id="council.providers.provider_registry.invoke_live_hashed",
                zone="CANONICAL",
                event_type="provider.invoke_live_hashed",
                start_ts=started_ms,
                end_ts=int(time() * 1000),
                result_status="FAIL_CLOSED",
                provider_id=provider_id,
                policy_applied="provider_resilience_live_hashed_gate",
                failure_artifact_ref=blocked,
                receipt_ref="provider.call_receipt",
                trace_id=str(trace_id or ""),
            )
            raise RuntimeError(f"{blocked} (fail-closed)")

        if provider_id == "openai":
            # Lazy import to avoid loading live-only network modules during dry-run/crucible runs
            from council.providers.live_provider_openai_hashed import LiveHashedOpenAIProvider

            prov = LiveHashedOpenAIProvider()
            attempts = max(1, policy_for(provider_id=provider_id, lane=LANE_LIVE_HASHED).max_attempts)
            delays_ms = backoff_schedule_ms(provider_id=provider_id, lane=LANE_LIVE_HASHED)
            last_error = ""
            for attempt in range(attempts):
                record_attempt(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                try:
                    receipt = prov.invoke_hashed(
                        model=model,
                        prompt=prompt,
                        timeout_ms=timeout_ms,
                        temperature=temperature,
                        kt_node_id=kt_node_id,
                        trace_id=str(trace_id or ""),
                    )
                    if _live_receipt_is_success(receipt):
                        record_success(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                        emit_runtime_telemetry(
                            surface_id="council.providers.provider_registry.invoke_live_hashed",
                            zone="CANONICAL",
                            event_type="provider.invoke_live_hashed",
                            start_ts=started_ms,
                            end_ts=int(time() * 1000),
                            result_status="OK",
                            provider_id=provider_id,
                            policy_applied="provider_resilience_live_hashed_lane",
                            receipt_ref="provider.call_receipt",
                            trace_id=str(trace_id or ""),
                        )
                    else:
                        last_error = _live_receipt_fail_reason(receipt)
                        record_failure(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                        emit_runtime_telemetry(
                            surface_id="council.providers.provider_registry.invoke_live_hashed",
                            zone="CANONICAL",
                            event_type="provider.invoke_live_hashed",
                            start_ts=started_ms,
                            end_ts=int(time() * 1000),
                            result_status="FAIL_CLOSED",
                            provider_id=provider_id,
                            policy_applied="provider_resilience_live_hashed_lane",
                            failure_artifact_ref=last_error,
                            receipt_ref="provider.call_receipt",
                            trace_id=str(trace_id or ""),
                        )
                    return receipt
                except Exception as exc:
                    last_error = classify_exception(exc)
                    record_failure(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                    if attempt < (attempts - 1) and retryable_exception(exc):
                        sleep_backoff(delays_ms[attempt] if attempt < len(delays_ms) else 0)
                        continue
                    emit_runtime_telemetry(
                        surface_id="council.providers.provider_registry.invoke_live_hashed",
                        zone="CANONICAL",
                        event_type="provider.invoke_live_hashed",
                        start_ts=started_ms,
                        end_ts=int(time() * 1000),
                        result_status="FAIL_CLOSED",
                        provider_id=provider_id,
                        policy_applied="provider_resilience_live_hashed_lane",
                        failure_artifact_ref=last_error,
                        receipt_ref="provider.call_receipt",
                        trace_id=str(trace_id or ""),
                    )
                    raise RuntimeError(f"{last_error} (fail-closed)")
        if provider_id == "openrouter":
            from council.providers.live_provider_openrouter_hashed import LiveHashedOpenRouterProvider

            prov = LiveHashedOpenRouterProvider()
            attempts = max(1, policy_for(provider_id=provider_id, lane=LANE_LIVE_HASHED).max_attempts)
            delays_ms = backoff_schedule_ms(provider_id=provider_id, lane=LANE_LIVE_HASHED)
            last_error = ""
            for attempt in range(attempts):
                record_attempt(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                try:
                    receipt = prov.invoke_hashed(
                        model=model,
                        prompt=prompt,
                        timeout_ms=timeout_ms,
                        temperature=temperature,
                        kt_node_id=kt_node_id,
                        trace_id=str(trace_id or ""),
                    )
                    if _live_receipt_is_success(receipt):
                        record_success(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                        emit_runtime_telemetry(
                            surface_id="council.providers.provider_registry.invoke_live_hashed",
                            zone="CANONICAL",
                            event_type="provider.invoke_live_hashed",
                            start_ts=started_ms,
                            end_ts=int(time() * 1000),
                            result_status="OK",
                            provider_id=provider_id,
                            policy_applied="provider_resilience_live_hashed_lane",
                            receipt_ref="provider.call_receipt",
                            trace_id=str(trace_id or ""),
                        )
                    else:
                        last_error = _live_receipt_fail_reason(receipt)
                        record_failure(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                        emit_runtime_telemetry(
                            surface_id="council.providers.provider_registry.invoke_live_hashed",
                            zone="CANONICAL",
                            event_type="provider.invoke_live_hashed",
                            start_ts=started_ms,
                            end_ts=int(time() * 1000),
                            result_status="FAIL_CLOSED",
                            provider_id=provider_id,
                            policy_applied="provider_resilience_live_hashed_lane",
                            failure_artifact_ref=last_error,
                            receipt_ref="provider.call_receipt",
                            trace_id=str(trace_id or ""),
                        )
                    return receipt
                except Exception as exc:
                    last_error = classify_exception(exc)
                    record_failure(provider_id=provider_id, lane=LANE_LIVE_HASHED)
                    if attempt < (attempts - 1) and retryable_exception(exc):
                        sleep_backoff(delays_ms[attempt] if attempt < len(delays_ms) else 0)
                        continue
                    emit_runtime_telemetry(
                        surface_id="council.providers.provider_registry.invoke_live_hashed",
                        zone="CANONICAL",
                        event_type="provider.invoke_live_hashed",
                        start_ts=started_ms,
                        end_ts=int(time() * 1000),
                        result_status="FAIL_CLOSED",
                        provider_id=provider_id,
                        policy_applied="provider_resilience_live_hashed_lane",
                        failure_artifact_ref=last_error,
                        receipt_ref="provider.call_receipt",
                        trace_id=str(trace_id or ""),
                    )
                    raise RuntimeError(f"{last_error} (fail-closed)")
        raise RuntimeError(f"LIVE_HASHED provider not implemented (fail-closed): {provider_id!r}")
