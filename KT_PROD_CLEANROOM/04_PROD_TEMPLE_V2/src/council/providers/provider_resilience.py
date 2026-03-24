from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Tuple


LANE_REQUEST = "REQUEST"
LANE_LIVE_HASHED = "LIVE_HASHED"


@dataclass(frozen=True)
class ProviderResiliencePolicy:
    max_attempts: int
    initial_backoff_ms: int
    backoff_multiplier: float
    max_backoff_ms: int
    circuit_failure_threshold: int
    circuit_reset_ms: int
    rate_limit_window_ms: int
    rate_limit_max_calls: int
    process_quota_max_calls: int


@dataclass
class ProviderResilienceState:
    consecutive_failures: int = 0
    circuit_open_until_ms: int = 0
    window_started_ms: int = 0
    window_calls: int = 0
    total_calls: int = 0


_DEFAULT_POLICIES: Dict[str, ProviderResiliencePolicy] = {
    LANE_REQUEST: ProviderResiliencePolicy(
        max_attempts=2,
        initial_backoff_ms=25,
        backoff_multiplier=2.0,
        max_backoff_ms=200,
        circuit_failure_threshold=2,
        circuit_reset_ms=2_000,
        rate_limit_window_ms=60_000,
        rate_limit_max_calls=30,
        process_quota_max_calls=250,
    ),
    LANE_LIVE_HASHED: ProviderResiliencePolicy(
        max_attempts=2,
        initial_backoff_ms=50,
        backoff_multiplier=2.0,
        max_backoff_ms=250,
        circuit_failure_threshold=2,
        circuit_reset_ms=3_000,
        rate_limit_window_ms=60_000,
        rate_limit_max_calls=20,
        process_quota_max_calls=120,
    ),
}

_STATE: Dict[Tuple[str, str], ProviderResilienceState] = {}
_POLICY_OVERRIDES: Dict[Tuple[str, str], ProviderResiliencePolicy] = {}


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def _state_key(*, provider_id: str, lane: str) -> Tuple[str, str]:
    return (str(provider_id).strip(), str(lane).strip())


def _state_for(*, provider_id: str, lane: str) -> ProviderResilienceState:
    key = _state_key(provider_id=provider_id, lane=lane)
    state = _STATE.get(key)
    if state is None:
        state = ProviderResilienceState()
        _STATE[key] = state
    return state


def reset_resilience_state_for_tests() -> None:
    _STATE.clear()
    _POLICY_OVERRIDES.clear()


def set_policy_override_for_tests(*, provider_id: str, lane: str, policy: ProviderResiliencePolicy) -> None:
    _POLICY_OVERRIDES[_state_key(provider_id=provider_id, lane=lane)] = policy


def policy_for(*, provider_id: str, lane: str) -> ProviderResiliencePolicy:
    key = _state_key(provider_id=provider_id, lane=lane)
    if key in _POLICY_OVERRIDES:
        return _POLICY_OVERRIDES[key]
    return _DEFAULT_POLICIES[str(lane).strip()]


def _reset_window_if_needed(*, state: ProviderResilienceState, policy: ProviderResiliencePolicy, now_ms: int) -> None:
    if state.window_started_ms == 0 or (now_ms - state.window_started_ms) >= policy.rate_limit_window_ms:
        state.window_started_ms = now_ms
        state.window_calls = 0


def preflight_error_code(*, provider_id: str, lane: str, now_ms: int | None = None) -> str | None:
    current_ms = _now_ms() if now_ms is None else int(now_ms)
    policy = policy_for(provider_id=provider_id, lane=lane)
    state = _state_for(provider_id=provider_id, lane=lane)
    _reset_window_if_needed(state=state, policy=policy, now_ms=current_ms)
    if state.circuit_open_until_ms > current_ms:
        return "CIRCUIT_OPEN"
    if state.window_calls >= policy.rate_limit_max_calls:
        return "RATE_LIMITED"
    if state.total_calls >= policy.process_quota_max_calls:
        return "QUOTA_EXCEEDED"
    return None


def record_attempt(*, provider_id: str, lane: str, now_ms: int | None = None) -> None:
    current_ms = _now_ms() if now_ms is None else int(now_ms)
    policy = policy_for(provider_id=provider_id, lane=lane)
    state = _state_for(provider_id=provider_id, lane=lane)
    _reset_window_if_needed(state=state, policy=policy, now_ms=current_ms)
    state.window_calls += 1
    state.total_calls += 1


def record_success(*, provider_id: str, lane: str) -> None:
    state = _state_for(provider_id=provider_id, lane=lane)
    state.consecutive_failures = 0
    state.circuit_open_until_ms = 0


def record_failure(*, provider_id: str, lane: str, now_ms: int | None = None) -> None:
    current_ms = _now_ms() if now_ms is None else int(now_ms)
    policy = policy_for(provider_id=provider_id, lane=lane)
    state = _state_for(provider_id=provider_id, lane=lane)
    state.consecutive_failures += 1
    if state.consecutive_failures >= policy.circuit_failure_threshold:
        state.circuit_open_until_ms = current_ms + policy.circuit_reset_ms


def retryable_exception(exc: Exception) -> bool:
    return isinstance(exc, (TimeoutError, ConnectionError, OSError))


def classify_exception(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, ConnectionError):
        return "CONNECTION_ERROR"
    if isinstance(exc, OSError):
        return "NETWORK_ERROR"
    return "PROVIDER_ERROR"


def backoff_schedule_ms(*, provider_id: str, lane: str) -> list[int]:
    policy = policy_for(provider_id=provider_id, lane=lane)
    delays: list[int] = []
    delay = int(policy.initial_backoff_ms)
    for _ in range(max(0, policy.max_attempts - 1)):
        delays.append(min(delay, policy.max_backoff_ms))
        delay = int(delay * policy.backoff_multiplier)
    return delays


def sleep_backoff(delay_ms: int) -> None:
    time.sleep(max(0.0, float(delay_ms) / 1000.0))
