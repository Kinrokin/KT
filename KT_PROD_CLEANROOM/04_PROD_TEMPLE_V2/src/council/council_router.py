
from __future__ import annotations
import os
from typing import Any, Dict
from council.providers.provider_registry import ProviderRegistry
from council.providers.provider_schemas import ProviderCallReceipt

class CouncilError(RuntimeError):
    pass

_ALLOWED_LIVE_HASHED_PROVIDERS = {"openai"}
_ALLOWED_LIVE_HASHED_REQUEST_TYPES = {"healthcheck", "analysis"}

def _require_live_hashed_env() -> None:
    if os.getenv("KT_PROVIDERS_ENABLED") != "1":
        raise CouncilError("KT_PROVIDERS_ENABLED=1 required (fail-closed).")
    if os.getenv("KT_EXECUTION_LANE") != "LIVE_HASHED":
        raise CouncilError("KT_EXECUTION_LANE=LIVE_HASHED required (fail-closed).")

def execute_council_request(req: Dict[str, Any]) -> Dict[str, Any]:
    mode = str(req.get("mode", "DRY_RUN"))
    request_type = str(req.get("request_type", "")).strip()

    if mode != "LIVE_HASHED":
        raise CouncilError("Only LIVE_HASHED mode is supported in this path (fail-closed).")

    _require_live_hashed_env()

    if request_type not in _ALLOWED_LIVE_HASHED_REQUEST_TYPES:
        raise CouncilError(f"request_type not allowlisted for LIVE_HASHED (fail-closed): {request_type!r}")

    provider_id = str(req.get("provider_id", "")).strip()
    if provider_id not in _ALLOWED_LIVE_HASHED_PROVIDERS:
        raise CouncilError(f"provider_id not allowlisted for LIVE_HASHED (fail-closed): {provider_id!r}")

    model = str(req.get("model", "")).strip()
    if not model:
        raise CouncilError("Missing model (fail-closed).")

    prompt = str(req.get("prompt", "")).strip()
    if not prompt:
        raise CouncilError("Missing prompt (fail-closed).")

    timeout_ms = int(req.get("timeout_ms", 20_000))
    temperature = float(req.get("temperature", 0.0))
    kt_node_id = str(req.get("kt_node_id", os.getenv("KT_NODE_ID", "")))

    registry = ProviderRegistry.build_default()

    receipt: ProviderCallReceipt = registry.invoke_live_hashed(
        provider_id=provider_id,
        model=model,
        prompt=prompt,
        timeout_ms=timeout_ms,
        temperature=temperature,
        kt_node_id=kt_node_id,
        trace_id=str(req.get("trace_id", "")).strip() or None,
    )

    out = {
        "status": "OK",
        "mode": "LIVE_HASHED",
        "provider_id": provider_id,
        "model": receipt.to_dict().get("model"),
        "receipt": receipt.to_dict(),
        "receipt_hash": receipt.to_dict().get("receipt_hash"),
    }
    return out

class CouncilRouter:
    execute = staticmethod(execute_council_request)

