from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[1] / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from council.providers.provider_registry import ProviderRegistry  # noqa: E402
from council.providers.provider_schemas import MODE_DRY_RUN, ProviderRequestSchema  # noqa: E402
from schemas.base_schema import SchemaValidationError  # noqa: E402


class NetworkCallAttempted(RuntimeError):
    pass


def _request(*, provider_id: str, mode: str = MODE_DRY_RUN) -> ProviderRequestSchema:
    payload = {
        "schema_id": ProviderRequestSchema.SCHEMA_ID,
        "schema_version_hash": ProviderRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "0" * 64,  # filled after compute
        "provider_id": provider_id,
        "model_id": "model-1",
        "input_hash": "1" * 64,
        "max_output_tokens": 0,
        "timeout_ms": 1000,
        "mode": mode,
    }
    payload["request_id"] = ProviderRequestSchema.compute_request_id(payload)
    return ProviderRequestSchema.from_dict(payload)


class TestProviderAdaptersC022(unittest.TestCase):
    def test_deterministic_request_id(self) -> None:
        a = _request(provider_id="dry_run")
        b = _request(provider_id="dry_run")
        self.assertEqual(a.to_dict()["request_id"], b.to_dict()["request_id"])

    def test_unknown_fields_rejected(self) -> None:
        payload = {
            "schema_id": ProviderRequestSchema.SCHEMA_ID,
            "schema_version_hash": ProviderRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "0" * 64,
            "provider_id": "dry_run",
            "model_id": "model-1",
            "input_hash": "1" * 64,
            "max_output_tokens": 0,
            "timeout_ms": 1000,
            "mode": MODE_DRY_RUN,
            "extra": "x",
        }
        payload["request_id"] = ProviderRequestSchema.compute_request_id(payload)
        with self.assertRaises(SchemaValidationError):
            ProviderRequestSchema.from_dict(payload)

    def test_disabled_mode_no_network(self) -> None:
        reg = ProviderRegistry.build_default()
        req = _request(provider_id="dry_run")

        original_socket = socket.socket
        original_create_connection = socket.create_connection

        def raise_network(*_a, **_k):  # type: ignore[no-untyped-def]
            raise NetworkCallAttempted("Network call attempted (fail-closed)")

        socket.socket = raise_network  # type: ignore[assignment]
        socket.create_connection = raise_network  # type: ignore[assignment]
        try:
            resp = reg.invoke(request=req).to_dict()
            self.assertEqual(resp["status"], "DISABLED")
            self.assertEqual(resp["output_hash"], "0" * 64)
            self.assertEqual(resp["output_bytes_len"], 0)
        finally:
            socket.socket = original_socket  # type: ignore[assignment]
            socket.create_connection = original_create_connection  # type: ignore[assignment]

    def test_unknown_provider_fail_closed(self) -> None:
        reg = ProviderRegistry.build_default()
        req = _request(provider_id="unknown")
        # Unknown provider_id resolves fail-closed through ProviderRegistry.invoke()
        resp = reg.invoke(request=req).to_dict()
        self.assertIn(resp["status"], {"FAIL_CLOSED", "DISABLED"})
        self.assertEqual(resp["output_hash"], "0" * 64)


if __name__ == "__main__":
    raise SystemExit(unittest.main())

