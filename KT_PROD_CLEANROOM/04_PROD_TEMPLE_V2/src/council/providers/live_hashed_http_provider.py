from __future__ import annotations

import hashlib
import http.client
import json
import os
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from council.providers.provider_schemas import ProviderCallReceipt
from council.providers.semantic_response import typed_message_from_provider_response
from schemas.semantic_vertical_schemas import MAX_PROVIDER_RESPONSE_BYTES, TypedProviderMessageSchema


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LiveHashedHTTPChatProvider:
    provider_id: str
    host: str
    path: str
    endpoint: str
    key_env_prefix: str
    referer: str = ""
    title: str = ""

    def invoke_hashed(
        self,
        *,
        model: str,
        prompt: str,
        timeout_ms: int,
        temperature: float,
        kt_node_id: str,
        trace_id: str | None = None,
    ) -> ProviderCallReceipt:
        api_keys = self._discover_keys()
        key_index = self._select_key_index(model=model, prompt=prompt, keys=api_keys, kt_node_id=kt_node_id)
        api_key = api_keys[key_index]

        t_start_ms = int(time.time() * 1000)
        timeout_s = max(0.001, float(timeout_ms) / 1000.0)
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if self.referer:
            headers["HTTP-Referer"] = self.referer
        if self.title:
            headers["X-Title"] = self.title

        ssl_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.host, timeout=timeout_s, context=ssl_ctx)
        raw = b""
        status = 0
        response_headers: dict[str, str] = {}
        cert_bin = b""
        remote_ip_hash = None
        try:
            conn.connect()
            sock = conn.sock
            try:
                cert_bin = sock.getpeercert(binary_form=True) if sock is not None else b""
                if not cert_bin:
                    raise RuntimeError("TLS peer certificate unavailable (fail-closed).")
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("TLS peer certificate unavailable (fail-closed).") from exc
            try:
                if sock is not None:
                    remote_ip = sock.getpeername()[0]
                    remote_ip_hash = "sha256:" + _sha256_text(str(remote_ip))
            except Exception:
                remote_ip_hash = None

            conn.request("POST", self.path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = int(resp.status or 0)
            response_headers = {str(k).lower(): str(v) for (k, v) in resp.getheaders()}
        finally:
            try:
                conn.close()
            except Exception:
                pass

        t_end_ms = int(time.time() * 1000)
        latency_ms = max(0, t_end_ms - t_start_ms)
        response_bytes_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
        response_len = len(raw)

        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("Provider response was not valid JSON (fail-closed)") from exc

        request_id = response_headers.get("x-request-id") or response_headers.get("request-id")
        model_name = str(obj.get("model") or model)
        usage = obj.get("usage")

        receipt = {
            "schema_id": ProviderCallReceipt.SCHEMA_ID,
            "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
            "trace_id": str(trace_id).strip() or f"{self.provider_id}-live-hashed-{t_start_ms}",
            "provider_id": self.provider_id,
            "lane": "LIVE_HASHED",
            "model": model_name,
            "endpoint": self.endpoint,
            "key_index": key_index,
            "key_count": len(api_keys),
            "timing": {
                "t_start_ms": t_start_ms,
                "t_end_ms": t_end_ms,
                "latency_ms": latency_ms,
            },
            "transport": {
                "host": self.host,
                "http_status": status,
                "tls_cert_sha256": hashlib.sha256(cert_bin).hexdigest(),
                "remote_ip_hash": remote_ip_hash,
            },
            "provider_attestation": {
                "request_id": request_id,
                "request_id_hash": ("sha256:" + _sha256_text(request_id)) if request_id else None,
            },
            "usage": usage,
            "payload": {
                "response_bytes_sha256": response_bytes_sha256,
                "response_bytes_len": response_len,
            },
            "verdict": {
                "pass": status == 200,
                "fail_reason": None if status == 200 else f"http_status={status}",
            },
            "receipt_id": "",
            "prev_receipt_hash": "GENESIS",
            "receipt_hash": "",
        }
        receipt_hash = self._compute_receipt_hash(receipt)
        receipt["receipt_id"] = receipt_hash
        receipt["receipt_hash"] = receipt_hash
        return ProviderCallReceipt.from_dict(receipt)

    def invoke_semantic(
        self,
        *,
        model: str,
        prompt: str,
        max_output_tokens: int,
        timeout_ms: int,
        temperature: float,
        kt_node_id: str,
        trace_id: str,
        offline_fixture_path: Path | None = None,
    ) -> Tuple[ProviderCallReceipt, TypedProviderMessageSchema, bytes]:
        if not trace_id:
            raise RuntimeError("semantic trace_id required (fail-closed)")
        if not 1 <= int(max_output_tokens) <= 512:
            raise RuntimeError("semantic max_output_tokens out of bounds (fail-closed)")
        if offline_fixture_path is None:
            raise RuntimeError("LIVE_SEMANTIC_NOT_AUTHORIZED_BY_OFFLINE_MICROFIX (fail-closed)")

        t_start_ms = int(time.time() * 1000)
        status = 0
        response_headers: dict[str, str] = {}
        cert_bin = b""
        remote_ip_hash = None
        key_index = 0
        key_count = 1
        transport_host = self.host

        if offline_fixture_path is not None:
            if not offline_fixture_path.is_absolute() or offline_fixture_path.is_symlink():
                raise RuntimeError("offline fixture path must be absolute and non-symlink (fail-closed)")
            try:
                if offline_fixture_path.stat().st_size > MAX_PROVIDER_RESPONSE_BYTES:
                    raise RuntimeError("offline provider response exceeds byte ceiling (fail-closed)")
                with offline_fixture_path.open("rb") as handle:
                    raw = handle.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
            except RuntimeError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("unable to read offline provider response (fail-closed)") from exc
            if not raw or len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise RuntimeError("offline provider response missing or oversized (fail-closed)")
            status = 200
            cert_bin = b"offline-proof-fixture"
            transport_host = "offline.fixture"
        else:
            api_keys = self._discover_keys()
            key_index = self._select_key_index(model=model, prompt=prompt, keys=api_keys, kt_node_id=kt_node_id)
            key_count = len(api_keys)
            api_key = api_keys[key_index]
            timeout_s = max(0.001, float(timeout_ms) / 1000.0)
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": int(max_output_tokens),
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "kt_semantic_meaning_v1",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["schema_id", "decision", "reason_code", "subject_hash", "nonce"],
                            "properties": {
                                "schema_id": {"type": "string", "const": "kt.semantic_meaning.v1"},
                                "decision": {"type": "string", "enum": ["PASS", "FAIL"]},
                                "reason_code": {"type": "string", "enum": ["ACCEPT", "REJECT"]},
                                "subject_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                "nonce": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                            },
                        },
                    },
                },
            }
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            if self.referer:
                headers["HTTP-Referer"] = self.referer
            if self.title:
                headers["X-Title"] = self.title
            ssl_ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(self.host, timeout=timeout_s, context=ssl_ctx)
            try:
                conn.connect()
                sock = conn.sock
                cert_bin = sock.getpeercert(binary_form=True) if sock is not None else b""
                if not cert_bin:
                    raise RuntimeError("TLS peer certificate unavailable (fail-closed).")
                try:
                    if sock is not None:
                        remote_ip_hash = "sha256:" + _sha256_text(str(sock.getpeername()[0]))
                except Exception:
                    remote_ip_hash = None
                conn.request("POST", self.path, body=body, headers=headers)
                response = conn.getresponse()
                raw = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                status = int(response.status or 0)
                response_headers = {str(k).lower(): str(v) for (k, v) in response.getheaders()}
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise RuntimeError("provider response exceeds byte ceiling (fail-closed)")

        t_end_ms = int(time.time() * 1000)
        if status != 200:
            raise RuntimeError(f"semantic provider http_status={status} (fail-closed)")
        typed = typed_message_from_provider_response(
            raw=raw,
            expected_model=model,
            provider_id=self.provider_id,
            request_id=trace_id,
        )
        typed_obj = typed.to_dict()
        request_id_header = response_headers.get("x-request-id") or response_headers.get("request-id")
        receipt = {
            "schema_id": ProviderCallReceipt.SCHEMA_ID,
            "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
            "trace_id": trace_id,
            "provider_id": self.provider_id,
            "lane": "OFFLINE_PROOF" if offline_fixture_path is not None else "LIVE_SEMANTIC",
            "model": model,
            "endpoint": self.endpoint,
            "key_index": key_index,
            "key_count": key_count,
            "timing": {
                "t_start_ms": t_start_ms,
                "t_end_ms": t_end_ms,
                "latency_ms": max(0, t_end_ms - t_start_ms),
            },
            "transport": {
                "host": transport_host,
                "http_status": status,
                "tls_cert_sha256": hashlib.sha256(cert_bin).hexdigest(),
                "remote_ip_hash": remote_ip_hash,
            },
            "provider_attestation": {
                "request_id": request_id_header,
                "request_id_hash": ("sha256:" + _sha256_text(request_id_header)) if request_id_header else None,
                "response_id_hash": "sha256:" + typed_obj["provider_response_id_hash"],
            },
            "usage": typed_obj["usage"],
            "payload": {
                "response_bytes_sha256": "sha256:" + typed_obj["raw_response_hash"],
                "response_bytes_len": typed_obj["raw_response_bytes"],
                "prompt_sha256": "sha256:" + _sha256_text(prompt),
                "content_sha256": "sha256:" + typed_obj["content_hash"],
                "message_hash": typed_obj["message_hash"],
            },
            "verdict": {"pass": True, "fail_reason": None},
            "receipt_id": "",
            "prev_receipt_hash": "GENESIS",
            "receipt_hash": "",
        }
        receipt_hash = self._compute_receipt_hash(receipt)
        receipt["receipt_id"] = receipt_hash
        receipt["receipt_hash"] = receipt_hash
        return ProviderCallReceipt.from_dict(receipt), typed, raw

    def _discover_keys(self) -> list[str]:
        multi_name = f"{self.key_env_prefix}_API_KEYS"
        single_name = f"{self.key_env_prefix}_API_KEY"
        keys: list[str] = []

        raw_multi = (os.getenv(multi_name) or "").strip()
        if raw_multi:
            for value in raw_multi.split(","):
                candidate = value.strip()
                if candidate:
                    keys.append(candidate)
        else:
            single = (os.getenv(single_name) or "").strip()
            if single:
                keys.append(single)
            idx = 1
            while True:
                candidate = (os.getenv(f"{single_name}_{idx}") or "").strip()
                if not candidate:
                    break
                keys.append(candidate)
                idx += 1

        deduped: list[str] = []
        seen = set()
        for key in keys:
            if key and key not in seen:
                deduped.append(key)
                seen.add(key)
        if not deduped:
            raise RuntimeError(f"No {single_name} keys found (fail-closed).")
        return deduped

    def _select_key_index(self, *, model: str, prompt: str, keys: list[str], kt_node_id: str) -> int:
        combo = f"{self.provider_id}:{model}:{_sha256_text(prompt)}:{kt_node_id or ''}"
        digest = hashlib.sha256(combo.encode("utf-8")).digest()
        return int(digest[0]) % len(keys)

    def _compute_receipt_hash(self, receipt: dict) -> str:
        payload = {k: v for k, v in receipt.items() if k not in {"receipt_id", "receipt_hash"}}
        return _sha256_text(_canonical_json(payload))
