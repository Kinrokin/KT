from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass

from council.providers.provider_schemas import ProviderCallReceipt


class LiveHashedOpenAIProvider:
    provider_id: str = "openai"
    host: str = "api.openai.com"

    def invoke_hashed(self, *, model: str, prompt: str, timeout_ms: int, temperature: float, kt_node_id: str) -> ProviderCallReceipt:
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

        # Enforce host allowlist (fail-closed)
        if self.host != "api.openai.com":
            raise RuntimeError("Host not allowlisted for LIVE_HASHED (fail-closed).")

        ssl_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.host, timeout=timeout_s, context=ssl_ctx)
        raw = b""
        status = None
        headers = {}
        sock = None
        try:
            conn.connect()
            sock = conn.sock
            # capture peer cert (MANDATORY) - fail-closed if unavailable
            try:
                cert_bin = None
                if sock is not None:
                    cert_bin = sock.getpeercert(binary_form=True)
                if not cert_bin:
                    raise RuntimeError("TLS peer certificate unavailable (fail-closed).")
            except Exception:
                raise RuntimeError("TLS peer certificate unavailable (fail-closed).")

            conn.request(
                "POST",
                "/v1/chat/completions",
                body=body,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
            headers = {k.lower(): v for (k, v) in resp.getheaders()}
        finally:
            try:
                conn.close()
            except Exception:
                pass

        t_end_ms = int(time.time() * 1000)
        latency_ms = max(0, t_end_ms - t_start_ms)

        # compute response hash
        response_bytes_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
        response_len = len(raw)

        # parse JSON to extract usage if present
        usage = None
        model_name = model
        try:
            obj = json.loads(raw.decode("utf-8"))
            model_name = obj.get("model") or model_name
            usage = obj.get("usage")
        except Exception:
            raise RuntimeError("Provider response was not valid JSON (fail-closed)")

        request_id = headers.get("x-request-id") or headers.get("request-id")

        # cert_bin guaranteed present by earlier fail-closed check
        tls_cert_sha256 = hashlib.sha256(cert_bin).hexdigest()

        # remote ip hash (best-effort)
        remote_ip_hash = None
        try:
            if sock is not None:
                ip = sock.getpeername()[0]
                remote_ip_hash = "sha256:" + hashlib.sha256(ip.encode("utf-8")).hexdigest()
        except Exception:
            remote_ip_hash = None

        receipt: dict = {
            "schema_id": ProviderCallReceipt.SCHEMA_ID,
            "schema_version_hash": ProviderCallReceipt.SCHEMA_VERSION_HASH,
            "trace_id": f"live_hashed-{int(time.time()*1000)}",
            "provider_id": self.provider_id,
            "lane": "LIVE_HASHED",
            "model": model_name,
            "endpoint": "chat.completions",
            "key_index": key_index,
            "key_count": len(api_keys),
            "timing": {
                "t_start_ms": t_start_ms,
                "t_end_ms": t_end_ms,
                "latency_ms": latency_ms,
            },
            "transport": {
                "host": self.host,
                "http_status": status if status is not None else 0,
                "tls_cert_sha256": tls_cert_sha256,
                "remote_ip_hash": remote_ip_hash,
            },
            "provider_attestation": {
                "request_id": request_id,
                "request_id_hash": ("sha256:" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()) if request_id else None,
            },
            "usage": usage,
            "payload": {
                "response_bytes_sha256": response_bytes_sha256,
                "response_bytes_len": response_len,
            },
            "verdict": {"pass": status == 200, "fail_reason": None if status == 200 else f"http_status={status}"},
        }

        # Validate BASE receipt only (no chain fields)
        ProviderCallReceipt.validate_base(receipt)
        # IMPORTANT: return raw dict, not a ProviderCallReceipt object
        return receipt

    def _discover_keys(self) -> list[str]:
        keys = []
        env = (os.getenv("OPENAI_API_KEYS") or "").strip()
        if env:
            for k in env.split(","):
                k = k.strip()
                if k:
                    keys.append(k)
        else:
            single = (os.getenv("OPENAI_API_KEY") or "").strip()
            if single:
                keys.append(single)
            i = 1
            while True:
                k = (os.getenv(f"OPENAI_API_KEY_{i}") or "").strip()
                if not k:
                    break
                keys.append(k)
                i += 1

        # dedupe
        seen = set()
        out = []
        for k in keys:
            if k and k not in seen:
                seen.add(k)
                out.append(k)
        if not out:
            raise RuntimeError("No OpenAI API keys found (fail-closed).")
        return out

    def _select_key_index(self, *, model: str, prompt: str, keys: list[str], kt_node_id: str) -> int:
        node = kt_node_id or ""
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        combo = f"{model}:{prompt_hash}:{node}"
        digest = hashlib.sha256(combo.encode("utf-8")).digest()
        return int(digest[0]) % len(keys)
