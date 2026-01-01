from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import hashlib
from pathlib import Path


class LiveRunError(RuntimeError):
    pass


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="KT interactive live runner (non-authoritative; no artifacts; no ledgers).",
    )
    p.add_argument(
        "--provider",
        default="openai",
        choices=["openai"],
        help="Live provider to call (default: openai).",
    )
    p.add_argument(
        "--model",
        required=True,
        help="Provider model id (required).",
    )
    p.add_argument(
        "--prompt",
        default="",
        help="Prompt string. If omitted, read from stdin.",
    )
    p.add_argument(
        "--timeout-ms",
        type=int,
        default=20_000,
        help="Hard HTTP timeout in milliseconds (default: 20000).",
    )
    p.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Temperature (default: 0.0).",
    )
    p.add_argument(
        "--allow-growth-artifacts-present",
        action="store_true",
        help="Allow running even if tools/growth/artifacts appears populated (explicit override).",
    )
    p.add_argument(
        "--i-understand-non-authoritative",
        action="store_true",
        help="Required acknowledgement: interactive live mode is non-authoritative and produces no evidence.",
    )
    p.add_argument(
        "--validate-keys",
        action="store_true",
        help="Validate all discovered provider keys and exit (no artifacts).",
    )
    return p.parse_args()


def _repo_root_from_here() -> Path:
    # .../KT_PROD_CLEANROOM/tools/live/live_run.py -> repo root
    return Path(__file__).resolve().parents[4]


def _kt_cleanroom_root_from_here() -> Path:
    # .../KT_PROD_CLEANROOM/tools/live/live_run.py -> .../KT_PROD_CLEANROOM
    return Path(__file__).resolve().parents[3]


def _fail_closed_if_growth_artifacts_present(*, allow_override: bool) -> None:
    cleanroom_root = _kt_cleanroom_root_from_here()
    artifacts = cleanroom_root / "tools" / "growth" / "artifacts"
    if not artifacts.exists():
        return

    # Fail-closed by default if the audited lane appears "active" (populated).
    # This keeps interactive live runs quarantined from the evidence-producing lane.
    allowed_placeholder = {".gitkeep", "ARTIFACT_POLICY.md"}
    populated = False
    for p in artifacts.rglob("*"):
        if not p.is_file():
            continue
        if p.name in allowed_placeholder:
            continue
        populated = True
        break

    if populated and not allow_override:
        raise LiveRunError(
            "Refusing to run interactive live mode while tools/growth/artifacts is populated "
            "(fail-closed). Use --allow-growth-artifacts-present to override explicitly."
        )

    if os.access(artifacts, os.W_OK) and not allow_override:
        raise LiveRunError(
            "Refusing to run interactive live mode while tools/growth/artifacts is writable "
            "(fail-closed). Use --allow-growth-artifacts-present to override explicitly."
        )


def _read_prompt(args: argparse.Namespace) -> str:
    if args.prompt:
        return args.prompt
    data = sys.stdin.read()
    if not data:
        raise LiveRunError("No prompt provided (--prompt or stdin) (fail-closed).")
    return data


def _discover_openai_keys() -> list[str]:
    """Discover OPENAI API keys from environment in priority order.

    Priority:
      - OPENAI_API_KEYS (comma-separated)
      - OPENAI_API_KEY
      - OPENAI_API_KEY_1 .. N

    Strip, de-duplicate (preserve order), and reject empty entries.
    """
    keys = []
    env = os.environ.get("OPENAI_API_KEYS", "").strip()
    if env:
        for k in env.split(","):
            k = k.strip()
            if k:
                keys.append(k)
    else:
        single = os.environ.get("OPENAI_API_KEY", "").strip()
        if single:
            keys.append(single)
        i = 1
        while True:
            k = os.environ.get(f"OPENAI_API_KEY_{i}")
            if not k:
                break
            k = k.strip()
            if k:
                keys.append(k)
            i += 1

    # De-duplicate while preserving order
    seen = {}
    out = []
    for k in keys:
        if k and k not in seen:
            seen[k] = True
            out.append(k)

    if not out:
        return []
    return out


def _openai_chat_completions(
    *,
    api_key: str,
    model: str,
    prompt: str,
    timeout_ms: int,
    temperature: float,
) -> tuple[str, dict]:
    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
    }
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )

    timeout_s = max(0.001, float(timeout_ms) / 1000.0)
    start = time.monotonic()
    try:
        cert_sha256 = None
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            status = getattr(resp, "status", None)
            headers = dict(getattr(resp, "headers", {}))
            # Try to capture TLS peer certificate fingerprint (best-effort).
            try:
                sock = getattr(resp, "fp", None)
                conn_sock = None
                if sock and hasattr(sock, "raw") and hasattr(sock.raw, "connection"):
                    conn_sock = sock.raw.connection.sock
                elif sock and hasattr(sock, "connection"):
                    conn_sock = sock.connection
                if conn_sock and hasattr(conn_sock, "getpeercert"):
                    cert = conn_sock.getpeercert(binary_form=True)
                    if cert:
                        import hashlib

                        cert_sha256 = hashlib.sha256(cert).hexdigest()
            except Exception:
                cert_sha256 = None
    except urllib.error.HTTPError as e:
        raw = e.read()
        raise LiveRunError(f"OpenAI HTTPError status={e.code} (fail-closed).") from e
    except Exception as e:
        raise LiveRunError(
            "OpenAI request failed (network unreachable / DNS / TLS) (fail-closed)."
        ) from e
    finally:
        end = time.monotonic()

    latency_ms = int((end - start) * 1000)

    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise LiveRunError("OpenAI response was not valid JSON (fail-closed).") from e

    # Extract first choice content (best-effort; fail-closed if missing).
    try:
        content = obj["choices"][0]["message"]["content"]
    except Exception as e:
        raise LiveRunError("OpenAI response missing expected chat completion fields (fail-closed).") from e
    if not isinstance(content, str):
        raise LiveRunError("OpenAI content was not a string (fail-closed).")

    # Metadata summary (no secrets, no prompt echo).
    meta = {
        "provider": "openai",
        "endpoint": "chat.completions",
        "http_status": status,
        "latency_ms": latency_ms,
        "model": obj.get("model"),
        "usage": obj.get("usage"),
        "request_id": headers.get("x-request-id") or headers.get("request-id"),
        "tls_cert_sha256": cert_sha256,
    }
    return content, meta


def main() -> int:
    sys.dont_write_bytecode = True

    args = _parse_args()
    if not args.i_understand_non_authoritative:
        raise SystemExit(
            "Missing required acknowledgement: --i-understand-non-authoritative (fail-closed)."
        )

    # Explicit live enable gates (fail-closed).
    if os.environ.get("KT_PROVIDERS_ENABLED") != "1":
        raise SystemExit(
            "KT_PROVIDERS_ENABLED=1 required for interactive live mode (fail-closed)."
        )

    if os.environ.get("KT_EXECUTION_LANE") != "INTERACTIVE_LIVE":
        raise SystemExit(
            "KT_EXECUTION_LANE=INTERACTIVE_LIVE required (fail-closed)."
        )

    _fail_closed_if_growth_artifacts_present(allow_override=bool(args.allow_growth_artifacts_present))

    prompt = _read_prompt(args)

    if args.provider != "openai":
        raise SystemExit("Unsupported provider (fail-closed).")

    keys = _discover_openai_keys()
    if not keys:
        raise SystemExit("No OPENAI API keys found in environment (fail-closed).")

    # If operator requested validation, iterate all keys and report statuses.
    if args.validate_keys:
        all_ok = True
        for idx, k in enumerate(keys):
            try:
                # Minimal, non-destructive request; ignore user prompt.
                _, vmeta = _openai_chat_completions(
                    api_key=k,
                    model=str(args.model),
                    prompt="validate-key",
                    timeout_ms=int(args.timeout_ms),
                    temperature=0.0,
                )
                status = vmeta.get("http_status")
                latency = vmeta.get("latency_ms")
                tls_ok = "✓" if vmeta.get("tls_cert_sha256") else "✗"
                if status == 200:
                    print(f"[key {idx}] OK latency={latency}ms tls={tls_ok}", file=sys.stderr)
                else:
                    all_ok = False
                    print(f"[key {idx}] ERROR http_status={status} tls={tls_ok}", file=sys.stderr)
            except LiveRunError as e:
                all_ok = False
                # Short, non-secret failure message
                msg = str(e)
                print(f"[key {idx}] FAIL {msg}", file=sys.stderr)
        return 0 if all_ok else 1

    if args.timeout_ms < 1 or args.timeout_ms > 120_000:
        raise SystemExit("--timeout-ms out of allowed bounds (1..120000) (fail-closed).")

    if not (0.0 <= args.temperature <= 2.0):
        raise SystemExit("--temperature out of allowed bounds (0.0..2.0) (fail-closed).")

    banner = [
        "WARNING: INTERACTIVE LIVE MODE (NON-AUTHORITATIVE)",
        "NO ARTIFACTS • NO LEDGERS • NO TRAINING",
        f"repo_root={_repo_root_from_here().as_posix()}",
    ]
    print("\n".join(banner), file=sys.stderr)
    print("", file=sys.stderr)

    # Deterministic key selection: model + prompt-hash + KT_NODE_ID
    phash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    node_id = os.environ.get("KT_NODE_ID", "")
    combo = f"{args.model}:{phash}:{node_id}"
    digest = hashlib.sha256(combo.encode("utf-8")).digest()
    key_index = int.from_bytes(digest, "big") % len(keys)
    api_key = keys[key_index]

    text, meta = _openai_chat_completions(
        api_key=api_key,
        model=str(args.model),
        prompt=prompt,
        timeout_ms=int(args.timeout_ms),
        temperature=float(args.temperature),
    )

    # Annotate which key index was used (audit-safe; never reveal secrets).
    meta["key_index"] = key_index
    meta["key_count"] = len(keys)

    # Print raw model output to stdout only (interactive lane).
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")

    # Print a minimal metadata record to stderr (hash-only lane may later persist equivalents).
    print("", file=sys.stderr)
    print("# live_call_meta", file=sys.stderr)
    print(json.dumps(meta, ensure_ascii=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

