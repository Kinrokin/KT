"""Fixed-code, local-only Qwen transport in a separate inference process.

The production interpreter never imports model/training libraries. This provider
has no fixture mode, command override, HTTP endpoint, or arbitrary executable.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import selectors
import secrets
import subprocess
import sys
import time
from typing import Any

from schemas.checked_task import canonical_bytes, strict_json
from schemas.trusted_local_path import assert_no_link_or_reparse_path


# Transitively pinned by the admitted canonical provider source closure.
# The inference toolchain stays outside runtime src; no caller chooses its path.
WORKER_SHA256 = "518109695548e8c4a59e03f1db942ca46b1239d187916300ace1d9242314bbcc"


def _verified_worker_path() -> Path:
    worker = Path(__file__).resolve().parents[4] / "tools/operator/local_qwen_worker.py"
    assert_no_link_or_reparse_path(worker, label="fixed inference worker")
    if not worker.is_file() or hashlib.sha256(worker.read_bytes()).hexdigest() != WORKER_SHA256:
        raise RuntimeError("QWEN_WORKER_SOURCE_PIN")
    return worker


def validate_backend(value: Any) -> None:
    expected = {"kind", "base_repo", "base_revision", "base_root", "base_files",
                "chat_template_sha256", "adapter_root", "adapter_files", "seed", "required_versions"}
    if type(value) is not dict or set(value) != expected:
        raise RuntimeError("QWEN_BACKEND_FIELDS")
    if (value["kind"] != "local_qwen_nf4" or value["base_repo"] != "Qwen/Qwen2.5-7B-Instruct"
            or value["base_revision"] != "a09a35458c702b33eeacc393d103063234e8bc28"):
        raise RuntimeError("QWEN_BASE_IDENTITY")
    if type(value["seed"]) is not int or not 0 <= value["seed"] < 2**32:
        raise RuntimeError("QWEN_SEED")
    for label in ("base", "adapter"):
        root, files = value[label + "_root"], value[label + "_files"]
        if label == "adapter" and root is None and files == {}:
            continue
        if type(root) is not str or not Path(root).is_absolute() or type(files) is not dict or not files:
            raise RuntimeError("QWEN_ASSET_ROOT")
        assert_no_link_or_reparse_path(Path(root), label="materialized model assets")
        for rel, digest in files.items():
            path = Path(rel)
            if (not isinstance(rel, str) or path.is_absolute() or ".." in path.parts
                    or "\\" in rel or ":" in rel or not isinstance(digest, str)
                    or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                raise RuntimeError("QWEN_ASSET_PIN")
        if label == "base" and not {"config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors.index.json"} <= set(files):
            raise RuntimeError("QWEN_BASE_PIN_COVERAGE")
        if label == "adapter" and set(files) != {"adapter_config.json", "adapter_model.safetensors"}:
            raise RuntimeError("QWEN_ADAPTER_PIN_COVERAGE")
    if type(value["required_versions"]) is not dict or set(value["required_versions"]) != {"torch", "transformers", "peft", "bitsandbytes", "accelerate", "safetensors", "tokenizers"}:
        raise RuntimeError("QWEN_ENVIRONMENT_PINS")


class LocalQwenBackend:
    def __init__(self, *, contract_path: Path, contract_sha256: str, output_root: Path, backend: dict[str, Any], timeout: int):
        validate_backend(backend)
        worker = _verified_worker_path()
        self.backend, self.timeout = backend, timeout
        self.buffer = bytearray()
        self.process = None
        self.worker_id = secrets.token_hex(16)
        self.stderr = (output_root / f"qwen_{self.worker_id}.stderr.log").open("xb")
        environment = {key: value for key, value in os.environ.items()
                       if key in {"PATH", "HOME", "LD_LIBRARY_PATH", "CUDA_VISIBLE_DEVICES", "CUDA_HOME", "TMPDIR"}}
        environment.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                            "TOKENIZERS_PARALLELISM": "false", "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-I", "-B", str(worker),
                 str(contract_path), contract_sha256], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.stderr, env=environment, close_fds=True)
            self.load_record = self._read()
            if self.load_record.get("kind") != "READY" or self.load_record.get("contract_sha256") != contract_sha256:
                raise RuntimeError("QWEN_LOAD_ADMISSION_FAILED")
            if self.load_record.get("model_identity") != backend or self.load_record.get("real_nf4") is not True:
                raise RuntimeError("QWEN_LOAD_IDENTITY")
            if (backend["adapter_root"] is None) != self.load_record.get("base_adapter_absence_asserted"):
                raise RuntimeError("QWEN_ADAPTER_STATE")
        except BaseException:
            self.close()
            raise

    def _read(self) -> dict[str, Any]:
        assert self.process is not None and self.process.stdout is not None
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                if len(self.buffer) > 2 * 1024 * 1024:
                    raise RuntimeError("QWEN_TRANSPORT_SIZE")
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self.close()
                    raise RuntimeError("QWEN_TRANSPORT_TIMEOUT_OUTCOME_UNKNOWN")
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError("QWEN_TRANSPORT_EOF")
                self.buffer.extend(chunk)
        line, rest = self.buffer.split(b"\n", 1)
        self.buffer = bytearray(rest)
        result = strict_json(bytes(line), max_bytes=2 * 1024 * 1024)
        if type(result) is not dict:
            raise RuntimeError("QWEN_TRANSPORT_OBJECT")
        return result

    def generate(self, *, prompt: str, nonce: str, max_new_tokens: int) -> dict[str, Any]:
        assert self.process is not None and self.process.stdin is not None
        request = {"prompt": prompt, "nonce": nonce, "max_new_tokens": max_new_tokens}
        self.process.stdin.write(canonical_bytes(request) + b"\n")
        self.process.stdin.flush()
        result = self._read()
        if result.get("nonce") != nonce or result.get("prompt_sha256") != hashlib.sha256(prompt.encode()).hexdigest():
            raise RuntimeError("QWEN_ATTEMPT_BINDING")
        return result

    def close(self) -> None:
        process = self.process
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()
        self.stderr.close()
