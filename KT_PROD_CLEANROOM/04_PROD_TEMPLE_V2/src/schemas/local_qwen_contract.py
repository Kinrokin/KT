"""Shared immutable local Qwen asset contract; no model imports."""
from pathlib import Path
from typing import Any
from schemas.trusted_local_path import assert_no_link_or_reparse_path


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

