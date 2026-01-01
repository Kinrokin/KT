from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from schemas.base_schema import SchemaRegistryError, SchemaValidationError
from schemas.runtime_context_schema import (
    RUNTIME_CONTEXT_MAX_CONTEXT_BYTES,
    RUNTIME_CONTEXT_MAX_INPUT_BYTES,
    RUNTIME_CONTEXT_SCHEMA_ID,
    RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    validate_runtime_context,
)
from schemas.schema_registry import validate_schema_binding
from schemas.state_vault_schema import STATE_VAULT_SCHEMA_ID, STATE_VAULT_SCHEMA_VERSION_HASH


MAX_INPUT_BYTES = RUNTIME_CONTEXT_MAX_INPUT_BYTES
MAX_CONTEXT_BYTES = RUNTIME_CONTEXT_MAX_CONTEXT_BYTES
MAX_PREFIX_SCAN_BYTES = 256 * 1024

TRAINING_MARKERS = ("curriculum", "epoch", "dataset", "benchmarks", "trainer", "finetune")

PROVIDER_MODULE_BANS = (
    "openai",
    "groq",
    "anthropic",
    "cerebras",
    "google.generativeai",
    "vertexai",
)

RAW_CONTENT_KEY_MARKERS = ("prompt", "messages", "content", "raw_response", "response", "completion")

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")
APIKEY_LITERAL_RE = re.compile(r"(?i)(api[_-]?key|apikey|token|secret)\s*[:=]\s*[\"'][^\"'\n]{16,}")


@dataclass(frozen=True)
class ConstitutionalCrisisError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class ContractViolationError(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compute_constitution_version_hash() -> str:
    spec = {
        "constitution_id": "kt.prod_cleanroom.v2.constitution.v1",
        "bindings": {
            "runtime_context_schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
            "runtime_context_schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
            "state_vault_schema_id": STATE_VAULT_SCHEMA_ID,
            "state_vault_schema_version_hash": STATE_VAULT_SCHEMA_VERSION_HASH,
        },
        "limits": {
            "max_input_bytes": MAX_INPUT_BYTES,
            "max_context_bytes": MAX_CONTEXT_BYTES,
        },
        "runtime_walls": {
            "training_markers": list(TRAINING_MARKERS),
            "provider_module_bans": list(PROVIDER_MODULE_BANS),
        },
    }
    return _sha256_text(_canonical_json(spec))


CONSTITUTION_VERSION_HASH = compute_constitution_version_hash()


def _src_root() -> Path:
    # .../04_PROD_TEMPLE_V2/src/core/invariants_gate.py -> .../src
    return Path(__file__).resolve().parents[1]


def _safe_read_prefix(path: Path, max_bytes: int) -> str:
    try:
        raw = path.read_bytes()
    except Exception:
        return ""
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _iter_loaded_module_files_under(root: Path) -> Iterable[Tuple[str, Path]]:
    root = root.resolve()
    for name, mod in list(sys.modules.items()):
        file = getattr(mod, "__file__", None)
        if not file:
            continue
        try:
            p = Path(file).resolve()
        except Exception:
            continue
        try:
            p.relative_to(root)
        except Exception:
            continue
        yield name, p


class InvariantsGate:
    @staticmethod
    def assert_runtime_invariants(context: Dict[str, Any]) -> None:
        InvariantsGate._assert_schema_contract(context)
        InvariantsGate._assert_constitution_binding(context)
        InvariantsGate._assert_runtime_purity(context)
        InvariantsGate._assert_no_training_modules_loaded()
        InvariantsGate._assert_no_provider_modules_loaded()
        InvariantsGate._assert_negative_space_loaded_modules()
        InvariantsGate._assert_no_secrets_locators_in_loaded_runtime_modules()

    @staticmethod
    def _assert_schema_contract(context: Dict[str, Any]) -> None:
        if not isinstance(context, dict):
            raise ContractViolationError("Context must be a JSON object (dict)")
        try:
            validate_schema_binding(context["schema_id"], context["schema_version_hash"])
            validate_runtime_context(context)
        except KeyError as exc:
            raise ContractViolationError(f"Missing required context key: {exc.args[0]}")
        except (SchemaRegistryError, SchemaValidationError) as exc:
            raise ContractViolationError(str(exc))

    @staticmethod
    def _assert_constitution_binding(context: Dict[str, Any]) -> None:
        if context["constitution_version_hash"] != CONSTITUTION_VERSION_HASH:
            raise ContractViolationError("constitution_version_hash mismatch (fail-closed)")

    @staticmethod
    def _assert_runtime_purity(context: Dict[str, Any]) -> None:
        # Context-level purity: forbid raw prompt/response fields (belt-and-suspenders).
        def contains_banned_key(obj: Any) -> Optional[str]:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    kl = str(k).lower()
                    if any(marker in kl for marker in RAW_CONTENT_KEY_MARKERS):
                        return str(k)
                    hit = contains_banned_key(v)
                    if hit:
                        return hit
            elif isinstance(obj, list):
                for item in obj:
                    hit = contains_banned_key(item)
                    if hit:
                        return hit
            return None

        hit = contains_banned_key(context)
        if hit:
            raise ConstitutionalCrisisError(f"Raw-content key marker detected in context: {hit!r}")

        # No provider config allowed in context (strict top-level allowlist already enforces this).
        # This explicit check is defensive if the allowlist is ever broadened.
        forbidden_context_keys = {"providers", "provider", "api_key", "token", "secret"}
        if any(k in forbidden_context_keys for k in context.keys()):
            raise ConstitutionalCrisisError("Provider/secrets configuration is forbidden in runtime context")

    @staticmethod
    def _assert_no_training_modules_loaded() -> None:
        # Fail closed if training-signature modules are present in the live import set.
        for name, mod in list(sys.modules.items()):
            if not name:
                continue
            lowered = name.lower()
            if any(marker in lowered for marker in TRAINING_MARKERS):
                raise ConstitutionalCrisisError(f"Training/runtime bleed detected (module loaded): {name}")
            file = getattr(mod, "__file__", None)
            if isinstance(file, str) and any(marker in file.lower() for marker in TRAINING_MARKERS):
                raise ConstitutionalCrisisError(f"Training/runtime bleed detected (module file): {file}")

    @staticmethod
    def _assert_no_provider_modules_loaded() -> None:
        # Provider SDKs must not be imported during dry-run / structural execution.
        for name in list(sys.modules.keys()):
            if not name:
                continue
            for banned in PROVIDER_MODULE_BANS:
                if name == banned or name.startswith(banned + "."):
                    raise ConstitutionalCrisisError(f"Provider SDK loaded at runtime: {name}")

    @staticmethod
    def _assert_negative_space_loaded_modules() -> None:
        # Fail closed if runtime *namespaces* are sourced from non-runtime directories.
        #
        # Rationale: test harnesses legitimately load test modules from /tests/. We only
        # treat it as a Negative Space violation if a runtime namespace (e.g. core/,
        # schemas/) is being resolved from tests/tools/docs (phantom dependency / shadowing).
        src_root = _src_root()
        repo_root = src_root.parents[1]  # .../04_PROD_TEMPLE_V2
        forbidden_segments = ("/tests/", "/tools/", "/docs/")

        internal_roots: Set[str] = set()
        for child in src_root.iterdir():
            if child.is_dir():
                internal_roots.add(child.name)
            elif child.is_file() and child.suffix == ".py":
                internal_roots.add(child.stem)

        for name, path in _iter_loaded_module_files_under(repo_root):
            rel = path.as_posix()
            if not any(seg in rel for seg in forbidden_segments):
                continue
            top = name.split(".", 1)[0] if name else ""
            if top in internal_roots:
                raise ConstitutionalCrisisError(
                    f"Negative Space violation (runtime namespace loaded from non-runtime path): {name} -> {rel}"
                )

    @staticmethod
    def _assert_no_secrets_locators_in_loaded_runtime_modules() -> None:
        # Belt-and-suspenders: check only the currently loaded runtime modules under src/.
        src_root = _src_root()
        for _name, path in _iter_loaded_module_files_under(src_root):
            prefix = _safe_read_prefix(path, MAX_PREFIX_SCAN_BYTES)
            if PRIVATE_KEY_RE.search(prefix):
                raise ConstitutionalCrisisError(f"Secrets locator: private key block detected in {path.name}")
            if APIKEY_LITERAL_RE.search(prefix):
                raise ConstitutionalCrisisError(f"Secrets locator: api_key/token literal pattern detected in {path.name}")
