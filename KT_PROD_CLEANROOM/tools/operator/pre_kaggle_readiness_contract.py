"""Static pre-Kaggle control-plane checks.

This module deliberately has no model, network, notebook, training, or
provider dependency. It validates inputs that a separately authorized
execution lane would need, and it can preserve supplied synthetic rows after a
simulated failure. It never selects a benchmark or grants execution authority.
"""

from __future__ import annotations

import os
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_ID = "kt.pre_kaggle_runtime_contract.v1"
PASS_STATUS = "PRE_KAGGLE_STATIC_PREFLIGHT_PASS__EXECUTION_NOT_AUTHORIZED"
PARTIAL_STATUS = "PARTIAL_MEASURED_OUTPUTS"
ASSESSMENT_ONLY = "ASSESSMENT_ONLY"
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
REQUIRED_OUTPUT_SUBTREES = (
    "ephemeral_heavy",
    "model_cache",
    "adapter_cache",
    "run_scratch",
    "durable_heavy",
    "assessment_return",
)
EXECUTION_FLAGS = (
    "model_inference_requested",
    "model_loading_requested",
    "model_download_requested",
    "provider_model_calls_requested",
    "notebook_execution_requested",
    "network_access_requested",
    "training_requested",
    "kaggle_execution_requested",
    "paid_compute_requested",
    "hf_upload_requested",
    "final_benchmark_selection_requested",
)


class PreflightViolation(ValueError):
    """A fail-closed static readiness violation with a stable predicate code."""


def _fail(code: str, detail: str) -> None:
    raise PreflightViolation(f"{code}: {detail}")


def _mapping(value: object, code: str, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(code, f"{label} must be an object")
    return value


def _text(value: object, code: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(code, f"{label} must be a non-empty string")
    return value


def _sha256(value: object, code: str, label: str) -> str:
    text = _text(value, code, label)
    if HEX_64.fullmatch(text) is None:
        _fail(code, f"{label} must be a lowercase SHA256")
    return text


def _head(value: object, code: str, label: str) -> str:
    text = _text(value, code, label)
    if HEX_40.fullmatch(text) is None:
        _fail(code, f"{label} must be a lowercase git head")
    return text


def _single_component(value: object, code: str, label: str) -> str:
    text = _text(value, code, label)
    candidate = Path(text)
    if (candidate.name != text or text in {".", ".."} or "/" in text
            or "\\" in text or candidate.is_absolute()):
        _fail(code, f"{label} must be one relative path component")
    return text


def _relative_path(value: object, code: str, label: str) -> Path:
    text = _text(value, code, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or "\\" in text or not path.parts:
        _fail(code, f"{label} must be a safe relative path")
    return path


def _regular_file(path: Path, code: str) -> None:
    if path.is_symlink() or not path.is_file():
        _fail(code, str(path))


def _json_without_duplicate_keys(path: Path, code: str) -> Mapping[str, Any]:
    def no_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(code, f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    _regular_file(path, code)
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(code, f"invalid JSON in {path}: {exc}")
    return _mapping(value, code, str(path))


def sha256_file(path: Path) -> str:
    """Return the exact digest of a regular file without interpreting its content."""
    _regular_file(path, "FILE_NOT_REGULAR")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _contains_symlink_component(path: Path) -> bool:
    """Return true when the unresolved path or any ancestor is a symlink."""
    probe = Path(path)
    while True:
        if probe.is_symlink():
            return True
        parent = probe.parent
        if parent == probe:
            return False
        probe = parent


def _is_within(candidate: Path, root: Path) -> bool:
    if _contains_symlink_component(candidate) or _contains_symlink_component(root):
        return False
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _reject_symlink_path(path: Path, code: str) -> None:
    if _contains_symlink_component(path):
        _fail(code, str(path))


def validate_identity_planes(planes: Mapping[str, Any]) -> dict[str, Any]:
    """Require complete, non-interchangeable source/artifact/environment/measurement IDs."""
    plane_specs = {
        "source": ("repo_head", "source_tree_sha256"),
        "artifact": ("adapter_manifest_sha256", "adapter_identity"),
        "environment": ("environment_lock_sha256", "toolchain_id"),
        "measurement": ("measurement_manifest_sha256", "benchmark_selection_status"),
    }
    all_fields = {field for fields in plane_specs.values() for field in fields}
    normalized: dict[str, dict[str, str]] = {}
    for name, fields in plane_specs.items():
        plane = _mapping(planes.get(name), "IDENTITY_PLANE_MISSING", name)
        foreign_fields = (set(plane) & all_fields) - set(fields)
        if foreign_fields:
            _fail(
                "IDENTITY_CROSS_PLANE_SUBSTITUTION",
                f"{name} carries {sorted(foreign_fields)!r} owned by another plane",
            )
        for field in fields:
            if field not in plane:
                _fail("IDENTITY_FIELD_MISSING", f"{name}.{field}")
        normalized[name] = {
            field: _text(plane[field], "IDENTITY_FIELD_INVALID", f"{name}.{field}")
            for field in fields
        }

    normalized["source"]["repo_head"] = _head(
        normalized["source"]["repo_head"], "IDENTITY_FIELD_INVALID", "source.repo_head"
    )
    for name, field in (
        ("source", "source_tree_sha256"),
        ("artifact", "adapter_manifest_sha256"),
        ("environment", "environment_lock_sha256"),
        ("measurement", "measurement_manifest_sha256"),
    ):
        normalized[name][field] = _sha256(
            normalized[name][field], "IDENTITY_FIELD_INVALID", f"{name}.{field}"
        )
    if normalized["measurement"]["benchmark_selection_status"] != "UNSELECTED_FOR_EXPERIMENT":
        _fail(
            "FINAL_BENCHMARK_SELECTION_OUT_OF_SCOPE",
            "measurement.benchmark_selection_status must remain UNSELECTED_FOR_EXPERIMENT",
        )
    return normalized


def validate_packet_selection(
    packet_root: Path,
    selection: Mapping[str, Any],
    actual_source_head: str,
) -> dict[str, str]:
    """Bind a packet to one file, digest, manifest record, and current source head."""
    _reject_symlink_path(packet_root, "PACKET_ROOT_SYMLINK_FORBIDDEN")
    if not packet_root.is_dir():
        _fail("PACKET_ROOT_INVALID", str(packet_root))
    expected_name = _single_component(
        selection.get("packet_name"), "PACKET_NAME_INVALID", "packet_name"
    )
    expected_sha = _sha256(
        selection.get("packet_sha256"), "PACKET_SHA256_INVALID", "packet_sha256"
    )
    expected_head = _head(
        selection.get("source_head"), "PACKET_SOURCE_HEAD_INVALID", "source_head"
    )
    current_head = _head(actual_source_head, "SOURCE_HEAD_INVALID", "actual_source_head")
    manifest = _mapping(selection.get("manifest"), "PACKET_MANIFEST_INVALID", "manifest")
    intent = selection.get("identity_mode")
    if intent not in {"CURRENT_EXPERIMENT", "HISTORICAL_REPRODUCTION"}:
        _fail("PACKET_IDENTITY_MODE_INVALID", "identity_mode")
    requested_head = _head(
        selection.get("requested_head"), "REQUESTED_HEAD_INVALID", "requested_head"
    )
    subject_head = _head(
        selection.get("subject_head"), "SUBJECT_HEAD_INVALID", "subject_head"
    )
    manifest_current_head = _head(
        selection.get("current_git_head"), "CURRENT_GIT_HEAD_INVALID", "current_git_head"
    )
    if selection.get("requested_head_remote_reachable") is not True:
        _fail("REQUESTED_HEAD_NOT_REMOTE_REACHABLE", requested_head)
    if selection.get("packet_hash_scope") != "EXTERNAL_MANIFEST":
        _fail("SELF_REFERENTIAL_PACKET_HASH_FORBIDDEN", "packet_hash_scope")
    if manifest.get("self_referential_packet_hash") is not False:
        _fail("SELF_REFERENTIAL_PACKET_HASH_FORBIDDEN", "manifest.self_referential_packet_hash")
    if expected_head != current_head:
        _fail("SOURCE_HEAD_MISMATCH", f"packet {expected_head}, source {current_head}")
    if intent == "CURRENT_EXPERIMENT":
        if {expected_head, requested_head, subject_head, manifest_current_head} != {current_head}:
            _fail("CURRENT_HEAD_BINDING_MISMATCH", "source/requested/subject/current heads must match")
    else:
        if subject_head == current_head:
            _fail("HISTORICAL_REPRODUCTION_IDENTITY_INVALID", "historical subject head must differ from current head")
        _sha256(
            selection.get("historical_reproduction_contract_sha256"),
            "HISTORICAL_REPRODUCTION_CONTRACT_INVALID",
            "historical_reproduction_contract_sha256",
        )

    entries = list(packet_root.iterdir())
    linked = sorted(path.name for path in entries if path.is_symlink())
    if linked:
        _fail("PACKET_SYMLINK_ENTRY_FORBIDDEN", ", ".join(linked))
    unexpected = sorted(path.name for path in entries if not path.is_file() or path.suffix != ".zip")
    if unexpected:
        _fail("PACKET_DISCOVERY_UNEXPECTED_ENTRY", ", ".join(unexpected))
    candidates = sorted(path for path in entries if path.is_file() and path.suffix == ".zip")
    if len(candidates) == 0:
        _fail("PACKET_DISCOVERY_NO_CANDIDATE", str(packet_root))
    if len(candidates) != 1:
        _fail("PACKET_DISCOVERY_MULTIPLE_CANDIDATES", ", ".join(path.name for path in candidates))
    candidate = candidates[0]
    if candidate.name != expected_name:
        _fail("PACKET_NAME_MISMATCH", f"expected {expected_name}, found {candidate.name}")
    actual_sha = sha256_file(candidate)
    if actual_sha != expected_sha:
        _fail("PACKET_SHA256_MISMATCH", f"{candidate.name} has {actual_sha}")
    for key, expected in (
        ("packet_name", expected_name),
        ("packet_sha256", expected_sha),
        ("source_head", expected_head),
    ):
        if manifest.get(key) != expected:
            _fail("PACKET_MANIFEST_MISMATCH", f"manifest.{key}")
    return {
        "packet_name": candidate.name,
        "packet_sha256": actual_sha,
        "source_head": current_head,
        "identity_mode": intent,
        "subject_head": subject_head,
    }


def validate_input_inventory(inventory: Mapping[str, Any]) -> dict[str, Any]:
    """Require one exact nested input inventory instead of a permissive glob."""
    stage_root = Path(_text(inventory.get("stage_root"), "INPUT_STAGE_ROOT_INVALID", "stage_root"))
    _reject_symlink_path(stage_root, "INPUT_STAGE_ROOT_SYMLINK_FORBIDDEN")
    if not stage_root.is_dir():
        _fail("INPUT_STAGE_ROOT_INVALID", str(stage_root))
    expected_name = _single_component(
        inventory.get("expected_stage_root_name"), "INPUT_STAGE_ROOT_NAME_INVALID", "expected_stage_root_name"
    )
    if stage_root.name != expected_name:
        _fail("INPUT_STAGE_ROOT_MISMATCH", f"expected {expected_name}, found {stage_root.name}")
    rows = inventory.get("required_inputs")
    if not isinstance(rows, list) or not rows:
        _fail("INPUT_INVENTORY_INVALID", "required_inputs")
    expected_paths: set[str] = set()
    logical_names: set[str] = set()
    basenames: set[str] = set()
    bindings: list[dict[str, str]] = []
    for number, raw in enumerate(rows, start=1):
        row = _mapping(raw, "INPUT_INVENTORY_INVALID", f"required_inputs[{number}]")
        logical_name = _text(row.get("logical_name"), "INPUT_LOGICAL_NAME_INVALID", "logical_name")
        if logical_name in logical_names:
            _fail("INPUT_LOGICAL_NAME_DUPLICATE", logical_name)
        logical_names.add(logical_name)
        relative = _relative_path(row.get("relative_path"), "INPUT_PATH_INVALID", "relative_path")
        relative_text = relative.as_posix()
        if relative.name in basenames:
            _fail("INPUT_FILENAME_AMBIGUITY", relative.name)
        basenames.add(relative.name)
        if relative_text in expected_paths:
            _fail("INPUT_PATH_DUPLICATE", relative_text)
        expected_paths.add(relative_text)
        expected_sha = _sha256(row.get("sha256"), "INPUT_SHA256_INVALID", "sha256")
        path = stage_root / relative
        stage_resolved = stage_root.resolve()
        resolved_path = path.resolve(strict=False)
        if not _is_within(resolved_path, stage_resolved):
            _fail("INPUT_PATH_ESCAPES_STAGE_ROOT", relative_text)
        _regular_file(path, "INPUT_REQUIRED_ARTIFACT_MISSING")
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha:
            _fail("INPUT_SHA256_MISMATCH", relative_text)
        bindings.append({"logical_name": logical_name, "relative_path": relative_text, "sha256": actual_sha})
    discovered = list(stage_root.rglob("*"))
    linked = sorted(path.relative_to(stage_root).as_posix() for path in discovered if path.is_symlink())
    if linked:
        _fail("INPUT_INVENTORY_SYMLINK_FORBIDDEN", ", ".join(linked))
    actual_paths = {
        path.relative_to(stage_root).as_posix()
        for path in discovered
        if path.is_file()
    }
    unexpected = sorted(actual_paths - expected_paths)
    if unexpected:
        _fail("INPUT_INVENTORY_UNEXPECTED_FILE", ", ".join(unexpected))
    return {"stage_root": str(stage_root), "inputs": bindings, "exact_inventory": True}


def validate_adapter_identity(adapter_root: Path, expected: Mapping[str, Any]) -> dict[str, Any]:
    """Resolve a future adapter only when all supplied identity fields agree exactly."""
    _reject_symlink_path(adapter_root, "ADAPTER_ROOT_SYMLINK_FORBIDDEN")
    if not adapter_root.is_dir():
        _fail("ADAPTER_ROOT_INVALID", str(adapter_root))
    directory = _single_component(
        expected.get("adapter_directory"), "ADAPTER_DIRECTORY_INVALID", "adapter_directory"
    )
    config_name = _single_component(
        expected.get("adapter_config_filename"), "ADAPTER_CONFIG_NAME_INVALID", "adapter_config_filename"
    )
    model_name = _single_component(
        expected.get("adapter_model_filename"), "ADAPTER_MODEL_NAME_INVALID", "adapter_model_filename"
    )
    if config_name == model_name:
        _fail("ADAPTER_CONFIG_MODEL_NAME_COLLISION", config_name)
    adapter_dir = adapter_root / directory
    if adapter_dir.is_symlink() or not adapter_dir.is_dir():
        _fail("ADAPTER_DIRECTORY_MISSING", str(adapter_dir))
    config_path = adapter_dir / config_name
    model_path = adapter_dir / model_name
    _regular_file(config_path, "ADAPTER_CONFIG_MISSING")
    _regular_file(model_path, "ADAPTER_MODEL_MISSING")

    expected_config_sha = _sha256(
        expected.get("adapter_config_sha256"), "ADAPTER_CONFIG_SHA256_INVALID", "adapter_config_sha256"
    )
    expected_model_sha = _sha256(
        expected.get("adapter_model_sha256"), "ADAPTER_MODEL_SHA256_INVALID", "adapter_model_sha256"
    )
    actual_config_sha = sha256_file(config_path)
    actual_model_sha = sha256_file(model_path)
    if actual_config_sha != expected_config_sha:
        _fail("ADAPTER_CONFIG_SHA256_MISMATCH", str(config_path))
    if actual_model_sha != expected_model_sha:
        _fail("ADAPTER_MODEL_SHA256_MISMATCH", str(model_path))

    config = _json_without_duplicate_keys(config_path, "ADAPTER_CONFIG_INVALID")
    exact_fields = (
        ("adapter_id", "ADAPTER_ID_MISMATCH"),
        ("base_model_name_or_path", "ADAPTER_BASE_MODEL_MISMATCH"),
        ("base_model_revision", "ADAPTER_BASE_REVISION_MISMATCH"),
        ("peft_type", "ADAPTER_PEFT_TYPE_MISMATCH"),
    )
    for field, code in exact_fields:
        required = _text(expected.get(field), f"{code}_EXPECTED_INVALID", field)
        if config.get(field) != required:
            _fail(code, field)
    expected_modules = expected.get("target_modules")
    if not isinstance(expected_modules, list) or not expected_modules or not all(
        isinstance(item, str) and item for item in expected_modules
    ):
        _fail("ADAPTER_TARGET_MODULES_EXPECTED_INVALID", "target_modules")
    if config.get("target_modules") != expected_modules:
        _fail("ADAPTER_TARGET_MODULES_MISMATCH", "target_modules")
    return {
        "adapter_directory": directory,
        "adapter_config_sha256": actual_config_sha,
        "adapter_model_sha256": actual_model_sha,
        "base_model_name_or_path": config["base_model_name_or_path"],
        "base_model_revision": config["base_model_revision"],
        "peft_type": config["peft_type"],
        "target_modules": list(config["target_modules"]),
    }


def validate_hf_transport(transport: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Validate a declared transport route without probing a service or reading a secret."""
    forbidden_secret_fields = {"token", "hf_token", "raw_token", "secret_value", "token_value"}
    exposed = sorted(key for key in transport if key.casefold() in forbidden_secret_fields)
    if exposed:
        _fail("SECRET_MATERIAL_FORBIDDEN", ", ".join(exposed))
    allowed_fields = {
        "selected_source", "secret_source", "token_printed", "token_available_to_runner",
        "live_route_available", "mounted_fallback_allowed", "transport_mode",
        "xet_failure_observed", "transport_fallback_policy", "dependency_conflict",
        "download_state", "cache_root",
    }
    unknown = sorted(key for key in transport if key not in allowed_fields)
    if unknown:
        _fail("HF_TRANSPORT_FIELD_UNKNOWN", ", ".join(unknown))
    if transport.get("token_printed") is not False:
        _fail("SECRET_EXPOSURE_FORBIDDEN", "token_printed must be false")
    selected_source = transport.get("selected_source")
    if selected_source not in {"HF_VAULT", "MOUNTED_LOCAL"}:
        _fail("HF_SOURCE_INVALID", "selected_source")
    secret_source = transport.get("secret_source")
    if secret_source not in {"KAGGLE_SECRETS", "HOST_SECRET_STORE", "NONE_FOR_MOUNTED_LOCAL"}:
        _fail("HF_SECRET_SOURCE_INVALID", "secret_source")
    cache_root = Path(_text(transport.get("cache_root"), "HF_CACHE_ROOT_INVALID", "cache_root"))
    if not cache_root.is_absolute() or cache_root.is_symlink() or _is_within(cache_root, source_root):
        _fail("HF_CACHE_ROOT_INVALID", str(cache_root))
    if transport.get("dependency_conflict") is not False:
        _fail("HF_TRANSPORT_DEPENDENCY_CONFLICT", "dependency_conflict must be false")
    if transport.get("download_state") != "COMPLETE":
        _fail("HF_DOWNLOAD_INCOMPLETE", "download_state must be COMPLETE")
    mode = transport.get("transport_mode")
    if mode not in {"XET", "HTTP_FALLBACK", "MOUNTED_LOCAL"}:
        _fail("HF_TRANSPORT_MODE_INVALID", "transport_mode")
    if selected_source == "HF_VAULT":
        if transport.get("live_route_available") is not True:
            _fail("HF_LIVE_ROUTE_UNAVAILABLE", "live_route_available")
        if transport.get("token_available_to_runner") is not True:
            _fail("HF_TOKEN_UNAVAILABLE_TO_RUNNER", "token_available_to_runner")
        if mode == "MOUNTED_LOCAL":
            _fail("HF_TRANSPORT_MODE_INVALID", "HF_VAULT cannot use MOUNTED_LOCAL mode")
    else:
        if transport.get("mounted_fallback_allowed") is not True:
            _fail("MOUNTED_FALLBACK_NOT_AUTHORIZED", "mounted_fallback_allowed")
        if mode != "MOUNTED_LOCAL":
            _fail("HF_TRANSPORT_MODE_INVALID", "MOUNTED_LOCAL source requires MOUNTED_LOCAL mode")
    if mode == "HTTP_FALLBACK":
        if transport.get("xet_failure_observed") is not True:
            _fail("HF_HTTP_FALLBACK_UNJUSTIFIED", "xet_failure_observed")
        if transport.get("transport_fallback_policy") != "CONDITIONAL_EXPLICIT":
            _fail("HF_HTTP_FALLBACK_UNAUTHORIZED", "transport_fallback_policy")
    return {
        "selected_source": selected_source,
        "secret_source": secret_source,
        "transport_mode": mode,
        "cache_root": str(cache_root),
        "secret_value_inspected": False,
        "network_probed": False,
    }


def validate_resource_controls(resources: Mapping[str, Any]) -> dict[str, Any]:
    """Validate declared CUDA/QLoRA lifecycle controls without importing a runtime stack."""
    if resources.get("loader_api") != "AutoModelForCausalLM.from_pretrained":
        _fail("MODEL_LOADER_CONTRACT_INVALID", "loader_api")
    if resources.get("quantization_config_used") is not True:
        _fail("QLORA_QUANTIZATION_CONFIG_REQUIRED", "quantization_config_used")
    if resources.get("legacy_load_in_4bit_kwarg_forwarded") is not False:
        _fail("QLORA_LEGACY_LOAD_KWARG_FORBIDDEN", "legacy_load_in_4bit_kwarg_forwarded")
    if resources.get("four_bit_linear_modules_present") is not True:
        _fail("QLORA_FOUR_BIT_MODULES_REQUIRED", "four_bit_linear_modules_present")
    if resources.get("glibcxx_compatible") is not True:
        _fail("CUDA_RUNTIME_LIBRARY_INCOMPATIBLE", "glibcxx_compatible")
    if resources.get("process_isolation") != "PROCESS_PER_ARM":
        _fail("PROCESS_ISOLATION_REQUIRED", "process_isolation")
    for field, code in (
        ("model_released_between_arms", "MODEL_RELEASE_BETWEEN_ARMS_REQUIRED"),
        ("adapter_unloaded_between_arms", "ADAPTER_UNLOAD_BETWEEN_ARMS_REQUIRED"),
        ("memory_telemetry_enabled", "MEMORY_TELEMETRY_REQUIRED"),
    ):
        if resources.get(field) is not True:
            _fail(code, field)
    for field in ("sequence_length", "batch_size", "max_sequence_length", "max_batch_size"):
        if type(resources.get(field)) is not int or resources[field] <= 0:
            _fail("RESOURCE_ENVELOPE_INVALID", field)
    if resources["sequence_length"] > resources["max_sequence_length"]:
        _fail("SEQUENCE_LENGTH_OUTSIDE_ENVELOPE", "sequence_length")
    if resources["batch_size"] > resources["max_batch_size"]:
        _fail("BATCH_SIZE_OUTSIDE_ENVELOPE", "batch_size")
    if resources.get("oom_policy") != "PARTIAL_ASSESSMENT_ONLY":
        _fail("OOM_RECOVERY_POLICY_INVALID", "oom_policy")
    return {
        "process_isolation": "PROCESS_PER_ARM",
        "runtime_proven": False,
        "model_inference_invoked": False,
        "memory_telemetry_observed": False,
    }


def validate_runtime_contract_shape(runtime: Mapping[str, Any]) -> dict[str, Any]:
    """Check filenames, keys, aliases, and post-artifact presentation failures statically."""
    expected_filename = _single_component(
        runtime.get("expected_contract_filename"), "RUNTIME_CONTRACT_FILENAME_INVALID", "expected_contract_filename"
    )
    actual_filename = _single_component(
        runtime.get("contract_filename"), "RUNTIME_CONTRACT_FILENAME_INVALID", "contract_filename"
    )
    if actual_filename != expected_filename:
        _fail("RUNTIME_CONTRACT_FILENAME_MISMATCH", f"expected {expected_filename}, found {actual_filename}")
    values = _mapping(runtime.get("values"), "RUNTIME_REQUIRED_KEY_MISSING", "values")
    required = ("run_root", "output_root", "artifact_root", "base_model_dir", "route_head_dir")
    normalized: dict[str, str] = {}
    for key in required:
        normalized[key] = _text(values.get(key), "RUNTIME_REQUIRED_KEY_MISSING", key)
    aliases = _mapping(runtime.get("legacy_aliases", {}), "RUNTIME_ALIAS_INVALID", "legacy_aliases")
    if "full_run_root" in aliases and aliases["full_run_root"] != normalized["run_root"]:
        _fail("RUNTIME_LEGACY_ALIAS_MISMATCH", "full_run_root")
    if "artifact_root" in aliases and aliases["artifact_root"] != normalized["artifact_root"]:
        _fail("RUNTIME_LEGACY_ALIAS_MISMATCH", "artifact_root")
    if "base_model_dir" in aliases and aliases["base_model_dir"] != normalized["base_model_dir"]:
        _fail("RUNTIME_LEGACY_ALIAS_MISMATCH", "base_model_dir")
    if "route_head_dir" in aliases and aliases["route_head_dir"] != normalized["route_head_dir"]:
        _fail("RUNTIME_LEGACY_ALIAS_MISMATCH", "route_head_dir")
    artifact_status = runtime.get("artifact_status")
    presentation_status = runtime.get("presentation_status")
    if artifact_status not in {"CREATED", "MISSING"}:
        _fail("RUNTIME_ARTIFACT_STATUS_INVALID", "artifact_status")
    if presentation_status not in {"PASS", "FAILED_AFTER_ARTIFACT", "NOT_RUN"}:
        _fail("RUNTIME_PRESENTATION_STATUS_INVALID", "presentation_status")
    if artifact_status == "MISSING" and presentation_status == "PASS":
        _fail("RUNTIME_PRESENTATION_FALSE_SUCCESS", "artifact missing")
    return {
        "contract_filename": actual_filename,
        "artifact_status": artifact_status,
        "presentation_status": presentation_status,
        "artifact_preserved_despite_presentation_failure": (
            artifact_status == "CREATED" and presentation_status == "FAILED_AFTER_ARTIFACT"
        ),
    }


def validate_environment(environment: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a declared QLoRA environment without importing or probing it."""
    _text(environment.get("python_version"), "ENVIRONMENT_PYTHON_INVALID", "python_version")
    if environment.get("pip_check_status") != "PASS":
        _fail("ENVIRONMENT_PIP_CHECK_FAILED", "pip_check_status must be PASS")
    packages = _mapping(environment.get("packages"), "ENVIRONMENT_PACKAGES_INVALID", "packages")
    required_packages = _mapping(
        environment.get("required_packages"), "ENVIRONMENT_REQUIRED_PACKAGES_INVALID", "required_packages"
    )
    for package, version in required_packages.items():
        if not isinstance(package, str) or not package or not isinstance(version, str) or not version:
            _fail("ENVIRONMENT_REQUIRED_PACKAGES_INVALID", "package pins must be non-empty strings")
        if packages.get(package) != version:
            _fail("ENVIRONMENT_PACKAGE_MISMATCH", package)
    if environment.get("quantization_mode") != "QLORA":
        _fail("ENVIRONMENT_QUANTIZATION_MODE_INVALID", "quantization_mode must be QLORA")
    if environment.get("load_in_4bit") is not True:
        _fail("QLORA_4BIT_REQUIRED", "load_in_4bit must be true")
    if environment.get("cuda_available") is not True:
        _fail("QLORA_CUDA_REQUIRED", "cuda_available must be true")
    _text(environment.get("cuda_version"), "QLORA_CUDA_VERSION_INVALID", "cuda_version")
    if environment.get("bitsandbytes_cuda_backend") != "AVAILABLE":
        _fail("QLORA_BITSANDBYTES_CUDA_REQUIRED", "bitsandbytes_cuda_backend must be AVAILABLE")
    if not isinstance(packages.get("bitsandbytes"), str) or not packages["bitsandbytes"]:
        _fail("QLORA_BITSANDBYTES_PACKAGE_REQUIRED", "packages.bitsandbytes")
    return {
        "python_version": environment["python_version"],
        "packages": dict(packages),
        "quantization_mode": "QLORA",
        "load_in_4bit": True,
        "bitsandbytes_cuda_backend": "AVAILABLE",
    }


def validate_runner_identity(runner: Mapping[str, Any]) -> dict[str, str]:
    """Require a meaningful future runner identity without importing or executing it."""
    runner_file = _text(runner.get("runner_file"), "RUNNER_FILE_INVALID", "runner_file")
    path = Path(runner_file)
    if (path.is_absolute() or "\\" in runner_file
            or runner_file in {"__file__", "__main__", ".", ".."}
            or ".." in path.parts or not runner_file.endswith(".py")):
        _fail("RUNNER_FILE_INVALID", runner_file)
    runner_sha = _sha256(runner.get("runner_file_sha256"), "RUNNER_FILE_SHA256_INVALID", "runner_file_sha256")
    return {"runner_file": runner_file, "runner_file_sha256": runner_sha}


def validate_output_allocation(
    source_root: Path,
    allocation: Mapping[str, Any],
    available_bytes: int,
) -> dict[str, Any]:
    """Keep transient artifacts outside source and out of the assessment-only package."""
    source = source_root.resolve()
    output_text = _text(allocation.get("output_root"), "OUTPUT_ROOT_INVALID", "output_root")
    output_root = Path(output_text)
    if not output_root.is_absolute():
        _fail("OUTPUT_ROOT_INVALID", output_text)
    _reject_symlink_path(output_root, "OUTPUT_ROOT_SYMLINK_FORBIDDEN")
    if output_root.exists() and not output_root.is_dir():
        _fail("OUTPUT_ROOT_INVALID", output_text)
    if _is_within(output_root, source):
        _fail("OUTPUT_ROOT_IN_SOURCE_TREE", str(output_root))
    subtrees = allocation.get("subtrees")
    if (
        not isinstance(subtrees, list)
        or not all(isinstance(item, str) and item for item in subtrees)
        or len(subtrees) != len(set(subtrees))
        or set(subtrees) != set(REQUIRED_OUTPUT_SUBTREES)
    ):
        _fail("OUTPUT_SUBTREE_LAYOUT_INVALID", "exact required output subtrees are required")
    minimum = allocation.get("minimum_free_bytes")
    if type(minimum) is not int or minimum < 0 or type(available_bytes) is not int or available_bytes < 0:
        _fail("OUTPUT_CAPACITY_INPUT_INVALID", "byte values must be non-negative integers")
    if available_bytes < minimum:
        _fail("OUTPUT_DISK_RESERVE_UNMET", f"available {available_bytes}, required {minimum}")
    assessment_includes = allocation.get("assessment_includes")
    if not isinstance(assessment_includes, list) or not assessment_includes or not all(isinstance(item, str) and item for item in assessment_includes):
        _fail("ASSESSMENT_CONTENTS_INVALID", "assessment_includes must be non-empty relative paths")
    forbidden_roots = {
        "ephemeral_heavy",
        "model_cache",
        "adapter_cache",
        "run_scratch",
        "durable_heavy",
    }
    for item in assessment_includes:
        relative = Path(item)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            _fail("ASSESSMENT_PATH_INVALID", item)
        if relative.parts[0] in forbidden_roots:
            _fail("ASSESSMENT_INCLUDES_HEAVY_OUTPUT", item)
    return {
        "output_root": str(output_root),
        "subtrees": list(REQUIRED_OUTPUT_SUBTREES),
        "available_bytes": available_bytes,
        "minimum_free_bytes": minimum,
        "assessment_excludes_heavy_output": True,
    }


def validate_supervision_contract(supervision: Mapping[str, Any]) -> dict[str, Any]:
    """Reject static supervision shapes that collapse prompt, target, or provenance."""
    rows = supervision.get("rows")
    if not isinstance(rows, list) or not rows:
        _fail("SUPERVISION_ROWS_INVALID", "rows")
    seen_ids: set[str] = set()
    for number, raw in enumerate(rows, start=1):
        row = _mapping(raw, "SUPERVISION_ROW_INVALID", f"rows[{number}]")
        sample_id = _text(row.get("sample_id"), "SUPERVISION_SAMPLE_ID_INVALID", "sample_id")
        if sample_id in seen_ids:
            _fail("SUPERVISION_SAMPLE_ID_DUPLICATE", sample_id)
        seen_ids.add(sample_id)
        prompt = _text(row.get("prompt"), "SUPERVISION_PROMPT_INVALID", "prompt")
        target = _text(row.get("target"), "SUPERVISION_TARGET_EMPTY", "target")
        if prompt == target or target in prompt:
            _fail("SUPERVISION_TARGET_LEAKS_TO_PROMPT", sample_id)
        for field in ("family", "source", "action"):
            _text(row.get(field), "SUPERVISION_DISCRIMINATIVE_FIELD_INVALID", field)
        audited_sha = _sha256(
            row.get("audited_object_sha256"), "SUPERVISION_AUDITED_OBJECT_INVALID", "audited_object_sha256"
        )
        training_sha = _sha256(
            row.get("training_object_sha256"), "SUPERVISION_TRAINING_OBJECT_INVALID", "training_object_sha256"
        )
        if audited_sha != training_sha:
            _fail("SUPERVISION_OBJECT_PROVENANCE_MISMATCH", sample_id)
    return {"row_count": len(rows), "training_invoked": False, "prompt_target_separated": True}


def validate_measurement_contract(measurement: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze row/scorer shape while leaving the next benchmark unselected."""
    if measurement.get("manifest_kind") != "BENCHMARK":
        _fail("MEASUREMENT_MANIFEST_NOT_BENCHMARK", "manifest_kind")
    if measurement.get("measurement_authority") != "PLAN_ONLY":
        _fail("MEASUREMENT_AUTHORITY_OUT_OF_SCOPE", "measurement_authority")
    requested_count = measurement.get("requested_row_count")
    rows = measurement.get("rows")
    if type(requested_count) is not int or requested_count <= 0:
        _fail("MEASUREMENT_REQUESTED_ROW_COUNT_INVALID", "requested_row_count")
    if not isinstance(rows, list) or len(rows) != requested_count:
        _fail("MEASUREMENT_ROW_COUNT_MISMATCH", "rows")
    for field in (
        "prompt_template_sha256",
        "scorer_sha256",
        "normalizer_sha256",
        "finalizer_sha256",
        "generation_config_sha256",
        "seed_policy_sha256",
    ):
        _sha256(measurement.get(field), "MEASUREMENT_IDENTITY_FIELD_INVALID", field)
    seen_ids: set[str] = set()
    for number, raw in enumerate(rows, start=1):
        row = _mapping(raw, "MEASUREMENT_ROW_INVALID", f"rows[{number}]")
        sample_id = _text(row.get("sample_id"), "MEASUREMENT_SAMPLE_ID_INVALID", "sample_id")
        if sample_id in seen_ids:
            _fail("MEASUREMENT_SAMPLE_ID_DUPLICATE", sample_id)
        seen_ids.add(sample_id)
        _text(row.get("question_text"), "MEASUREMENT_QUESTION_TEXT_MISSING", "question_text")
        _sha256(row.get("source_row_sha256"), "MEASUREMENT_SOURCE_ROW_INVALID", "source_row_sha256")
        _sha256(row.get("expected_answer_sha256"), "MEASUREMENT_EXPECTED_ANSWER_INVALID", "expected_answer_sha256")
        if "expected_answer" in row or row.get("expected_answer_visible_to_model") is not False:
            _fail("MEASUREMENT_EXPECTED_ANSWER_VISIBLE_TO_MODEL", sample_id)
    return {
        "requested_row_count": requested_count,
        "measurement_authority": "PLAN_ONLY",
        "benchmark_selected": False,
        "expected_answers_scorer_only": True,
    }


def validate_scorecard_reconciliation(scorecard: Mapping[str, Any]) -> dict[str, Any]:
    """Ensure a declared aggregate can be recomputed from its row-level decisions."""
    rows = scorecard.get("rows")
    if not isinstance(rows, list) or not rows:
        _fail("SCORECARD_ROWS_INVALID", "rows")
    seen_ids: set[str] = set()
    correct_count = 0
    for number, raw in enumerate(rows, start=1):
        row = _mapping(raw, "SCORECARD_ROW_INVALID", f"rows[{number}]")
        sample_id = _text(row.get("sample_id"), "SCORECARD_SAMPLE_ID_INVALID", "sample_id")
        if sample_id in seen_ids:
            _fail("SCORECARD_SAMPLE_ID_DUPLICATE", sample_id)
        seen_ids.add(sample_id)
        if row.get("decision_sample_id") != sample_id or row.get("prediction_sample_id") != sample_id:
            _fail("SCORECARD_DECISION_PREDICTION_ID_MISMATCH", sample_id)
        if type(row.get("decision_correct")) is not bool or type(row.get("prediction_correct")) is not bool:
            _fail("SCORECARD_CORRECTNESS_INVALID", sample_id)
        if row["decision_correct"] != row["prediction_correct"]:
            _fail("SCORECARD_DECISION_PREDICTION_MISMATCH", sample_id)
        correct_count += int(row["prediction_correct"])
    row_count = scorecard.get("row_count")
    declared_correct = scorecard.get("correct_count")
    accuracy = scorecard.get("accuracy")
    if (
        type(row_count) is not int
        or type(declared_correct) is not int
        or type(accuracy) not in (int, float)
        or row_count != len(rows)
        or declared_correct != correct_count
    ):
        _fail("SCORECARD_AGGREGATE_MISMATCH", "row_count or correct_count")
    expected_accuracy = correct_count / len(rows)
    if accuracy != expected_accuracy:
        _fail("SCORECARD_AGGREGATE_MISMATCH", "accuracy")
    if scorecard.get("frozen_source_reuse") is not False:
        _fail("SCORECARD_STALE_SOURCE_REUSE", "frozen_source_reuse")
    return {"row_count": len(rows), "correct_count": correct_count, "accuracy": expected_accuracy}


def validate_claim_ceiling(claims: Mapping[str, Any]) -> dict[str, Any]:
    """Keep simulation, replay, upload, and scaffold evidence below live claim tiers."""
    evidence_mode = claims.get("evidence_mode")
    allowed_modes = {
        "PLAN_ONLY",
        "SIMULATION_ONLY",
        "SCAFFOLD_ONLY",
        "FROZEN_OUTPUT_REPLAY",
        "SOURCE_ROW_REPLAY",
        "FRESH_GENERATION_INTERNAL",
        "FRESH_GENERATION_EXTERNAL",
    }
    if evidence_mode not in allowed_modes:
        _fail("EVIDENCE_MODE_INVALID", "evidence_mode")
    result_status = _text(claims.get("result_status"), "CLAIM_RESULT_STATUS_INVALID", "result_status")
    if evidence_mode == "SCAFFOLD_ONLY" and result_status.startswith("PASS"):
        _fail("SCAFFOLD_CANNOT_EARN_PASS", result_status)
    outcomes = _mapping(claims.get("claims"), "CLAIM_FLAGS_INVALID", "claims")
    claim_fields = ("fresh_generation", "performance_superiority", "promotion", "external_authority", "commercial_authority")
    unknown_claims = sorted(set(outcomes) - set(claim_fields))
    if unknown_claims:
        _fail("CLAIM_FLAG_UNKNOWN", ", ".join(unknown_claims))
    for field in claim_fields:
        if type(outcomes.get(field)) is not bool:
            _fail("CLAIM_FLAGS_INVALID", field)
    if evidence_mode == "FROZEN_OUTPUT_REPLAY" and outcomes["fresh_generation"]:
        _fail("REPLAY_CANNOT_CLAIM_FRESH_GENERATION", evidence_mode)
    if evidence_mode in {"PLAN_ONLY", "SIMULATION_ONLY", "SCAFFOLD_ONLY", "FROZEN_OUTPUT_REPLAY", "SOURCE_ROW_REPLAY"}:
        if any(outcomes[field] for field in claim_fields):
            _fail("CLAIM_EXCEEDS_EVIDENCE_TIER", evidence_mode)
    if evidence_mode in {"FRESH_GENERATION_INTERNAL", "FRESH_GENERATION_EXTERNAL"}:
        if any(outcomes[field] for field in ("performance_superiority", "promotion", "external_authority", "commercial_authority")):
            _fail("CLAIM_EXCEEDS_EVIDENCE_TIER", evidence_mode)
    if claims.get("hf_upload_observed") is True and outcomes["promotion"]:
        _fail("HF_UPLOAD_CANNOT_PROMOTE", "promotion")
    gates = claims.get("mandatory_gates")
    if not isinstance(gates, list) or not gates:
        _fail("MANDATORY_GATE_LIST_INVALID", "mandatory_gates")
    for number, raw in enumerate(gates, start=1):
        gate = _mapping(raw, "MANDATORY_GATE_INVALID", f"mandatory_gates[{number}]")
        _text(gate.get("gate_id"), "MANDATORY_GATE_INVALID", "gate_id")
        if gate.get("required") is not True or gate.get("status") != "PASS":
            _fail("MANDATORY_GATE_NOT_PASS", str(gate.get("gate_id")))
    return {
        "evidence_mode": evidence_mode,
        "performance_claim_authorized": False,
        "promotion_authorized": False,
        "external_authority": False,
    }


def validate_finalization_payload(payload: object) -> None:
    """Fail before a packaging tail can hide a non-JSON-safe summary object."""
    try:
        json.dumps(payload, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        _fail("FINALIZATION_PAYLOAD_NOT_JSON_SAFE", str(exc))


def validate_execution_ceiling(execution: Mapping[str, Any]) -> None:
    """Reject a request to turn this static control into an execution authorization."""
    unknown = sorted(set(execution) - set(EXECUTION_FLAGS))
    if unknown:
        _fail("EXECUTION_FLAG_UNKNOWN", ", ".join(unknown))
    for flag in EXECUTION_FLAGS:
        if execution.get(flag) is not False:
            _fail("OUT_OF_SCOPE_EXECUTION_REQUEST", flag)


def evaluate_static_preflight(
    plan: Mapping[str, Any],
    *,
    source_root: Path,
    available_bytes: int,
) -> dict[str, Any]:
    """Evaluate the complete static contract and return no execution authority."""
    planes = validate_identity_planes(
        _mapping(plan.get("identity_planes"), "IDENTITY_PLAN_INVALID", "identity_planes")
    )
    packet_root = Path(_text(plan.get("packet_root"), "PACKET_ROOT_INVALID", "packet_root"))
    declared_head = planes["source"]["repo_head"]
    actual_head = declared_head
    try:
        import subprocess
        actual_head = subprocess.run(("git", "-C", str(source_root), "rev-parse", "HEAD"), check=True, capture_output=True, text=True).stdout.strip()
        actual_head = _head(actual_head, "SOURCE_HEAD_INVALID", "actual_source_head")
    except (OSError, subprocess.CalledProcessError) as exc:
        _fail("SOURCE_HEAD_UNAVAILABLE", str(source_root))
    if declared_head != actual_head:
        _fail("SOURCE_HEAD_MISMATCH", f"declared={declared_head} actual={actual_head}")
    packet = validate_packet_selection(
        packet_root,
        _mapping(plan.get("packet_selection"), "PACKET_SELECTION_INVALID", "packet_selection"),
        actual_head,
    )
    adapter = validate_adapter_identity(
        Path(_text(plan.get("adapter_root"), "ADAPTER_ROOT_INVALID", "adapter_root")),
        _mapping(plan.get("adapter"), "ADAPTER_EXPECTATION_INVALID", "adapter"),
    )
    inventory = validate_input_inventory(
        _mapping(plan.get("input_inventory"), "INPUT_INVENTORY_INVALID", "input_inventory")
    )
    hf_transport = validate_hf_transport(
        _mapping(plan.get("hf_transport"), "HF_TRANSPORT_INVALID", "hf_transport"), source_root
    )
    environment = validate_environment(
        _mapping(plan.get("environment"), "ENVIRONMENT_PLAN_INVALID", "environment")
    )
    resources = validate_resource_controls(
        _mapping(plan.get("resource_controls"), "RESOURCE_CONTROLS_INVALID", "resource_controls")
    )
    runtime = validate_runtime_contract_shape(
        _mapping(plan.get("runtime_contract"), "RUNTIME_CONTRACT_INVALID", "runtime_contract")
    )
    output = validate_output_allocation(
        source_root,
        _mapping(plan.get("output"), "OUTPUT_PLAN_INVALID", "output"),
        available_bytes,
    )
    runner = validate_runner_identity(_mapping(plan.get("runner"), "RUNNER_PLAN_INVALID", "runner"))
    supervision = validate_supervision_contract(
        _mapping(plan.get("supervision"), "SUPERVISION_PLAN_INVALID", "supervision")
    )
    measurement_plan = _mapping(plan.get("measurement"), "MEASUREMENT_PLAN_INVALID", "measurement")
    scorecard_plan = _mapping(plan.get("scorecard"), "SCORECARD_PLAN_INVALID", "scorecard")
    measurement = validate_measurement_contract(measurement_plan)
    scorecard = validate_scorecard_reconciliation(scorecard_plan)
    measurement_ids = {str(row.get("sample_id")) for row in measurement_plan.get("rows", []) if isinstance(row, dict)}
    scorecard_ids = {str(row.get("sample_id")) for row in scorecard_plan.get("rows", []) if isinstance(row, dict)}
    if measurement_ids != scorecard_ids:
        _fail("SCORECARD_MEASUREMENT_ID_MISMATCH", "sample_id")
    claim_ceiling = validate_claim_ceiling(
        _mapping(plan.get("claim_ceiling"), "CLAIM_CEILING_INVALID", "claim_ceiling")
    )
    validate_finalization_payload(plan.get("finalization_payload"))
    validate_execution_ceiling(_mapping(plan.get("execution"), "EXECUTION_PLAN_INVALID", "execution"))
    return {
        "schema_id": SCHEMA_ID,
        "status": PASS_STATUS,
        "identity_planes": planes,
        "packet": packet,
        "adapter": adapter,
        "input_inventory": inventory,
        "hf_transport": hf_transport,
        "environment": environment,
        "resource_controls": resources,
        "runtime_contract": runtime,
        "output": output,
        "runner": runner,
        "supervision": supervision,
        "measurement": measurement,
        "scorecard": scorecard,
        "claim_ceiling": claim_ceiling,
        "simulation_only": True,
        "model_inference_invoked": False,
        "training_invoked": False,
        "kaggle_execution_authorized": False,
        "paid_compute_authorized": False,
        "final_benchmark_selected": False,
        "performance_claim_authorized": False,
    }


def preserve_partial_measurements(
    source_root: Path,
    allocation: Mapping[str, Any],
    available_bytes: int,
    completed_rows: Sequence[Mapping[str, Any]],
    failure_reason: str,
) -> dict[str, Any]:
    """Persist supplied synthetic rows after a simulated arm failure.

    The caller supplies rows already measured by an external future lane. This
    function does not load a model or make a measurement; it only preserves the
    supplied rows and marks them assessment-only.
    """
    output = validate_output_allocation(source_root, allocation, available_bytes)
    reason = _text(failure_reason, "PARTIAL_FAILURE_REASON_INVALID", "failure_reason")
    root = Path(output["output_root"])
    assessment = root / "assessment_return"
    if assessment.exists() and (assessment.is_symlink() or not assessment.is_dir()):
        _fail("ASSESSMENT_RETURN_ROOT_INVALID", str(assessment))
    assessment.mkdir(parents=True, exist_ok=True)
    journal_path = assessment / "measurement_journal.jsonl"
    receipt_path = assessment / "partial_assessment_receipt.json"
    for destination in (journal_path, receipt_path):
        if destination.is_symlink() or destination.exists():
            _fail("ASSESSMENT_OUTPUT_DESTINATION_INVALID", str(destination))
    encoded_events = []
    for index, row in enumerate(completed_rows, start=1):
        if not isinstance(row, Mapping):
            _fail("PARTIAL_MEASUREMENT_ROW_INVALID", f"row {index}")
        event = {"event": "MEASURED_ROW", "sequence": index, "row": dict(row)}
        try:
            encoded_events.append(json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False))
        except (TypeError, ValueError) as exc:
            _fail("PARTIAL_MEASUREMENT_ROW_NOT_JSON_SAFE", str(exc))
    written = len(encoded_events)
    try:
        encoded_events.append(json.dumps(
            {"event": "SIMULATED_ARM_FAILURE", "completed_rows": written, "reason": reason},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ))
    except (TypeError, ValueError) as exc:
        _fail("PARTIAL_MEASUREMENT_ROW_NOT_JSON_SAFE", str(exc))
    journal_tmp = journal_path.with_name(f".{journal_path.name}.tmp")
    if journal_tmp.is_symlink() or journal_tmp.exists():
        _fail("ASSESSMENT_OUTPUT_DESTINATION_INVALID", str(journal_tmp))
    try:
        journal_tmp.write_text("\n".join(encoded_events) + "\n", encoding="utf-8", newline="\n")
        os.replace(journal_tmp, journal_path)
    finally:
        journal_tmp.unlink(missing_ok=True)
    receipt = {
        "schema_id": SCHEMA_ID,
        "status": PARTIAL_STATUS,
        "output_mode": ASSESSMENT_ONLY,
        "completed_measured_rows": written,
        "failure_reason": reason,
        "journal": str(journal_path),
        "control_module_file": str(Path(__file__).resolve()),
        "simulation_only": True,
        "model_inference_invoked": False,
        "training_invoked": False,
        "kaggle_execution_authorized": False,
        "performance_claim_authorized": False,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    return receipt
