from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from schemas.adapter_entry_schema import ADAPTER_ENTRY_SCHEMA_ID, ADAPTER_ENTRY_SCHEMA_VERSION_HASH
from schemas.runtime_registry_schema import (
    RUNTIME_REGISTRY_SCHEMA_ID,
    RUNTIME_REGISTRY_SCHEMA_VERSION_HASH,
    validate_runtime_registry,
)

class RuntimeRegistryError(RuntimeError):
    pass


_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_ADAPTER_REGISTRY_SCHEMA_ID = "kt.adapters.registry.v1"


@dataclass(frozen=True)
class CallableSpec:
    module: str
    callable: str


@dataclass(frozen=True)
class StateVaultSpec:
    jsonl_path: str


@dataclass(frozen=True)
class DryRunSpec:
    no_network: bool
    providers_enabled: bool


@dataclass(frozen=True)
class PolicyCDriftSpec:
    l2_warn: float
    l2_fail: float
    max_fail: float


@dataclass(frozen=True)
class PolicyCSweepSpec:
    max_runs_default: int
    fail_fast_default: bool
    export_enabled: bool
    allowed_export_roots: Tuple[str, ...]


@dataclass(frozen=True)
class PolicyCStaticSafetySpec:
    enabled: bool
    forbidden_imports: Tuple[str, ...]
    allowed_export_roots: Tuple[str, ...]


@dataclass(frozen=True)
class PolicyCSpec:
    drift: PolicyCDriftSpec
    sweep: PolicyCSweepSpec
    static_safety: PolicyCStaticSafetySpec


@dataclass(frozen=True)
class AdapterEntry:
    schema_id: str
    schema_version_hash: str
    adapter_id: str
    version: str
    base_model: str
    artifact_path: str
    artifact_hash: str
    capabilities: Tuple[str, ...]
    constraints: Tuple[str, ...]
    training_receipt_ref: str
    evaluation_receipt_ref: str
    status: str


@dataclass(frozen=True)
class AdapterRegistrySpec:
    registry_schema_id: str
    allowed_export_roots: Tuple[str, ...]
    entries: Tuple[AdapterEntry, ...]


@dataclass(frozen=True)
class RuntimeRegistry:
    schema_id: str
    schema_version_hash: str
    registry_version: str
    canonical_entry: CallableSpec
    canonical_spine: CallableSpec
    state_vault: StateVaultSpec
    runtime_import_roots: Tuple[str, ...]
    organs_by_root: Mapping[str, str]
    import_truth_matrix: Mapping[str, Tuple[str, ...]]
    dry_run: DryRunSpec
    policy_c: PolicyCSpec
    adapters: AdapterRegistrySpec

    def resolve_state_vault_jsonl_path(self) -> Path:
        repo_root = _v2_repo_root()
        rel = Path(self.state_vault.jsonl_path)
        if rel.is_absolute():
            raise RuntimeRegistryError("state_vault.jsonl_path must be a relative path (fail-closed)")
        if any(part in {"..", "."} for part in rel.parts):
            raise RuntimeRegistryError("state_vault.jsonl_path must not contain '.' or '..' segments (fail-closed)")
        resolved = (repo_root / rel).resolve()
        try:
            resolved.relative_to(repo_root)
        except Exception:
            raise RuntimeRegistryError("state_vault.jsonl_path escapes repo_root (fail-closed)")
        return resolved

    def organ_for_module(self, module_name: str) -> str | None:
        top = module_name.split(".", 1)[0]
        return self.organs_by_root.get(top)


def _v2_repo_root() -> Path:
    # .../04_PROD_TEMPLE_V2/src/core/runtime_registry.py -> .../04_PROD_TEMPLE_V2
    return Path(__file__).resolve().parents[2]


def runtime_registry_path() -> Path:
    return _v2_repo_root() / "docs" / "RUNTIME_REGISTRY.json"


def load_runtime_registry() -> RuntimeRegistry:
    path = runtime_registry_path()
    if not path.exists():
        raise RuntimeRegistryError(f"Missing runtime registry (fail-closed): {path.as_posix()}")

    try:
        raw = path.read_bytes()
    except Exception as exc:
        raise RuntimeRegistryError(f"Unable to read runtime registry: {exc.__class__.__name__}")
    if len(raw) > 64 * 1024:
        raise RuntimeRegistryError("Runtime registry exceeds max bytes (fail-closed)")

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeRegistryError(f"Runtime registry JSON parse error: {exc.__class__.__name__}")
    if not isinstance(data, dict):
        raise RuntimeRegistryError("Runtime registry must be a JSON object (fail-closed)")

    allowed_top = {
        "schema_id",
        "schema_version_hash",
        "registry_version",
        "canonical_entry",
        "canonical_spine",
        "state_vault",
        "runtime_import_roots",
        "organs_by_root",
        "import_truth_matrix",
        "dry_run",
        "policy_c",
        "adapters",
    }
    extra = set(data.keys()) - allowed_top
    if extra:
        raise RuntimeRegistryError(f"Runtime registry has unknown top-level keys (fail-closed): {sorted(extra)}")

    if data.get("schema_id") != RUNTIME_REGISTRY_SCHEMA_ID:
        raise RuntimeRegistryError("runtime registry schema_id mismatch (fail-closed)")
    if data.get("schema_version_hash") != RUNTIME_REGISTRY_SCHEMA_VERSION_HASH:
        raise RuntimeRegistryError("runtime registry schema_version_hash mismatch (fail-closed)")

    try:
        validate_runtime_registry(data)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeRegistryError(str(exc))

    registry_version = data.get("registry_version")
    if registry_version != "1":
        raise RuntimeRegistryError("registry_version must be '1' (fail-closed)")

    canonical_entry = _parse_callable_spec(data.get("canonical_entry"), name="canonical_entry")
    canonical_spine = _parse_callable_spec(data.get("canonical_spine"), name="canonical_spine")
    state_vault = _parse_state_vault_spec(data.get("state_vault"))
    runtime_import_roots = _parse_sorted_str_list(data.get("runtime_import_roots"), name="runtime_import_roots")
    organs_by_root = _parse_organs_by_root(data.get("organs_by_root"), runtime_import_roots)
    import_truth_matrix = _parse_import_truth_matrix(data.get("import_truth_matrix"))
    dry_run = _parse_dry_run_spec(data.get("dry_run"))
    policy_c = _parse_policy_c_spec(data.get("policy_c"))
    adapters = _parse_adapters_spec(data.get("adapters"))

    # Root allowlist must cover canonical Entry + Spine module roots (no silent discovery).
    for spec, label in ((canonical_entry, "canonical_entry"), (canonical_spine, "canonical_spine")):
        top = spec.module.split(".", 1)[0]
        if top not in runtime_import_roots:
            raise RuntimeRegistryError(f"{label}.module root {top!r} not in runtime_import_roots (fail-closed)")

    # Organs must be declared for each runtime root (fail-closed).
    for root in runtime_import_roots:
        if root not in organs_by_root:
            raise RuntimeRegistryError(f"Missing organs_by_root mapping for runtime root: {root!r}")

    # Import Truth matrix must define the Entry organ row.
    entry_organ = organs_by_root.get(canonical_entry.module.split(".", 1)[0], "")
    if entry_organ not in import_truth_matrix:
        raise RuntimeRegistryError("Import Truth matrix missing canonical Entry organ row (fail-closed)")

    return RuntimeRegistry(
        schema_id=RUNTIME_REGISTRY_SCHEMA_ID,
        schema_version_hash=RUNTIME_REGISTRY_SCHEMA_VERSION_HASH,
        registry_version=registry_version,
        canonical_entry=canonical_entry,
        canonical_spine=canonical_spine,
        state_vault=state_vault,
        runtime_import_roots=runtime_import_roots,
        organs_by_root=organs_by_root,
        import_truth_matrix=import_truth_matrix,
        dry_run=dry_run,
        policy_c=policy_c,
        adapters=adapters,
    )


def _parse_callable_spec(value: Any, *, name: str) -> CallableSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError(f"{name} must be an object (fail-closed)")
    if set(value.keys()) != {"module", "callable"}:
        raise RuntimeRegistryError(f"{name} must contain exactly keys ['module','callable'] (fail-closed)")

    mod = value.get("module")
    call = value.get("callable")
    if not isinstance(mod, str) or not _MODULE_RE.match(mod):
        raise RuntimeRegistryError(f"{name}.module must be a valid module path (fail-closed)")
    if not isinstance(call, str) or not _IDENT_RE.match(call):
        raise RuntimeRegistryError(f"{name}.callable must be a valid identifier (fail-closed)")
    return CallableSpec(module=mod, callable=call)


def _parse_state_vault_spec(value: Any) -> StateVaultSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("state_vault must be an object (fail-closed)")
    if set(value.keys()) != {"jsonl_path"}:
        raise RuntimeRegistryError("state_vault must contain exactly key ['jsonl_path'] (fail-closed)")
    jsonl_path = value.get("jsonl_path")
    if not isinstance(jsonl_path, str) or not jsonl_path.endswith(".jsonl"):
        raise RuntimeRegistryError("state_vault.jsonl_path must be a .jsonl path string (fail-closed)")
    # Ensure path resolves inside repo root.
    _ = RuntimeRegistry(
        registry_version="1",
        schema_id=RUNTIME_REGISTRY_SCHEMA_ID,
        schema_version_hash=RUNTIME_REGISTRY_SCHEMA_VERSION_HASH,
        canonical_entry=CallableSpec("kt.entrypoint", "invoke"),
        canonical_spine=CallableSpec("core.spine", "run"),
        state_vault=StateVaultSpec(jsonl_path=jsonl_path),
        runtime_import_roots=(),
        organs_by_root={},
        import_truth_matrix={},
        dry_run=DryRunSpec(no_network=True, providers_enabled=False),
        policy_c=PolicyCSpec(
            drift=PolicyCDriftSpec(l2_warn=0.0, l2_fail=0.0, max_fail=0.0),
            sweep=PolicyCSweepSpec(
                max_runs_default=0,
                fail_fast_default=True,
                export_enabled=False,
                allowed_export_roots=(),
            ),
            static_safety=PolicyCStaticSafetySpec(
                enabled=True,
                forbidden_imports=(),
                allowed_export_roots=(),
            ),
        ),
        adapters=AdapterRegistrySpec(
            registry_schema_id="kt.adapters.registry.v1",
            allowed_export_roots=(),
            entries=(),
        ),
    ).resolve_state_vault_jsonl_path()
    return StateVaultSpec(jsonl_path=jsonl_path)


def _parse_sorted_str_list(value: Any, *, name: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
        raise RuntimeRegistryError(f"{name} must be a non-empty list of strings (fail-closed)")
    normalized = [x.strip() for x in value]
    if any(not x for x in normalized):
        raise RuntimeRegistryError(f"{name} contains empty strings (fail-closed)")
    if normalized != sorted(normalized):
        raise RuntimeRegistryError(f"{name} must be sorted lexicographically (fail-closed)")
    if len(set(normalized)) != len(normalized):
        raise RuntimeRegistryError(f"{name} must not contain duplicates (fail-closed)")
    if any(not _IDENT_RE.match(x) for x in normalized):
        raise RuntimeRegistryError(f"{name} contains invalid identifiers (fail-closed)")
    return tuple(normalized)


def _parse_organs_by_root(value: Any, runtime_import_roots: Sequence[str]) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("organs_by_root must be an object (fail-closed)")
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise RuntimeRegistryError("organs_by_root keys/values must be strings (fail-closed)")
        if k not in runtime_import_roots:
            raise RuntimeRegistryError(f"organs_by_root includes non-runtime root: {k!r} (fail-closed)")
        if not v.strip():
            raise RuntimeRegistryError("organs_by_root organ names must be non-empty (fail-closed)")
    return value


def _parse_import_truth_matrix(value: Any) -> Mapping[str, Tuple[str, ...]]:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("import_truth_matrix must be an object (fail-closed)")
    matrix: Dict[str, Tuple[str, ...]] = {}
    for src_organ, dsts in value.items():
        if not isinstance(src_organ, str) or not src_organ.strip():
            raise RuntimeRegistryError("import_truth_matrix organ keys must be non-empty strings (fail-closed)")
        if not isinstance(dsts, list) or not dsts or not all(isinstance(x, str) and x.strip() for x in dsts):
            raise RuntimeRegistryError("import_truth_matrix values must be non-empty lists of strings (fail-closed)")
        if len(set(dsts)) != len(dsts):
            raise RuntimeRegistryError("import_truth_matrix values must not contain duplicates (fail-closed)")
        matrix[src_organ] = tuple(dsts)
    return matrix


def _parse_dry_run_spec(value: Any) -> DryRunSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("dry_run must be an object (fail-closed)")
    if set(value.keys()) != {"no_network", "providers_enabled"}:
        raise RuntimeRegistryError("dry_run must contain exactly keys ['no_network','providers_enabled'] (fail-closed)")
    no_network = value.get("no_network")
    providers_enabled = value.get("providers_enabled")
    if not isinstance(no_network, bool) or not isinstance(providers_enabled, bool):
        raise RuntimeRegistryError("dry_run.no_network and dry_run.providers_enabled must be booleans (fail-closed)")
    return DryRunSpec(no_network=no_network, providers_enabled=providers_enabled)


def _parse_policy_c_spec(value: Any) -> PolicyCSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("policy_c must be an object (fail-closed)")
    if set(value.keys()) != {"drift", "sweep", "static_safety"}:
        raise RuntimeRegistryError("policy_c must contain exactly keys ['drift','sweep','static_safety'] (fail-closed)")
    drift = _parse_policy_c_drift(value.get("drift"))
    sweep = _parse_policy_c_sweep(value.get("sweep"))
    static_safety = _parse_policy_c_static_safety(value.get("static_safety"))
    return PolicyCSpec(drift=drift, sweep=sweep, static_safety=static_safety)


def _parse_policy_c_drift(value: Any) -> PolicyCDriftSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("policy_c.drift must be an object (fail-closed)")
    if set(value.keys()) != {"l2_warn", "l2_fail", "max_fail"}:
        raise RuntimeRegistryError("policy_c.drift must contain l2_warn, l2_fail, max_fail (fail-closed)")
    l2_warn = value.get("l2_warn")
    l2_fail = value.get("l2_fail")
    max_fail = value.get("max_fail")
    for name, val in (("l2_warn", l2_warn), ("l2_fail", l2_fail), ("max_fail", max_fail)):
        if not isinstance(val, (int, float)):
            raise RuntimeRegistryError(f"policy_c.drift.{name} must be numeric (fail-closed)")
        if val < 0.0 or val > 1.0:
            raise RuntimeRegistryError(f"policy_c.drift.{name} out of bounds [0,1] (fail-closed)")
    if l2_warn > l2_fail:
        raise RuntimeRegistryError("policy_c.drift.l2_warn must be <= l2_fail (fail-closed)")
    return PolicyCDriftSpec(l2_warn=float(l2_warn), l2_fail=float(l2_fail), max_fail=float(max_fail))


def _parse_policy_c_sweep(value: Any) -> PolicyCSweepSpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("policy_c.sweep must be an object (fail-closed)")
    if set(value.keys()) != {"max_runs_default", "fail_fast_default", "export_enabled", "allowed_export_roots"}:
        raise RuntimeRegistryError(
            "policy_c.sweep must contain max_runs_default, fail_fast_default, export_enabled, allowed_export_roots (fail-closed)"
        )
    max_runs_default = value.get("max_runs_default")
    fail_fast_default = value.get("fail_fast_default")
    export_enabled = value.get("export_enabled")
    allowed_export_roots = value.get("allowed_export_roots")
    if not isinstance(max_runs_default, int) or max_runs_default <= 0:
        raise RuntimeRegistryError("policy_c.sweep.max_runs_default must be positive int (fail-closed)")
    if not isinstance(fail_fast_default, bool) or not isinstance(export_enabled, bool):
        raise RuntimeRegistryError("policy_c.sweep flags must be booleans (fail-closed)")
    roots = _parse_export_root_list(allowed_export_roots, name="policy_c.sweep.allowed_export_roots")
    return PolicyCSweepSpec(
        max_runs_default=int(max_runs_default),
        fail_fast_default=bool(fail_fast_default),
        export_enabled=bool(export_enabled),
        allowed_export_roots=roots,
    )


def _parse_policy_c_static_safety(value: Any) -> PolicyCStaticSafetySpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("policy_c.static_safety must be an object (fail-closed)")
    if set(value.keys()) != {"enabled", "forbidden_imports", "allowed_export_roots"}:
        raise RuntimeRegistryError(
            "policy_c.static_safety must contain enabled, forbidden_imports, allowed_export_roots (fail-closed)"
        )
    enabled = value.get("enabled")
    forbidden_imports = value.get("forbidden_imports")
    allowed_export_roots = value.get("allowed_export_roots")
    if not isinstance(enabled, bool):
        raise RuntimeRegistryError("policy_c.static_safety.enabled must be boolean (fail-closed)")
    if not isinstance(forbidden_imports, list) or not forbidden_imports or not all(
        isinstance(x, str) and x.strip() for x in forbidden_imports
    ):
        raise RuntimeRegistryError("policy_c.static_safety.forbidden_imports must be non-empty list of strings (fail-closed)")
    roots = _parse_export_root_list(allowed_export_roots, name="policy_c.static_safety.allowed_export_roots")
    forbidden_sorted = tuple(sorted(x.strip() for x in forbidden_imports))
    return PolicyCStaticSafetySpec(
        enabled=enabled,
        forbidden_imports=forbidden_sorted,
        allowed_export_roots=roots,
    )


def _parse_export_root_list(value: Any, *, name: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
        raise RuntimeRegistryError(f"{name} must be a non-empty list of strings (fail-closed)")
    normalized = [x.strip() for x in value]
    if any(not x for x in normalized):
        raise RuntimeRegistryError(f"{name} contains empty strings (fail-closed)")
    if normalized != sorted(normalized):
        raise RuntimeRegistryError(f"{name} must be sorted lexicographically (fail-closed)")
    if len(set(normalized)) != len(normalized):
        raise RuntimeRegistryError(f"{name} must not contain duplicates (fail-closed)")
    for entry in normalized:
        p = Path(entry)
        if p.is_absolute():
            raise RuntimeRegistryError(f"{name} must be relative (fail-closed)")
        if any(part in {"..", "."} for part in p.parts):
            raise RuntimeRegistryError(f"{name} must not contain '.' or '..' segments (fail-closed)")
    return tuple(normalized)


def parse_adapters_spec(value: Any) -> AdapterRegistrySpec:
    """
    Public, stable wrapper for parsing adapters registry spec.

    Tools that need adapters parsing semantics should call this instead of the
    private underscore helper.
    """
    return _parse_adapters_spec(value)


def _parse_adapters_spec(value: Any) -> AdapterRegistrySpec:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("adapters must be an object (fail-closed)")
    if set(value.keys()) != {"registry_schema_id", "allowed_export_roots", "entries"}:
        raise RuntimeRegistryError("adapters must contain registry_schema_id, allowed_export_roots, entries (fail-closed)")
    registry_schema_id = value.get("registry_schema_id")
    if not isinstance(registry_schema_id, str) or not registry_schema_id.strip():
        raise RuntimeRegistryError("adapters.registry_schema_id must be a non-empty string (fail-closed)")
    if registry_schema_id.strip() != _ADAPTER_REGISTRY_SCHEMA_ID:
        raise RuntimeRegistryError("adapters.registry_schema_id mismatch (fail-closed)")
    allowed_export_roots = _parse_export_root_list(value.get("allowed_export_roots"), name="adapters.allowed_export_roots")
    entries_raw = value.get("entries")
    if not isinstance(entries_raw, list):
        raise RuntimeRegistryError("adapters.entries must be a list (fail-closed)")
    entries = [_parse_adapter_entry(item, allowed_export_roots) for item in entries_raw]
    ordering = [(e.adapter_id, e.version) for e in entries]
    if ordering != sorted(ordering):
        raise RuntimeRegistryError("adapters.entries must be sorted by adapter_id,version (fail-closed)")
    return AdapterRegistrySpec(
        registry_schema_id=registry_schema_id.strip(),
        allowed_export_roots=allowed_export_roots,
        entries=tuple(entries),
    )


def _parse_adapter_entry(value: Any, allowed_export_roots: Tuple[str, ...]) -> AdapterEntry:
    if not isinstance(value, dict):
        raise RuntimeRegistryError("adapter entry must be an object (fail-closed)")
    expected = {
        "schema_id",
        "schema_version_hash",
        "adapter_id",
        "version",
        "base_model",
        "artifact_path",
        "artifact_hash",
        "capabilities",
        "constraints",
        "training_receipt_ref",
        "evaluation_receipt_ref",
        "status",
    }
    if set(value.keys()) != expected:
        raise RuntimeRegistryError("adapter entry keys must match spec exactly (fail-closed)")
    schema_id = value.get("schema_id")
    schema_version_hash = value.get("schema_version_hash")
    adapter_id = value.get("adapter_id")
    version = value.get("version")
    base_model = value.get("base_model")
    artifact_path = value.get("artifact_path")
    artifact_hash = value.get("artifact_hash")
    capabilities = value.get("capabilities")
    constraints = value.get("constraints")
    training_receipt_ref = value.get("training_receipt_ref")
    evaluation_receipt_ref = value.get("evaluation_receipt_ref")
    status = value.get("status")

    for field, val in (
        ("schema_id", schema_id),
        ("schema_version_hash", schema_version_hash),
        ("adapter_id", adapter_id),
        ("version", version),
        ("base_model", base_model),
        ("artifact_path", artifact_path),
        ("artifact_hash", artifact_hash),
        ("training_receipt_ref", training_receipt_ref),
        ("evaluation_receipt_ref", evaluation_receipt_ref),
        ("status", status),
    ):
        if not isinstance(val, str) or not val.strip():
            raise RuntimeRegistryError(f"adapter entry {field} must be a non-empty string (fail-closed)")

    if schema_id != ADAPTER_ENTRY_SCHEMA_ID:
        raise RuntimeRegistryError("adapter entry schema_id mismatch (fail-closed)")
    if schema_version_hash != ADAPTER_ENTRY_SCHEMA_VERSION_HASH:
        raise RuntimeRegistryError("adapter entry schema_version_hash mismatch (fail-closed)")

    if not _HEX_64_RE.match(artifact_hash):
        raise RuntimeRegistryError("adapter entry artifact_hash must be 64 lowercase hex (fail-closed)")

    path_obj = Path(artifact_path)
    if path_obj.is_absolute():
        raise RuntimeRegistryError("adapter entry artifact_path must be relative (fail-closed)")
    if any(part in {".", ".."} for part in path_obj.parts):
        raise RuntimeRegistryError("adapter entry artifact_path must not contain '.' or '..' (fail-closed)")
    if not any(str(artifact_path).startswith(root) for root in allowed_export_roots):
        raise RuntimeRegistryError("adapter entry artifact_path not under allowed_export_roots (fail-closed)")

    if not isinstance(capabilities, list) or not all(isinstance(x, str) and x.strip() for x in capabilities):
        raise RuntimeRegistryError("adapter entry capabilities must be list of non-empty strings (fail-closed)")
    if not isinstance(constraints, list) or not all(isinstance(x, str) and x.strip() for x in constraints):
        raise RuntimeRegistryError("adapter entry constraints must be list of non-empty strings (fail-closed)")

    if status not in {"ACTIVE", "DEPRECATED", "REVOKED"}:
        raise RuntimeRegistryError("adapter entry status must be ACTIVE, DEPRECATED, or REVOKED (fail-closed)")

    return AdapterEntry(
        schema_id=schema_id.strip(),
        schema_version_hash=schema_version_hash.strip(),
        adapter_id=adapter_id.strip(),
        version=version.strip(),
        base_model=base_model.strip(),
        artifact_path=str(artifact_path).strip(),
        artifact_hash=artifact_hash.strip(),
        capabilities=tuple(sorted(x.strip() for x in capabilities)),
        constraints=tuple(sorted(x.strip() for x in constraints)),
        training_receipt_ref=training_receipt_ref.strip(),
        evaluation_receipt_ref=evaluation_receipt_ref.strip(),
        status=status.strip(),
    )
