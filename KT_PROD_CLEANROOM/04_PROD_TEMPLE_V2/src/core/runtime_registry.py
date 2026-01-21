from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple


class RuntimeRegistryError(RuntimeError):
    pass


_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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
class PolicyCSpec:
    drift: PolicyCDriftSpec


@dataclass(frozen=True)
class RuntimeRegistry:
    registry_version: str
    canonical_entry: CallableSpec
    canonical_spine: CallableSpec
    state_vault: StateVaultSpec
    runtime_import_roots: Tuple[str, ...]
    organs_by_root: Mapping[str, str]
    import_truth_matrix: Mapping[str, Tuple[str, ...]]
    dry_run: DryRunSpec
    policy_c: PolicyCSpec

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
        "registry_version",
        "canonical_entry",
        "canonical_spine",
        "state_vault",
        "runtime_import_roots",
        "organs_by_root",
        "import_truth_matrix",
        "dry_run",
        "policy_c",
    }
    extra = set(data.keys()) - allowed_top
    if extra:
        raise RuntimeRegistryError(f"Runtime registry has unknown top-level keys (fail-closed): {sorted(extra)}")

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
        registry_version=registry_version,
        canonical_entry=canonical_entry,
        canonical_spine=canonical_spine,
        state_vault=state_vault,
        runtime_import_roots=runtime_import_roots,
        organs_by_root=organs_by_root,
        import_truth_matrix=import_truth_matrix,
        dry_run=dry_run,
        policy_c=policy_c,
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
        canonical_entry=CallableSpec("kt.entrypoint", "invoke"),
        canonical_spine=CallableSpec("core.spine", "run"),
        state_vault=StateVaultSpec(jsonl_path=jsonl_path),
        runtime_import_roots=(),
        organs_by_root={},
        import_truth_matrix={},
        dry_run=DryRunSpec(no_network=True, providers_enabled=False),
        policy_c=PolicyCSpec(drift=PolicyCDriftSpec(l2_warn=0.0, l2_fail=0.0, max_fail=0.0)),
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
    if set(value.keys()) != {"drift"}:
        raise RuntimeRegistryError("policy_c must contain exactly key ['drift'] (fail-closed)")
    drift = value.get("drift")
    if not isinstance(drift, dict):
        raise RuntimeRegistryError("policy_c.drift must be an object (fail-closed)")
    if set(drift.keys()) != {"l2_warn", "l2_fail", "max_fail"}:
        raise RuntimeRegistryError("policy_c.drift must contain l2_warn, l2_fail, max_fail (fail-closed)")
    l2_warn = drift.get("l2_warn")
    l2_fail = drift.get("l2_fail")
    max_fail = drift.get("max_fail")
    for name, value in (("l2_warn", l2_warn), ("l2_fail", l2_fail), ("max_fail", max_fail)):
        if not isinstance(value, (int, float)):
            raise RuntimeRegistryError(f"policy_c.drift.{name} must be numeric (fail-closed)")
        if value < 0.0 or value > 1.0:
            raise RuntimeRegistryError(f"policy_c.drift.{name} out of bounds [0,1] (fail-closed)")
    if l2_warn > l2_fail:
        raise RuntimeRegistryError("policy_c.drift.l2_warn must be <= l2_fail (fail-closed)")
    return PolicyCSpec(drift=PolicyCDriftSpec(l2_warn=float(l2_warn), l2_fail=float(l2_fail), max_fail=float(max_fail)))
