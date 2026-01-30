from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from tools.training.fl3_factory.hashing import sha256_file_normalized
from tools.training.fl3_factory.io import read_json_object
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


@dataclass(frozen=True)
class OrganContract:
    raw: Dict[str, Any]

    @property
    def allowed_base_models(self) -> List[str]:
        return list(self.raw.get("allowed_base_models", []))

    @property
    def allowed_training_modes(self) -> List[str]:
        return list(self.raw.get("allowed_training_modes", []))

    @property
    def allowed_output_schemas(self) -> List[str]:
        return list(self.raw.get("allowed_output_schemas", []))

    @property
    def allowed_export_roots(self) -> List[str]:
        return list(self.raw.get("allowed_export_roots", []))

    @property
    def entrypoints(self) -> Dict[str, Dict[str, str]]:
        return dict(self.raw.get("entrypoints", {}))


def load_organ_contract(path: Path) -> OrganContract:
    obj = read_json_object(path)
    validate_schema_bound_object(obj)
    if obj.get("schema_id") != "kt.factory.organ_contract.v1":
        raise FL3ValidationError("organ contract schema_id mismatch (fail-closed)")
    return OrganContract(raw=obj)


def enforce_entrypoints(contract: OrganContract, *, repo_root: Path) -> None:
    eps = contract.entrypoints
    if "run_job" not in eps:
        raise FL3ValidationError("entrypoints.run_job missing (fail-closed)")
    for name, spec in eps.items():
        rel = spec.get("path", "")
        expected = spec.get("sha256", "")
        if not isinstance(rel, str) or not rel.strip():
            raise FL3ValidationError(f"entrypoints.{name}.path invalid (fail-closed)")
        if not isinstance(expected, str) or len(expected) != 64:
            raise FL3ValidationError(f"entrypoints.{name}.sha256 invalid (fail-closed)")
        file_path = (repo_root / rel).resolve()
        if not file_path.exists():
            raise FL3ValidationError(f"entrypoint path missing on disk (fail-closed): {rel}")
        actual = sha256_file_normalized(file_path)
        if actual != expected:
            raise FL3ValidationError(f"entrypoint hash mismatch (fail-closed): {name}")


def enforce_allowlists(
    contract: OrganContract,
    *,
    base_model_id: str,
    training_mode: str,
    output_schema_ids: Iterable[str],
    export_roots: Iterable[str],
) -> None:
    if base_model_id not in set(contract.allowed_base_models):
        raise FL3ValidationError("base_model_id not allowlisted by organ contract (fail-closed)")
    if training_mode not in set(contract.allowed_training_modes):
        raise FL3ValidationError("training_mode not allowlisted by organ contract (fail-closed)")

    allowed_out: Set[str] = set(contract.allowed_output_schemas)
    missing = set(output_schema_ids) - allowed_out
    if missing:
        raise FL3ValidationError(f"Output schema(s) not allowlisted by organ contract (fail-closed): {sorted(missing)}")

    allowed_roots = set(contract.allowed_export_roots)
    for r in export_roots:
        if not any(str(r).startswith(root) for root in allowed_roots):
            raise FL3ValidationError(f"Export root not under allowed_export_roots (fail-closed): {r}")
