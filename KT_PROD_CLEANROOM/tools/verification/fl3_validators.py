from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.verification.fl3_canonical import read_json, repo_root_from


class FL3ValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExportRoots:
    exports_adapters: Path
    exports_shadow: Path


@dataclass(frozen=True)
class ExportRootsMRT1:
    exports_adapters_mrt1: Path
    exports_shadow_mrt1: Path


def load_fl3_canonical_runtime_paths(*, repo_root: Path) -> Dict[str, Any]:
    p = repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FL3_CANONICAL_RUNTIME_PATHS.json"
    if not p.exists():
        raise FL3ValidationError(f"Missing FL3 canonical runtime paths file (fail-closed): {p.as_posix()}")
    obj = read_json(p)
    if not isinstance(obj, dict) or obj.get("schema_id") != "kt.fl3.canonical_runtime_paths.v1":
        raise FL3ValidationError("FL3_CANONICAL_RUNTIME_PATHS.json schema_id mismatch (fail-closed)")
    return obj


def fl3_export_roots(*, repo_root: Path) -> ExportRoots:
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    exports_adapters = (repo_root / paths["exports_adapters_root"]).resolve()
    exports_shadow = (repo_root / paths["exports_shadow_root"]).resolve()
    return ExportRoots(exports_adapters=exports_adapters, exports_shadow=exports_shadow)


def fl3_export_roots_mrt1(*, repo_root: Path) -> ExportRootsMRT1:
    """
    MRT-1 export roots are separate from MRT-0 and must never be implicitly mixed.

    These are declared in AUDITS/FL3_CANONICAL_RUNTIME_PATHS.json (append-only).
    """
    paths = load_fl3_canonical_runtime_paths(repo_root=repo_root)
    exports_adapters = str(paths.get("exports_adapters_mrt1_root", "")).strip()
    exports_shadow = str(paths.get("exports_shadow_mrt1_root", "")).strip()
    if not exports_adapters or not exports_shadow:
        raise FL3ValidationError("Missing MRT-1 exports roots in FL3 canonical runtime paths (fail-closed)")
    return ExportRootsMRT1(
        exports_adapters_mrt1=(repo_root / exports_adapters).resolve(),
        exports_shadow_mrt1=(repo_root / exports_shadow).resolve(),
    )


def assert_path_under_exports(*, repo_root: Path, path: Path, allow_promoted: bool = True) -> None:
    roots = fl3_export_roots(repo_root=repo_root)
    target = path.resolve()
    allowed: List[Path] = [roots.exports_shadow]
    if allow_promoted:
        allowed.append(roots.exports_adapters)
    for root in allowed:
        try:
            target.relative_to(root)
            return
        except Exception:
            continue
    raise FL3ValidationError(f"Path escapes allowed exports roots (fail-closed): {target.as_posix()}")


def assert_relpath_under_exports(*, repo_root: Path, relpath: str, allow_promoted: bool = True) -> Path:
    if not isinstance(relpath, str) or not relpath.strip():
        raise FL3ValidationError("relpath must be a non-empty string (fail-closed)")
    p = Path(relpath)
    if p.is_absolute() or any(part in {"..", "."} for part in p.parts):
        raise FL3ValidationError("relpath must be a clean relative path (fail-closed)")
    resolved = (repo_root / p).resolve()
    assert_path_under_exports(repo_root=repo_root, path=resolved, allow_promoted=allow_promoted)
    return resolved


def assert_path_under_exports_mrt1(*, repo_root: Path, path: Path, allow_promoted: bool = True) -> None:
    roots = fl3_export_roots_mrt1(repo_root=repo_root)
    target = path.resolve()
    allowed: List[Path] = [roots.exports_shadow_mrt1]
    if allow_promoted:
        allowed.append(roots.exports_adapters_mrt1)
    for root in allowed:
        try:
            target.relative_to(root)
            return
        except Exception:
            continue
    raise FL3ValidationError(f"Path escapes allowed MRT-1 exports roots (fail-closed): {target.as_posix()}")


def assert_relpath_under_exports_mrt1(*, repo_root: Path, relpath: str, allow_promoted: bool = True) -> Path:
    if not isinstance(relpath, str) or not relpath.strip():
        raise FL3ValidationError("relpath must be a non-empty string (fail-closed)")
    p = Path(relpath)
    if p.is_absolute() or any(part in {"..", "."} for part in p.parts):
        raise FL3ValidationError("relpath must be a clean relative path (fail-closed)")
    resolved = (repo_root / p).resolve()
    assert_path_under_exports_mrt1(repo_root=repo_root, path=resolved, allow_promoted=allow_promoted)
    return resolved


def validate_schema_bound_object(payload: Any) -> None:
    # Defer to the existing schema registry/binding mechanism (global enforcement).
    from schemas.schema_registry import validate_object_with_binding  # type: ignore

    try:
        validate_object_with_binding(payload)
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(str(exc)) from exc


def validate_many_schema_bound_objects(objs: Iterable[Any]) -> None:
    for o in objs:
        validate_schema_bound_object(o)
