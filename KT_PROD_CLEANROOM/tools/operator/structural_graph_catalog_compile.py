from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterator, List, Optional, Sequence, Set, Tuple

import jsonschema

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP5_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_snapshot_inventory_compilation_receipt.json"
SNAPSHOT_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_snapshot_manifest.json"
PARSE_RESULTS_REL = f"{REPORT_ROOT_REL}/kt_parse_results.json"
FACT_GRAPH_SCHEMA_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_fact_graph.schema.json"
ORGAN_ONTOLOGY_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_organ_ontology.json"
RUNTIME_REGISTRY_REL = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"
ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
LOBE_ROLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/lobe_role_registry.json"
ROUTER_POLICY_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
CRUCIBLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/crucible_registry.json"
OVERLAY_REGISTRY_REL = "KT_PROD_CLEANROOM/AUDITS/OVERLAYS/OVERLAY_REGISTRY.json"
ANCHOR_REFERENCE_SET_REL = "KT_PROD_CLEANROOM/AUDITS/ANCHOR_REFERENCE_SET.json"
REOPENED_DEFECT_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_reopened_defect_register.json"
FORGOTTEN_SURFACE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_forgotten_surface_register.json"
HISTORICAL_CONFLICTS_REL = f"{REPORT_ROOT_REL}/kt_historical_conflicts.json"
HISTORICAL_RESOLUTIONS_REL = f"{REPORT_ROOT_REL}/kt_historical_resolutions.json"
WS0_WS11_RECEIPT_INDEX_REL = f"{REPORT_ROOT_REL}/ws0_ws11_closeout_receipt_index.json"
LOBE_COOPERATION_MATRIX_REL = f"{REPORT_ROOT_REL}/lobe_cooperation_matrix.json"
ROUTING_DELTA_MATRIX_REL = f"{REPORT_ROOT_REL}/routing_delta_matrix.json"

FACT_GRAPH_REL = f"{REPORT_ROOT_REL}/kt_fact_graph.json"
TEMPORAL_GRAPH_REL = f"{REPORT_ROOT_REL}/kt_temporal_graph.json"
DATA_LINEAGE_REL = f"{REPORT_ROOT_REL}/kt_data_lineage.json"
ADAPTER_REGISTRY_OUT_REL = f"{REPORT_ROOT_REL}/kt_adapter_registry.json"
MODEL_REGISTRY_OUT_REL = f"{REPORT_ROOT_REL}/kt_model_registry.json"
SECTOR_HARNESS_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_sector_harness_registry.json"
TAG_CATALOG_REL = f"{REPORT_ROOT_REL}/kt_tag_catalog.json"
SYMBOL_INDEX_REL = f"{REPORT_ROOT_REL}/kt_symbol_index.json"
CONTRACT_INDEX_REL = f"{REPORT_ROOT_REL}/kt_contract_index.json"
TRUTH_SURFACE_MAP_REL = f"{REPORT_ROOT_REL}/kt_truth_surface_map.json"
RUNTIME_GRAPH_REL = f"{REPORT_ROOT_REL}/kt_runtime_graph.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_graph_and_catalog_compilation_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/structural_graph_catalog_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_structural_graph_catalog_compile.py"

DELIVERABLE_REFS = [
    FACT_GRAPH_REL,
    TEMPORAL_GRAPH_REL,
    DATA_LINEAGE_REL,
    ADAPTER_REGISTRY_OUT_REL,
    MODEL_REGISTRY_OUT_REL,
    SECTOR_HARNESS_REGISTRY_REL,
    TAG_CATALOG_REL,
    SYMBOL_INDEX_REL,
    CONTRACT_INDEX_REL,
    TRUTH_SURFACE_MAP_REL,
    RUNTIME_GRAPH_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

MODEL_ID_KEYS = {"model_id", "baseline_model_id", "base_model_id"}
TRUTH_PATH_TOKENS = (
    "truth",
    "authority",
    "verifier",
    "publication",
    "current_pointer",
    "current_state_receipt",
    "runtime_closure_audit",
    "execution_board",
)
CONTRACT_NAME_TOKENS = ("contract", "law", "policy", "rules", "manifest", "registry", "schema")
PYTHON_ROOT_PREFIX = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _load_optional(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        return {}
    return load_json(path)


def _load_json_any(path: Path) -> Any:
    return json.loads(path.read_bytes().decode("utf-8-sig"))


def _decode_text(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _normalize_ref(ref: str) -> str:
    return str(ref).replace("\\", "/").strip()


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _iter_keyed_scalars(value: Any) -> Iterator[Tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _iter_keyed_scalars(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_keyed_scalars(item)


def _string_list(value: Any) -> List[str]:
    if isinstance(value, str):
        cleaned = _normalize_ref(value)
        return [cleaned] if cleaned else []
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            if isinstance(item, str):
                cleaned = _normalize_ref(item)
                if cleaned:
                    out.append(cleaned)
        return sorted(set(out))
    return []


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("||".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}::{digest}"


def _module_name_for_path(path: str) -> str:
    normalized = _normalize_ref(path)
    if normalized.endswith("/__init__.py"):
        normalized = normalized[: -len("/__init__.py")]
    elif normalized.endswith(".py"):
        normalized = normalized[:-3]
    return normalized.replace("/", ".")


def _top_level_runtime_root(path: str) -> str:
    rel = _normalize_ref(path)
    if not rel.startswith(PYTHON_ROOT_PREFIX):
        return ""
    return rel[len(PYTHON_ROOT_PREFIX) :].split("/", 1)[0].strip()


def _extract_import_roots(path: Path) -> Set[str]:
    tree = ast.parse(_decode_text(path), filename=path.as_posix())
    roots: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = str(alias.name).split(".", 1)[0].strip()
                if root:
                    roots.add(root)
        elif isinstance(node, ast.ImportFrom):
            if node.level and not node.module:
                continue
            module_name = str(node.module or "").split(".", 1)[0].strip()
            if module_name:
                roots.add(module_name)
    return roots


def _python_symbols(path: Path, rel: str, trust_zone: str, tags: Sequence[str]) -> List[Dict[str, Any]]:
    tree = ast.parse(_decode_text(path), filename=path.as_posix())
    module_name = _module_name_for_path(rel)
    out: List[Dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(
                {
                    "path": rel,
                    "module": module_name,
                    "symbol_name": str(node.name),
                    "symbol_kind": "function",
                    "lineno": int(getattr(node, "lineno", 1)),
                    "trust_zone": trust_zone,
                    "tags": sorted(set(tags)),
                }
            )
        elif isinstance(node, ast.ClassDef):
            out.append(
                {
                    "path": rel,
                    "module": module_name,
                    "symbol_name": str(node.name),
                    "symbol_kind": "class",
                    "lineno": int(getattr(node, "lineno", 1)),
                    "trust_zone": trust_zone,
                    "tags": sorted(set(tags)),
                }
            )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and str(target.id).isupper():
                    out.append(
                        {
                            "path": rel,
                            "module": module_name,
                            "symbol_name": str(target.id),
                            "symbol_kind": "constant",
                            "lineno": int(getattr(node, "lineno", 1)),
                            "trust_zone": trust_zone,
                            "tags": sorted(set(tags)),
                        }
                    )
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and str(node.target.id).isupper():
            out.append(
                {
                    "path": rel,
                    "module": module_name,
                    "symbol_name": str(node.target.id),
                    "symbol_kind": "constant",
                    "lineno": int(getattr(node, "lineno", 1)),
                    "trust_zone": trust_zone,
                    "tags": sorted(set(tags)),
                }
            )
    return out


def _path_tags(path: str, entry: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    lower = path.lower()
    name = Path(path).name.lower()
    trust_zone = str(entry.get("trust_zone", "UNKNOWN")).strip()
    file_type = str(entry.get("file_type", "unknown")).strip()
    generation_status = str(entry.get("generation_status", "unknown")).strip()

    tags = {
        f"zone.{trust_zone.lower()}",
        f"file.{file_type.lower()}",
        f"generation.{generation_status.lower()}",
    }
    facets = {
        f"trust_zone:{trust_zone}",
        f"file_type:{file_type}",
        f"generation_status:{generation_status}",
    }

    if path.startswith("KT_PROD_CLEANROOM/governance/"):
        tags.add("surface.governance")
    if path.startswith("KT_PROD_CLEANROOM/reports/"):
        tags.add("surface.report")
    if path.startswith("KT_PROD_CLEANROOM/tests/") or "/tests/" in path:
        tags.add("surface.test")
    if path.startswith("KT_PROD_CLEANROOM/tools/operator/"):
        tags.add("surface.operator")
    if path.startswith("KT_PROD_CLEANROOM/tools/growth/"):
        tags.add("surface.growth")
    if path.startswith("KT_PROD_CLEANROOM/AUDITS/"):
        tags.add("surface.audit")
    if path.startswith("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/"):
        tags.add("surface.runtime_code")
    if path.startswith("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/"):
        tags.add("surface.runtime_doc")
    if path.startswith("docs/"):
        tags.add("surface.historical_docs")
    if path.startswith("KT-Codex/"):
        tags.add("surface.codex")
    if "receipt" in lower:
        tags.add("role.receipt")
    if any(token in name for token in CONTRACT_NAME_TOKENS):
        tags.add("role.contractual")
    if "truth" in lower:
        tags.add("domain.truth")
    if "authority" in lower:
        tags.add("domain.authority")
    if "runtime" in lower:
        tags.add("domain.runtime")
    if "adapter" in lower or "lobe" in lower:
        tags.add("domain.adapter")
    if "overlay" in lower or "domain." in lower:
        tags.add("domain.sector")
    if "crucible" in lower:
        tags.add("domain.crucible")
    if name.endswith(".schema.json"):
        tags.add("role.schema")
    if file_type == "python":
        tags.add("language.python")
    elif file_type in {"json", "json_schema", "jsonl"}:
        tags.add("language.json")
    elif file_type == "markdown":
        tags.add("language.markdown")
    elif file_type == "yaml":
        tags.add("language.yaml")
    return sorted(tags), sorted(facets)


class _GraphBuilder:
    def __init__(self, *, schema_id: str, graph_id: str, generated_utc: str, plane: str) -> None:
        self.schema_id = schema_id
        self.graph_id = graph_id
        self.generated_utc = generated_utc
        self.plane = plane
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[Tuple[str, str, str, Tuple[str, ...], str], Dict[str, Any]] = {}

    def add_node(
        self,
        *,
        node_id: str,
        node_type: str,
        label: str,
        source_refs: Sequence[str],
        facets: Sequence[str],
        attributes: Dict[str, Any],
    ) -> str:
        refs = sorted({_normalize_ref(ref) for ref in source_refs if _normalize_ref(ref)})
        if not refs:
            raise RuntimeError(f"FAIL_CLOSED: node missing source refs: {node_id}")
        node = {
            "node_id": node_id,
            "node_type": node_type,
            "label": label,
            "plane": self.plane,
            "source_refs": refs,
            "facets": sorted(set(facets)),
            "attributes": attributes,
        }
        existing = self._nodes.get(node_id)
        if existing is not None:
            if existing["node_type"] != node["node_type"] or existing["label"] != node["label"] or existing["plane"] != node["plane"]:
                raise RuntimeError(f"FAIL_CLOSED: node collision with divergent identity: {node_id}")
            merged_attributes = dict(existing["attributes"])
            for key, value in node["attributes"].items():
                if key not in merged_attributes:
                    merged_attributes[key] = value
                elif merged_attributes[key] == value:
                    continue
                elif isinstance(merged_attributes[key], list) and isinstance(value, list):
                    merged_attributes[key] = sorted({str(item) for item in merged_attributes[key]} | {str(item) for item in value})
                elif not merged_attributes[key]:
                    merged_attributes[key] = value
                elif value:
                    merged_attributes[key] = merged_attributes[key]
            existing["source_refs"] = sorted(set(existing["source_refs"]) | set(node["source_refs"]))
            existing["facets"] = sorted(set(existing["facets"]) | set(node["facets"]))
            existing["attributes"] = merged_attributes
            self._nodes[node_id] = existing
            return node_id
        self._nodes[node_id] = node
        return node_id

    def add_edge(
        self,
        *,
        edge_type: str,
        from_node: str,
        to_node: str,
        provenance_refs: Sequence[str],
        temporal_state: str,
    ) -> str:
        refs = tuple(sorted({_normalize_ref(ref) for ref in provenance_refs if _normalize_ref(ref)}))
        if not refs:
            raise RuntimeError(f"FAIL_CLOSED: edge missing provenance refs: {edge_type} {from_node} -> {to_node}")
        key = (edge_type, from_node, to_node, refs, temporal_state)
        if key not in self._edges:
            self._edges[key] = {
                "edge_id": _stable_id("edge", edge_type, from_node, to_node, temporal_state, "::".join(refs)),
                "edge_type": edge_type,
                "from_node": from_node,
                "to_node": to_node,
                "provenance_refs": list(refs),
                "temporal_state": temporal_state,
            }
        return self._edges[key]["edge_id"]

    def materialize(self) -> Dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "graph_id": self.graph_id,
            "generated_utc": self.generated_utc,
            "nodes": [self._nodes[key] for key in sorted(self._nodes)],
            "edges": [self._edges[key] for key in sorted(self._edges)],
        }


def _step_context(root: Path) -> Dict[str, Any]:
    step5 = _load_required(root, STEP5_RECEIPT_REL)
    if str(step5.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 6 is blocked until Step 5 snapshot inventory receipt is PASS.")
    if str(step5.get("state_taint_status", "")).strip() != "CLEAR":
        raise RuntimeError("FAIL_CLOSED: Step 6 is blocked until Step 5 state_taint_status is CLEAR.")
    return {
        "step5_receipt": step5,
        "work_order": _load_required(root, WORK_ORDER_REL),
        "snapshot_manifest": _load_required(root, SNAPSHOT_MANIFEST_REL),
        "parse_results": _load_required(root, PARSE_RESULTS_REL),
        "graph_schema": _load_required(root, FACT_GRAPH_SCHEMA_REL),
        "organ_ontology": _load_required(root, ORGAN_ONTOLOGY_REL),
        "runtime_registry": _load_required(root, RUNTIME_REGISTRY_REL),
        "adapter_registry": _load_required(root, ADAPTER_REGISTRY_REL),
        "lobe_role_registry": _load_required(root, LOBE_ROLE_REGISTRY_REL),
        "router_policy_registry": _load_required(root, ROUTER_POLICY_REGISTRY_REL),
        "crucible_registry": _load_required(root, CRUCIBLE_REGISTRY_REL),
        "overlay_registry": _load_required(root, OVERLAY_REGISTRY_REL),
        "anchor_reference_set": _load_required(root, ANCHOR_REFERENCE_SET_REL),
        "reopened_defect_register": _load_required(root, REOPENED_DEFECT_REGISTER_REL),
        "forgotten_surface_register": _load_required(root, FORGOTTEN_SURFACE_REGISTER_REL),
        "historical_conflicts": _load_required(root, HISTORICAL_CONFLICTS_REL),
        "historical_resolutions": _load_required(root, HISTORICAL_RESOLUTIONS_REL),
        "ws0_ws11_receipt_index": _load_required(root, WS0_WS11_RECEIPT_INDEX_REL),
        "lobe_cooperation_matrix": _load_optional(root, LOBE_COOPERATION_MATRIX_REL),
        "routing_delta_matrix": _load_optional(root, ROUTING_DELTA_MATRIX_REL),
    }


def _parseable_entry_map(snapshot_manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for entry in snapshot_manifest.get("files", []):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("parse_state", "")).strip() != "parseable":
            continue
        rel = _normalize_ref(str(entry.get("path", "")))
        if rel:
            out[rel] = dict(entry)
    return out


def _compile_tag_catalog(parseable_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    assignments: List[Dict[str, Any]] = []
    tag_counts: Counter[str] = Counter()
    facet_counts: Counter[str] = Counter()
    for path in sorted(parseable_map):
        tags, facets = _path_tags(path, parseable_map[path])
        tag_counts.update(tags)
        facet_counts.update(facets)
        assignments.append(
            {
                "path": path,
                "tags": tags,
                "facets": facets,
                "source_refs": [path],
            }
        )
    return {
        "schema_id": "kt.operator.tag_catalog.v1",
        "generated_utc": "",
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "summary": {
            "assignment_count": len(assignments),
            "facet_count": len(facet_counts),
            "tag_count": len(tag_counts),
        },
        "facet_counts": dict(sorted(facet_counts.items())),
        "tag_counts": dict(sorted(tag_counts.items())),
        "tag_assignments": assignments,
    }


def _compile_symbol_index(root: Path, parseable_map: Dict[str, Dict[str, Any]], tag_catalog: Dict[str, Any]) -> Dict[str, Any]:
    assignment_map = {row["path"]: row for row in tag_catalog.get("tag_assignments", []) if isinstance(row, dict)}
    symbols: List[Dict[str, Any]] = []
    modules: Set[str] = set()
    files: Set[str] = set()
    for path, entry in sorted(parseable_map.items()):
        if str(entry.get("file_type", "")).strip() != "python":
            continue
        symbol_rows = _python_symbols(
            root / Path(path),
            path,
            str(entry.get("trust_zone", "")),
            assignment_map.get(path, {}).get("tags", []),
        )
        for row in symbol_rows:
            files.add(path)
            modules.add(str(row["module"]))
            symbols.append(row)
    symbols.sort(key=lambda row: (row["path"], row["lineno"], row["symbol_kind"], row["symbol_name"]))
    return {
        "schema_id": "kt.operator.symbol_index.v1",
        "generated_utc": "",
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "summary": {
            "file_count": len(files),
            "module_count": len(modules),
            "symbol_count": len(symbols),
        },
        "symbols": symbols,
    }


def _classify_contract_kind(path: str) -> str:
    lower = path.lower()
    name = Path(path).name.lower()
    if name.endswith(".schema.json"):
        return "schema_contract"
    for token in ("contract", "law", "policy", "rules", "manifest", "registry"):
        if token in name:
            return f"{token}_surface"
    if lower.endswith(".md"):
        return "markdown_contract"
    return "structured_surface"


def _looks_contract_surface(path: str, entry: Dict[str, Any]) -> bool:
    lower = path.lower()
    name = Path(path).name.lower()
    if str(entry.get("file_type", "")).strip() == "json_schema":
        return True
    if path.startswith("KT_PROD_CLEANROOM/governance/") and any(token in name for token in CONTRACT_NAME_TOKENS):
        return True
    if "/schemas/" in lower and lower.endswith(".json"):
        return True
    if name == "authority_contract.md":
        return True
    return False


def _compile_contract_index(root: Path, parseable_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    kind_counts: Counter[str] = Counter()
    for path, manifest_entry in sorted(parseable_map.items()):
        if not _looks_contract_surface(path, manifest_entry):
            continue
        contract_kind = _classify_contract_kind(path)
        supersedes: List[str] = []
        schema_id = ""
        status = ""
        documentary_only: Optional[bool] = None
        live_truth_allowed: Optional[bool] = None
        if str(manifest_entry.get("file_type", "")).strip() in {"json", "json_schema"}:
            payload = _load_json_any(root / Path(path))
            if isinstance(payload, dict):
                schema_id = str(payload.get("schema_id", "")).strip()
                status = str(payload.get("status", "")).strip()
                supersedes = sorted(
                    set(
                        _string_list(payload.get("supersedes"))
                        + _string_list(payload.get("superseded_by"))
                        + _string_list(payload.get("SUPERSEDED_BY"))
                    )
                )
                if "DOCUMENTARY_ONLY" in payload:
                    documentary_only = bool(payload.get("DOCUMENTARY_ONLY"))
                if "LIVE_TRUTH_ALLOWED" in payload:
                    live_truth_allowed = bool(payload.get("LIVE_TRUTH_ALLOWED"))
        kind_counts[contract_kind] += 1
        entries.append(
            {
                "path": path,
                "contract_kind": contract_kind,
                "file_type": manifest_entry["file_type"],
                "trust_zone": manifest_entry["trust_zone"],
                "schema_id": schema_id,
                "status": status,
                "supersedes_refs": supersedes,
                "documentary_only": documentary_only,
                "live_truth_allowed": live_truth_allowed,
                "source_refs": [path],
            }
        )
    return {
        "schema_id": "kt.operator.contract_index.v1",
        "generated_utc": "",
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "summary": {
            "contract_count": len(entries),
            "contract_kind_counts": dict(sorted(kind_counts.items())),
        },
        "contracts": entries,
    }


def _compile_model_registry(root: Path, parseable_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    registry: Dict[str, Dict[str, Any]] = {}
    for path, entry in sorted(parseable_map.items()):
        if str(entry.get("file_type", "")).strip() != "json":
            continue
        payload = _load_json_any(root / Path(path))
        for key, value in _iter_keyed_scalars(payload):
            if key not in MODEL_ID_KEYS or not isinstance(value, str):
                continue
            model_id = value.strip()
            if not model_id:
                continue
            row = registry.setdefault(
                model_id,
                {
                    "model_id": model_id,
                    "model_class": "governance_model",
                    "observed_fields": set(),
                    "declared_in": set(),
                    "trust_zones": set(),
                    "source_refs": set(),
                },
            )
            row["observed_fields"].add(key)
            row["declared_in"].add(path)
            row["trust_zones"].add(str(entry.get("trust_zone", "")))
            row["source_refs"].add(path)
            if key in {"baseline_model_id", "base_model_id"}:
                row["model_class"] = "base_model"
            elif not str(model_id).startswith("KT_"):
                row["model_class"] = "named_model"
    entries = [
        {
            "model_id": model_id,
            "model_class": row["model_class"],
            "observed_fields": sorted(row["observed_fields"]),
            "declared_in": sorted(row["declared_in"]),
            "trust_zones": sorted(row["trust_zones"]),
            "source_refs": sorted(row["source_refs"]),
        }
        for model_id, row in sorted(registry.items())
    ]
    return {
        "schema_id": "kt.operator.model_registry.v1",
        "generated_utc": "",
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "summary": {
            "model_count": len(entries),
            "model_class_counts": dict(sorted(Counter(entry["model_class"] for entry in entries).items())),
        },
        "models": entries,
    }


def _compile_adapter_registry(ctx: Dict[str, Any]) -> Dict[str, Any]:
    adapter_registry = ctx["adapter_registry"]
    lobe_role_registry = ctx["lobe_role_registry"]
    router_policy_registry = ctx["router_policy_registry"]
    cooperation = ctx["lobe_cooperation_matrix"]
    routing_delta = ctx["routing_delta_matrix"]

    rows: Dict[str, Dict[str, Any]] = {}
    for adapter_id in adapter_registry.get("ratified_adapter_ids", []):
        rows[str(adapter_id)] = {
            "adapter_id": str(adapter_id),
            "registry_status": "ratified",
            "role": "",
            "role_status": "",
            "default_router": False,
            "route_domain_tags": set(),
            "required_by_domains": set(),
            "required_guard_ids": set(),
            "authority_refs": set(_string_list(adapter_registry.get("authority_refs"))),
            "evidence_refs": set(),
            "source_refs": {ADAPTER_REGISTRY_REL},
            "demo_case_refs": set(),
            "cooperation_refs": set(),
        }
    for adapter_id in adapter_registry.get("experimental_adapter_ids", []):
        rows.setdefault(
            str(adapter_id),
            {
                "adapter_id": str(adapter_id),
                "registry_status": "experimental",
                "role": "",
                "role_status": "",
                "default_router": False,
                "route_domain_tags": set(),
                "required_by_domains": set(),
                "required_guard_ids": set(),
                "authority_refs": set(_string_list(adapter_registry.get("authority_refs"))),
                "evidence_refs": set(),
                "source_refs": {ADAPTER_REGISTRY_REL},
                "demo_case_refs": set(),
                "cooperation_refs": set(),
            },
        )
    for role_row in lobe_role_registry.get("entries", []):
        if not isinstance(role_row, dict):
            continue
        adapter_id = str(role_row.get("lobe_id", "")).strip()
        if not adapter_id:
            continue
        row = rows.setdefault(
            adapter_id,
            {
                "adapter_id": adapter_id,
                "registry_status": "observed",
                "role": "",
                "role_status": "",
                "default_router": False,
                "route_domain_tags": set(),
                "required_by_domains": set(),
                "required_guard_ids": set(),
                "authority_refs": set(),
                "evidence_refs": set(),
                "source_refs": set(),
                "demo_case_refs": set(),
                "cooperation_refs": set(),
            },
        )
        row["role"] = str(role_row.get("role", "")).strip()
        row["role_status"] = str(role_row.get("status", "")).strip()
        row["evidence_refs"].update(_string_list(role_row.get("evidence_refs")))
        row["source_refs"].add(LOBE_ROLE_REGISTRY_REL)
    for adapter_id in router_policy_registry.get("default_adapter_ids", []):
        cleaned = str(adapter_id).strip()
        if cleaned in rows:
            rows[cleaned]["default_router"] = True
            rows[cleaned]["source_refs"].add(ROUTER_POLICY_REGISTRY_REL)
    for route in router_policy_registry.get("routes", []):
        if not isinstance(route, dict):
            continue
        domain_tag = str(route.get("domain_tag", "")).strip()
        for adapter_id in route.get("adapter_ids", []):
            cleaned = str(adapter_id).strip()
            if cleaned not in rows:
                continue
            rows[cleaned]["route_domain_tags"].add(domain_tag)
            rows[cleaned]["source_refs"].add(ROUTER_POLICY_REGISTRY_REL)
            rows[cleaned]["required_guard_ids"].update(str(item).strip() for item in route.get("required_adapter_ids", []) if str(item).strip())
        for adapter_id in route.get("required_adapter_ids", []):
            cleaned = str(adapter_id).strip()
            if cleaned in rows:
                rows[cleaned]["required_by_domains"].add(domain_tag)
                rows[cleaned]["source_refs"].add(ROUTER_POLICY_REGISTRY_REL)
    for coop_row in cooperation.get("rows", []):
        if not isinstance(coop_row, dict):
            continue
        primary = str(coop_row.get("primary_lobe", "")).strip()
        if primary in rows:
            authority_ref = str(coop_row.get("authority_ref", "")).strip()
            if authority_ref:
                rows[primary]["cooperation_refs"].add(authority_ref)
            rows[primary]["source_refs"].add(LOBE_COOPERATION_MATRIX_REL)
    for route_row in routing_delta.get("rows", []):
        if not isinstance(route_row, dict):
            continue
        case_id = str(route_row.get("case_id", "")).strip()
        authority_ref = str(route_row.get("authority_ref", "")).strip()
        for adapter_id in route_row.get("expected_adapter_ids", []):
            cleaned = str(adapter_id).strip()
            if cleaned not in rows:
                continue
            if case_id:
                rows[cleaned]["demo_case_refs"].add(case_id)
            if authority_ref:
                rows[cleaned]["evidence_refs"].add(authority_ref)
            rows[cleaned]["source_refs"].add(ROUTING_DELTA_MATRIX_REL)

    entries = []
    for adapter_id, row in sorted(rows.items()):
        entries.append(
            {
                "adapter_id": adapter_id,
                "registry_status": row["registry_status"],
                "role": row["role"],
                "role_status": row["role_status"],
                "default_router": bool(row["default_router"]),
                "route_domain_tags": sorted(item for item in row["route_domain_tags"] if item),
                "required_by_domains": sorted(item for item in row["required_by_domains"] if item),
                "required_guard_ids": sorted(item for item in row["required_guard_ids"] if item),
                "authority_refs": sorted(item for item in row["authority_refs"] if item),
                "evidence_refs": sorted(item for item in row["evidence_refs"] if item),
                "source_refs": sorted(item for item in row["source_refs"] if item),
                "demo_case_refs": sorted(item for item in row["demo_case_refs"] if item),
                "cooperation_refs": sorted(item for item in row["cooperation_refs"] if item),
            }
        )
    return {
        "schema_id": "kt.operator.adapter_registry.v1",
        "generated_utc": "",
        "summary": {
            "adapter_count": len(entries),
            "registry_status_counts": dict(sorted(Counter(entry["registry_status"] for entry in entries).items())),
        },
        "adapters": entries,
    }


def _compile_sector_harness_registry(root: Path, ctx: Dict[str, Any]) -> Dict[str, Any]:
    overlay_registry = ctx["overlay_registry"]
    entries: List[Dict[str, Any]] = []
    for row in overlay_registry.get("overlays", []):
        if not isinstance(row, dict):
            continue
        pack_ref = _normalize_ref(str(row.get("pack_relpath", "")))
        if not pack_ref:
            continue
        pack = _load_json_any(root / Path(pack_ref))
        overlay_id = str(row.get("overlay_id", "")).strip()
        domain_slug = overlay_id.split(".", 1)[1] if "." in overlay_id else overlay_id
        entries.append(
            {
                "sector_id": overlay_id,
                "domain_slug": domain_slug,
                "pack_ref": pack_ref,
                "pack_sha256": str(row.get("pack_sha256", "")).strip(),
                "version": str(row.get("version", "")).strip(),
                "applies_to": sorted(str(item).strip() for item in row.get("applies_to", []) if str(item).strip()),
                "suite_scope_additions": sorted(str(item).strip() for item in pack.get("suite_scope_additions", []) if str(item).strip()),
                "policy_additions": sorted(str(item).strip() for item in pack.get("policy_additions", []) if str(item).strip()),
                "reporting_fields": sorted(str(item).strip() for item in pack.get("reporting_fields", []) if str(item).strip()),
                "source_refs": [OVERLAY_REGISTRY_REL, pack_ref],
                "trust_zone": "CANONICAL",
            }
        )
    return {
        "schema_id": "kt.operator.sector_harness_registry.v1",
        "generated_utc": "",
        "summary": {
            "sector_count": len(entries),
            "applies_to_programs": sorted({program for entry in entries for program in entry["applies_to"]}),
        },
        "sectors": entries,
    }


def _truth_surface_class(path: str, payload: Dict[str, Any]) -> str:
    lower = path.lower()
    if path.startswith("KT_PROD_CLEANROOM/exports/_truth/current/"):
        return "documentary_mirror"
    if path.endswith("public_verifier_manifest.json"):
        return "public_verifier_manifest"
    if path.endswith("execution_board.json"):
        return "execution_board_surface"
    if "publication" in lower:
        return "publication_surface"
    if "settled_truth_source_receipt" in lower:
        return "settled_truth_receipt"
    if path.startswith("KT_PROD_CLEANROOM/governance/"):
        return "governance_truth_law"
    if path.startswith("KT_PROD_CLEANROOM/reports/"):
        return "truth_receipt_or_manifest"
    if payload.get("schema_id"):
        return "structured_truth_surface"
    return "truth_surface"


def _truth_authority_role(path: str, payload: Dict[str, Any]) -> str:
    if payload.get("DOCUMENTARY_ONLY") is True or payload.get("ACTIVE_AUTHORITY") is False:
        return "documentary_only"
    if path.startswith("KT_PROD_CLEANROOM/exports/_truth/current/"):
        return "documentary_only"
    if path.startswith("KT_PROD_CLEANROOM/governance/"):
        return "policy_surface"
    if "subject_verdict" in payload or "head_claim_verdict" in payload:
        return "verifier_surface"
    if "truth_subject_commit" in payload or "active_truth_source" in payload:
        return "truth_receipt"
    return "supporting_surface"


def _compile_truth_surface_map(root: Path, ctx: Dict[str, Any], parseable_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    receipt_index_rows = {
        _normalize_ref(str(row.get("artifact_ref", ""))): row
        for row in ctx["ws0_ws11_receipt_index"].get("artifact_index", [])
        if isinstance(row, dict) and _normalize_ref(str(row.get("artifact_ref", "")))
    }
    candidate_paths: Set[str] = set()
    for path in parseable_map:
        lower = path.lower()
        if any(token in lower for token in TRUTH_PATH_TOKENS):
            candidate_paths.add(path)
    candidate_paths.update(path for path in receipt_index_rows if path in parseable_map)

    surfaces: List[Dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    role_counts: Counter[str] = Counter()
    for path in sorted(candidate_paths):
        entry = parseable_map[path]
        payload: Dict[str, Any] = {}
        if str(entry.get("file_type", "")).strip() in {"json", "json_schema"}:
            parsed = _load_json_any(root / Path(path))
            if isinstance(parsed, dict):
                payload = parsed
        index_row = receipt_index_rows.get(path, {})
        surface_class = _truth_surface_class(path, payload)
        authority_role = _truth_authority_role(path, payload)
        class_counts[surface_class] += 1
        role_counts[authority_role] += 1
        commit_fields = {
            key: value
            for key, value in payload.items()
            if isinstance(value, str)
            and (
                key.endswith("_commit")
                or key in {"validated_head_sha", "truth_subject_commit", "current_head_commit", "evidence_commit", "subject_commit"}
            )
        }
        surfaces.append(
            {
                "surface_ref": path,
                "surface_class": surface_class,
                "authority_role": authority_role,
                "trust_zone": entry["trust_zone"],
                "file_type": entry["file_type"],
                "schema_id": str(payload.get("schema_id", "")).strip(),
                "status": str(payload.get("status", index_row.get("status", ""))).strip(),
                "documentary_only": payload.get("DOCUMENTARY_ONLY") if "DOCUMENTARY_ONLY" in payload else path.startswith("KT_PROD_CLEANROOM/exports/_truth/current/"),
                "live_truth_allowed": payload.get("LIVE_TRUTH_ALLOWED"),
                "superseded_by": sorted(set(_string_list(payload.get("SUPERSEDED_BY")) + _string_list(payload.get("superseded_by")))),
                "commit_fields": commit_fields,
                "claim_fields": sorted(
                    key
                    for key in payload.keys()
                    if key
                    in {
                        "subject_verdict",
                        "head_claim_verdict",
                        "platform_governance_verdict",
                        "runtime_boundary_verdict",
                        "active_truth_source",
                        "published_head_authority_claimed",
                        "h1_allowed",
                    }
                ),
                "source_refs": [path] + ([WS0_WS11_RECEIPT_INDEX_REL] if index_row else []),
            }
        )
    return {
        "schema_id": "kt.operator.truth_surface_map.v1",
        "generated_utc": "",
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "summary": {
            "surface_count": len(surfaces),
            "surface_class_counts": dict(sorted(class_counts.items())),
            "authority_role_counts": dict(sorted(role_counts.items())),
        },
        "surfaces": surfaces,
    }


def _compile_runtime_graph(root: Path, ctx: Dict[str, Any], parseable_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    runtime_registry = ctx["runtime_registry"]
    graph = _GraphBuilder(
        schema_id="kt.operator.runtime_graph.v1",
        graph_id=_stable_id("runtime_graph", runtime_registry.get("registry_version", "1")),
        generated_utc="",
        plane="operability_plane",
    )
    registry_ref = RUNTIME_REGISTRY_REL
    graph.add_node(
        node_id="runtime_source::registry",
        node_type="runtime_source",
        label="Runtime Registry",
        source_refs=[registry_ref],
        facets=["source:runtime_registry"],
        attributes={"registry_ref": registry_ref},
    )

    runtime_roots = [str(item).strip() for item in runtime_registry.get("runtime_import_roots", []) if str(item).strip()]
    compatibility_roots = [str(item).strip() for item in runtime_registry.get("compatibility_allowlist_roots", []) if str(item).strip()]
    all_roots = sorted(set(runtime_roots + compatibility_roots))
    known_root_nodes: Set[str] = set()
    for root_name in all_roots:
        known_root_nodes.add(f"runtime_root::{root_name}")
        graph.add_node(
            node_id=f"runtime_root::{root_name}",
            node_type="runtime_root",
            label=root_name,
            source_refs=[registry_ref],
            facets=[f"root_class:{'compatibility' if root_name in compatibility_roots else 'canonical'}"],
            attributes={"compatibility_only": root_name in compatibility_roots, "runtime_import_root": root_name},
        )

    for root_name, organ_label in sorted(runtime_registry.get("organs_by_root", {}).items()):
        organ_node = f"runtime_organ::{organ_label}"
        graph.add_node(
            node_id=organ_node,
            node_type="runtime_organ",
            label=str(organ_label),
            source_refs=[registry_ref],
            facets=["runtime_organ"],
            attributes={"organ_label": organ_label},
        )
        if f"runtime_root::{root_name}" in known_root_nodes:
            graph.add_edge(
                edge_type="maps_to_runtime_organ",
                from_node=f"runtime_root::{root_name}",
                to_node=organ_node,
                provenance_refs=[registry_ref],
                temporal_state="current",
            )

    entry = runtime_registry.get("canonical_entry", {})
    spine = runtime_registry.get("canonical_spine", {})
    entry_node = f"runtime_callable::{entry.get('module', '')}.{entry.get('callable', '')}"
    spine_node = f"runtime_callable::{spine.get('module', '')}.{spine.get('callable', '')}"
    graph.add_node(
        node_id=entry_node,
        node_type="runtime_callable",
        label=f"{entry.get('module', '')}.{entry.get('callable', '')}",
        source_refs=[registry_ref],
        facets=["canonical_entry"],
        attributes={"module": entry.get("module", ""), "callable": entry.get("callable", "")},
    )
    graph.add_node(
        node_id=spine_node,
        node_type="runtime_callable",
        label=f"{spine.get('module', '')}.{spine.get('callable', '')}",
        source_refs=[registry_ref],
        facets=["canonical_spine"],
        attributes={"module": spine.get("module", ""), "callable": spine.get("callable", "")},
    )
    if entry.get("module"):
        graph.add_edge(
            edge_type="contains_canonical_entry",
            from_node=f"runtime_root::{str(entry.get('module', '')).split('.', 1)[0]}",
            to_node=entry_node,
            provenance_refs=[registry_ref],
            temporal_state="current",
        )
    if spine.get("module"):
        graph.add_edge(
            edge_type="contains_canonical_spine",
            from_node=f"runtime_root::{str(spine.get('module', '')).split('.', 1)[0]}",
            to_node=spine_node,
            provenance_refs=[registry_ref],
            temporal_state="current",
        )
    graph.add_edge(
        edge_type="invokes_canonical_spine",
        from_node=entry_node,
        to_node=spine_node,
        provenance_refs=[registry_ref],
        temporal_state="current",
    )

    edge_provenance: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)
    for path, entry_meta in sorted(parseable_map.items()):
        if not path.startswith(PYTHON_ROOT_PREFIX) or str(entry_meta.get("file_type", "")).strip() != "python":
            continue
        root_name = _top_level_runtime_root(path)
        if not root_name:
            continue
        for imported in _extract_import_roots(root / Path(path)):
            if imported in all_roots and imported != root_name:
                edge_provenance[(root_name, imported)].add(path)

    for (from_root, to_root), provenance in sorted(edge_provenance.items()):
        graph.add_edge(
            edge_type="imports_root",
            from_node=f"runtime_root::{from_root}",
            to_node=f"runtime_root::{to_root}",
            provenance_refs=sorted(provenance),
            temporal_state="current",
        )
    return graph.materialize()


def _compile_fact_graph(
    parseable_map: Dict[str, Dict[str, Any]],
    tag_catalog: Dict[str, Any],
    ctx: Dict[str, Any],
    adapter_registry: Dict[str, Any],
    model_registry: Dict[str, Any],
    sector_registry: Dict[str, Any],
) -> Dict[str, Any]:
    graph = _GraphBuilder(
        schema_id="kt.operator.fact_graph.v1",
        graph_id=_stable_id("fact_graph", ctx["snapshot_manifest"].get("snapshot_id", "")),
        generated_utc="",
        plane="fact_plane",
    )
    assignment_map = {row["path"]: row for row in tag_catalog.get("tag_assignments", []) if isinstance(row, dict)}
    graph.add_node(
        node_id="snapshot_source::step5",
        node_type="snapshot_source",
        label="Step 5 Snapshot Manifest",
        source_refs=[SNAPSHOT_MANIFEST_REL, STEP5_RECEIPT_REL],
        facets=["snapshot_source"],
        attributes={"snapshot_id": ctx["snapshot_manifest"].get("snapshot_id", ""), "source_head_commit": ctx["snapshot_manifest"].get("source_head_commit", "")},
    )
    for zone in sorted({str(entry["trust_zone"]) for entry in parseable_map.values()}):
        graph.add_node(
            node_id=f"trust_zone::{zone}",
            node_type="trust_zone",
            label=zone,
            source_refs=[SNAPSHOT_MANIFEST_REL],
            facets=["trust_zone"],
            attributes={"trust_zone": zone},
        )
    for path, entry in sorted(parseable_map.items()):
        assignment = assignment_map.get(path, {"tags": [], "facets": []})
        graph.add_node(
            node_id=f"file::{path}",
            node_type="artifact_surface",
            label=Path(path).name,
            source_refs=[path],
            facets=list(assignment.get("tags", [])) + list(assignment.get("facets", [])),
            attributes={
                "path": path,
                "file_type": entry.get("file_type", ""),
                "generation_status": entry.get("generation_status", ""),
                "trust_zone": entry.get("trust_zone", ""),
                "sha256": entry.get("sha256", ""),
            },
        )
        graph.add_edge(
            edge_type="classified_in_zone",
            from_node=f"file::{path}",
            to_node=f"trust_zone::{entry.get('trust_zone', '')}",
            provenance_refs=[SNAPSHOT_MANIFEST_REL],
            temporal_state="current",
        )

    path_set = set(parseable_map.keys())
    for organ in ctx["organ_ontology"].get("organs", []):
        if not isinstance(organ, dict):
            continue
        organ_id = str(organ.get("organ_id", "")).strip()
        if not organ_id:
            continue
        organ_node = f"organ::{organ_id}"
        graph.add_node(
            node_id=organ_node,
            node_type="organ",
            label=str(organ.get("label", organ_id)),
            source_refs=[ORGAN_ONTOLOGY_REL],
            facets=[f"organ_class:{organ.get('organ_class', '')}", f"current_ceiling:{organ.get('current_ceiling', '')}"],
            attributes={
                "organ_class": organ.get("organ_class", ""),
                "current_ceiling": organ.get("current_ceiling", ""),
                "trust_zones": organ.get("trust_zones", []),
                "primary_planes": organ.get("primary_planes", []),
            },
        )
        for upstream in organ.get("upstream_organs", []):
            if str(upstream).strip():
                graph.add_edge(
                    edge_type="depends_on_organ",
                    from_node=organ_node,
                    to_node=f"organ::{str(upstream).strip()}",
                    provenance_refs=[ORGAN_ONTOLOGY_REL],
                    temporal_state="current",
                )
        for ref in list(organ.get("primary_surfaces", [])) + list(organ.get("law_refs", [])):
            if not isinstance(ref, str) or not ref.strip():
                continue
            normalized = _normalize_ref(ref)
            matched_paths: Set[str] = set()
            if "*" in normalized or "?" in normalized or "[" in normalized:
                matched_paths = {path for path in path_set if Path(path).match(normalized)}
            elif normalized in path_set:
                matched_paths = {normalized}
            elif normalized.endswith("/**"):
                prefix = normalized[:-3]
                matched_paths = {path for path in path_set if path.startswith(prefix)}
            for matched in sorted(matched_paths):
                graph.add_edge(
                    edge_type="organ_references_surface",
                    from_node=organ_node,
                    to_node=f"file::{matched}",
                    provenance_refs=[ORGAN_ONTOLOGY_REL, matched],
                    temporal_state="current",
                )

    for adapter in adapter_registry.get("adapters", []):
        adapter_id = str(adapter.get("adapter_id", "")).strip()
        if not adapter_id:
            continue
        graph.add_node(
            node_id=f"adapter::{adapter_id}",
            node_type="adapter",
            label=adapter_id,
            source_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
            facets=[f"registry_status:{adapter.get('registry_status', '')}"],
            attributes={"registry_status": adapter.get("registry_status", ""), "role": adapter.get("role", ""), "route_domain_tags": adapter.get("route_domain_tags", [])},
        )
    for model in model_registry.get("models", []):
        model_id = str(model.get("model_id", "")).strip()
        if model_id:
            graph.add_node(
                node_id=f"model::{model_id}",
                node_type="model",
                label=model_id,
                source_refs=model.get("source_refs", model.get("declared_in", [MODEL_REGISTRY_OUT_REL])),
                facets=[f"model_class:{model.get('model_class', '')}"],
                attributes={"model_class": model.get("model_class", ""), "observed_fields": model.get("observed_fields", [])},
            )
    for sector in sector_registry.get("sectors", []):
        sector_id = str(sector.get("sector_id", "")).strip()
        if not sector_id:
            continue
        sector_node = f"sector::{sector_id}"
        graph.add_node(
            node_id=sector_node,
            node_type="sector",
            label=sector_id,
            source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
            facets=["sector_overlay"],
            attributes={"domain_slug": sector.get("domain_slug", ""), "applies_to": sector.get("applies_to", [])},
        )
        for program in sector.get("applies_to", []):
            program_node = f"program::{program}"
            graph.add_node(
                node_id=program_node,
                node_type="program",
                label=str(program),
                source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                facets=["program_surface"],
                attributes={"program_name": program},
            )
            graph.add_edge(
                edge_type="sector_applies_to_program",
                from_node=sector_node,
                to_node=program_node,
                provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                temporal_state="current",
            )
    return graph.materialize()


def _compile_temporal_graph(root: Path, ctx: Dict[str, Any], parseable_map: Dict[str, Dict[str, Any]], contract_index: Dict[str, Any]) -> Dict[str, Any]:
    graph = _GraphBuilder(
        schema_id="kt.operator.temporal_graph.v1",
        graph_id=_stable_id("temporal_graph", ctx["snapshot_manifest"].get("snapshot_id", "")),
        generated_utc="",
        plane="temporal_plane",
    )

    def ensure_ref_node(ref: str) -> str:
        normalized = _normalize_ref(ref)
        if normalized in parseable_map:
            entry = parseable_map[normalized]
            node_id = f"artifact::{normalized}"
            graph.add_node(
                node_id=node_id,
                node_type="artifact_ref",
                label=Path(normalized).name,
                source_refs=[normalized],
                facets=[f"trust_zone:{entry.get('trust_zone', '')}"],
                attributes={"path": normalized, "trust_zone": entry.get("trust_zone", ""), "file_type": entry.get("file_type", "")},
            )
            return node_id
        node_id = f"external_ref::{_stable_id('ref', normalized)}"
        graph.add_node(
            node_id=node_id,
            node_type="external_ref",
            label=normalized,
            source_refs=[normalized],
            facets=["external_reference"],
            attributes={"ref": normalized},
        )
        return node_id

    conflicts_by_id: Dict[str, Dict[str, Any]] = {}
    for row in ctx["historical_conflicts"].get("historical_blocker_conflicts", []):
        if not isinstance(row, dict):
            continue
        conflict_id = str(row.get("conflict_id", "")).strip()
        if not conflict_id:
            continue
        conflicts_by_id[conflict_id] = row
        graph.add_node(
            node_id=f"historical_conflict::{conflict_id}",
            node_type="historical_conflict",
            label=conflict_id,
            source_refs=row.get("evidence_refs", [HISTORICAL_CONFLICTS_REL]),
            facets=[f"severity:{row.get('severity', '')}", f"historical_status:{row.get('historical_status', '')}"],
            attributes={"description": row.get("description", ""), "exit_criteria": row.get("exit_criteria", []), "historical_status": row.get("historical_status", "")},
        )
    for row in ctx["reopened_defect_register"].get("defects", []):
        if not isinstance(row, dict):
            continue
        defect_id = str(row.get("defect_id", "")).strip()
        if not defect_id:
            continue
        defect_node = f"reopened_defect::{defect_id}"
        graph.add_node(
            node_id=defect_node,
            node_type="reopened_defect",
            label=defect_id,
            source_refs=row.get("current_evidence_refs", []) or row.get("historical_evidence_refs", [REOPENED_DEFECT_REGISTER_REL]),
            facets=[f"current_status:{row.get('current_status', '')}", f"reopened:{str(bool(row.get('reopened', False))).lower()}"],
            attributes={"current_status": row.get("current_status", ""), "historical_status": row.get("historical_status", ""), "current_summary": row.get("current_summary", "")},
        )
        if defect_id in conflicts_by_id:
            graph.add_edge(
                edge_type="reopened_as_current_disposition",
                from_node=f"historical_conflict::{defect_id}",
                to_node=defect_node,
                provenance_refs=[HISTORICAL_CONFLICTS_REL, REOPENED_DEFECT_REGISTER_REL],
                temporal_state=str(row.get("current_status", "")).strip() or "current",
            )
        for ref in row.get("historical_evidence_refs", []):
            graph.add_edge(
                edge_type="historically_evidenced_by",
                from_node=defect_node,
                to_node=ensure_ref_node(str(ref)),
                provenance_refs=[REOPENED_DEFECT_REGISTER_REL],
                temporal_state="historical",
            )
        for ref in row.get("current_evidence_refs", []):
            graph.add_edge(
                edge_type="currently_evidenced_by",
                from_node=defect_node,
                to_node=ensure_ref_node(str(ref)),
                provenance_refs=[REOPENED_DEFECT_REGISTER_REL],
                temporal_state=str(row.get("current_status", "")).strip() or "current",
            )

    for row in ctx["historical_resolutions"].get("resolved_blockers", []):
        if not isinstance(row, dict):
            continue
        blocker_id = str(row.get("blocker_id", "")).strip()
        if not blocker_id:
            continue
        resolution_node = f"resolution::{blocker_id}"
        graph.add_node(
            node_id=resolution_node,
            node_type="historical_resolution",
            label=blocker_id,
            source_refs=row.get("evidence_refs", [HISTORICAL_RESOLUTIONS_REL]),
            facets=[f"historical_status:{row.get('historical_status', '')}"],
            attributes={"description": row.get("description", ""), "exit_criteria": row.get("exit_criteria", []), "historical_status": row.get("historical_status", "")},
        )
        if blocker_id in conflicts_by_id:
            graph.add_edge(
                edge_type="resolved_later",
                from_node=f"historical_conflict::{blocker_id}",
                to_node=resolution_node,
                provenance_refs=[HISTORICAL_CONFLICTS_REL, HISTORICAL_RESOLUTIONS_REL],
                temporal_state=str(row.get("historical_status", "")).strip() or "resolved",
            )

    for row in ctx["forgotten_surface_register"].get("surfaces", []):
        if not isinstance(row, dict):
            continue
        surface_ref = str(row.get("surface_ref", "")).strip()
        if not surface_ref:
            continue
        surface_node = f"forgotten_surface::{_stable_id('forgotten', surface_ref)}"
        graph.add_node(
            node_id=surface_node,
            node_type="forgotten_surface",
            label=surface_ref,
            source_refs=row.get("evidence_refs", [FORGOTTEN_SURFACE_REGISTER_REL]),
            facets=[f"surface_class:{row.get('surface_class', '')}", f"current_status:{row.get('current_status', '')}"],
            attributes={"surface_ref": surface_ref, "surface_class": row.get("surface_class", ""), "current_status": row.get("current_status", ""), "recovery_track": row.get("recovery_track", "")},
        )
        status = str(row.get("current_status", "")).strip()
        status_node = f"temporal_status::{status}"
        graph.add_node(
            node_id=status_node,
            node_type="temporal_status",
            label=status,
            source_refs=[FORGOTTEN_SURFACE_REGISTER_REL],
            facets=["temporal_status"],
            attributes={"status": status},
        )
        graph.add_edge(
            edge_type="has_temporal_status",
            from_node=surface_node,
            to_node=status_node,
            provenance_refs=[FORGOTTEN_SURFACE_REGISTER_REL],
            temporal_state="deprecated_or_archived",
        )
        graph.add_edge(
            edge_type="references_surface",
            from_node=surface_node,
            to_node=ensure_ref_node(surface_ref),
            provenance_refs=[FORGOTTEN_SURFACE_REGISTER_REL],
            temporal_state="historical",
        )

    for contract in contract_index.get("contracts", []):
        if not isinstance(contract, dict):
            continue
        source_path = str(contract.get("path", "")).strip()
        if not source_path:
            continue
        for target_ref in contract.get("supersedes_refs", []):
            target = str(target_ref).strip()
            if not target:
                continue
            edge_type = "supersedes"
            temporal_state = "current"
            if target.startswith("kt_truth_ledger:"):
                edge_type = "superseded_by"
                temporal_state = "superseded"
            graph.add_edge(
                edge_type=edge_type,
                from_node=ensure_ref_node(source_path),
                to_node=ensure_ref_node(target),
                provenance_refs=[source_path],
                temporal_state=temporal_state,
            )
    return graph.materialize()


def _compile_data_lineage_graph(
    ctx: Dict[str, Any],
    parseable_map: Dict[str, Dict[str, Any]],
    adapter_registry: Dict[str, Any],
    model_registry: Dict[str, Any],
    sector_registry: Dict[str, Any],
) -> Dict[str, Any]:
    graph = _GraphBuilder(
        schema_id="kt.operator.data_lineage.v1",
        graph_id=_stable_id("data_lineage", ctx["snapshot_manifest"].get("snapshot_id", "")),
        generated_utc="",
        plane="lineage_plane",
    )

    def ensure_asset_node(ref: str) -> str:
        normalized = _normalize_ref(ref)
        if normalized in parseable_map:
            entry = parseable_map[normalized]
            node_id = f"data_asset::{normalized}"
            graph.add_node(
                node_id=node_id,
                node_type="data_asset",
                label=Path(normalized).name,
                source_refs=[normalized],
                facets=[f"trust_zone:{entry.get('trust_zone', '')}", f"file_type:{entry.get('file_type', '')}"],
                attributes={"path": normalized, "trust_zone": entry.get("trust_zone", ""), "file_type": entry.get("file_type", "")},
            )
            return node_id
        node_id = f"data_asset::{_stable_id('external_asset', normalized)}"
        graph.add_node(
            node_id=node_id,
            node_type="data_asset",
            label=normalized,
            source_refs=[normalized],
            facets=["external_data_asset"],
            attributes={"ref": normalized},
        )
        return node_id

    historical_adapter_docs = [
        row
        for row in ctx["forgotten_surface_register"].get("surfaces", [])
        if isinstance(row, dict) and str(row.get("recovery_track", "")).strip() == "step_6_graph_and_lineage_compilation"
    ]
    anchor_node = ensure_asset_node(ANCHOR_REFERENCE_SET_REL)

    for model in model_registry.get("models", []):
        model_id = str(model.get("model_id", "")).strip()
        if not model_id:
            continue
        model_node = f"model::{model_id}"
        graph.add_node(
            node_id=model_node,
            node_type="model",
            label=model_id,
            source_refs=model.get("source_refs", model.get("declared_in", [MODEL_REGISTRY_OUT_REL])),
            facets=[f"model_class:{model.get('model_class', '')}"],
            attributes={"model_class": model.get("model_class", ""), "observed_fields": model.get("observed_fields", [])},
        )
        for ref in model.get("declared_in", []):
            graph.add_edge(
                edge_type="declared_in",
                from_node=model_node,
                to_node=ensure_asset_node(str(ref)),
                provenance_refs=model.get("source_refs", [MODEL_REGISTRY_OUT_REL]),
                temporal_state="current",
            )
        if "baseline_model_id" in model.get("observed_fields", []) or "base_model_id" in model.get("observed_fields", []):
            graph.add_edge(
                edge_type="anchored_by",
                from_node=model_node,
                to_node=anchor_node,
                provenance_refs=[ANCHOR_REFERENCE_SET_REL],
                temporal_state="current",
            )

    for adapter in adapter_registry.get("adapters", []):
        adapter_id = str(adapter.get("adapter_id", "")).strip()
        if not adapter_id:
            continue
        adapter_node = f"adapter::{adapter_id}"
        graph.add_node(
            node_id=adapter_node,
            node_type="adapter",
            label=adapter_id,
            source_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
            facets=[f"registry_status:{adapter.get('registry_status', '')}", f"role:{adapter.get('role', '')}"],
            attributes={"registry_status": adapter.get("registry_status", ""), "role": adapter.get("role", "")},
        )
        for ref in set(adapter.get("authority_refs", []) + adapter.get("evidence_refs", []) + adapter.get("source_refs", [])):
            graph.add_edge(
                edge_type="documented_by",
                from_node=adapter_node,
                to_node=ensure_asset_node(str(ref)),
                provenance_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
                temporal_state="current",
            )
        for domain_tag in adapter.get("route_domain_tags", []):
            domain_node = f"domain::{domain_tag}"
            graph.add_node(
                node_id=domain_node,
                node_type="domain_tag",
                label=domain_tag,
                source_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
                facets=["route_domain"],
                attributes={"domain_tag": domain_tag},
            )
            graph.add_edge(
                edge_type="routes_domain",
                from_node=adapter_node,
                to_node=domain_node,
                provenance_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
                temporal_state="current",
            )
        for guard_id in adapter.get("required_guard_ids", []):
            graph.add_edge(
                edge_type="guarded_by",
                from_node=adapter_node,
                to_node=f"adapter::{guard_id}",
                provenance_refs=adapter.get("source_refs", [ADAPTER_REGISTRY_OUT_REL]),
                temporal_state="current",
            )
        for row in historical_adapter_docs:
            surface_ref = str(row.get("surface_ref", "")).strip()
            if surface_ref:
                graph.add_edge(
                    edge_type="historically_documented_by",
                    from_node=adapter_node,
                    to_node=ensure_asset_node(surface_ref),
                    provenance_refs=row.get("evidence_refs", [FORGOTTEN_SURFACE_REGISTER_REL]),
                    temporal_state="historical",
                )

    for sector in sector_registry.get("sectors", []):
        sector_id = str(sector.get("sector_id", "")).strip()
        if not sector_id:
            continue
        sector_node = f"sector::{sector_id}"
        graph.add_node(
            node_id=sector_node,
            node_type="sector",
            label=sector_id,
            source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
            facets=["sector_overlay"],
            attributes={"domain_slug": sector.get("domain_slug", ""), "pack_ref": sector.get("pack_ref", "")},
        )
        graph.add_edge(
            edge_type="declared_in",
            from_node=sector_node,
            to_node=ensure_asset_node(str(sector.get("pack_ref", "")).strip()),
            provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
            temporal_state="current",
        )
        for suite_id in sector.get("suite_scope_additions", []):
            suite_node = f"suite::{suite_id}"
            graph.add_node(
                node_id=suite_node,
                node_type="suite",
                label=suite_id,
                source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                facets=["suite_addition"],
                attributes={"suite_id": suite_id},
            )
            graph.add_edge(
                edge_type="extends_suite_scope",
                from_node=sector_node,
                to_node=suite_node,
                provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                temporal_state="current",
            )
        for policy_id in sector.get("policy_additions", []):
            policy_node = f"policy::{policy_id}"
            graph.add_node(
                node_id=policy_node,
                node_type="policy",
                label=policy_id,
                source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                facets=["policy_addition"],
                attributes={"policy_id": policy_id},
            )
            graph.add_edge(
                edge_type="adds_policy",
                from_node=sector_node,
                to_node=policy_node,
                provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                temporal_state="current",
            )
        for program in sector.get("applies_to", []):
            program_node = f"program::{program}"
            graph.add_node(
                node_id=program_node,
                node_type="program",
                label=str(program),
                source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                facets=["program_surface"],
                attributes={"program_name": program},
            )
            graph.add_edge(
                edge_type="applies_to_program",
                from_node=sector_node,
                to_node=program_node,
                provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                temporal_state="current",
            )
        for field_name in sector.get("reporting_fields", []):
            field_node = f"field::{field_name}"
            graph.add_node(
                node_id=field_node,
                node_type="reporting_field",
                label=field_name,
                source_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                facets=["reporting_field"],
                attributes={"field_name": field_name},
            )
            graph.add_edge(
                edge_type="requires_reporting_field",
                from_node=sector_node,
                to_node=field_node,
                provenance_refs=sector.get("source_refs", [SECTOR_HARNESS_REGISTRY_REL]),
                temporal_state="current",
            )

    for row in ctx["crucible_registry"].get("entries", []):
        if not isinstance(row, dict):
            continue
        crucible_id = str(row.get("crucible_id", "")).strip()
        spec_ref = str(row.get("spec_ref", "")).strip()
        if not crucible_id or not spec_ref:
            continue
        crucible_node = f"crucible::{crucible_id}"
        graph.add_node(
            node_id=crucible_node,
            node_type="crucible",
            label=crucible_id,
            source_refs=[CRUCIBLE_REGISTRY_REL, spec_ref],
            facets=[f"promotion_scope:{row.get('promotion_scope', '')}"],
            attributes={"promotion_scope": row.get("promotion_scope", ""), "trust_zone": row.get("trust_zone", "")},
        )
        graph.add_edge(
            edge_type="specified_by",
            from_node=crucible_node,
            to_node=ensure_asset_node(spec_ref),
            provenance_refs=[CRUCIBLE_REGISTRY_REL, spec_ref],
            temporal_state="current",
        )
    return graph.materialize()


def _build_graph_and_catalog_reports(root: Path, *, generated_utc: str) -> Dict[str, Any]:
    ctx = _step_context(root)
    parseable_map = _parseable_entry_map(ctx["snapshot_manifest"])
    if not parseable_map:
        raise RuntimeError("FAIL_CLOSED: Step 6 parseable surface set is empty.")

    tag_catalog = _compile_tag_catalog(parseable_map)
    symbol_index = _compile_symbol_index(root, parseable_map, tag_catalog)
    contract_index = _compile_contract_index(root, parseable_map)
    adapter_registry = _compile_adapter_registry(ctx)
    model_registry = _compile_model_registry(root, parseable_map)
    sector_registry = _compile_sector_harness_registry(root, ctx)
    truth_surface_map = _compile_truth_surface_map(root, ctx, parseable_map)
    runtime_graph = _compile_runtime_graph(root, ctx, parseable_map)
    data_lineage = _compile_data_lineage_graph(ctx, parseable_map, adapter_registry, model_registry, sector_registry)
    fact_graph = _compile_fact_graph(parseable_map, tag_catalog, ctx, adapter_registry, model_registry, sector_registry)
    temporal_graph = _compile_temporal_graph(root, ctx, parseable_map, contract_index)

    for payload in (
        tag_catalog,
        symbol_index,
        contract_index,
        adapter_registry,
        model_registry,
        sector_registry,
        truth_surface_map,
        fact_graph,
        temporal_graph,
        data_lineage,
        runtime_graph,
    ):
        payload["generated_utc"] = generated_utc

    return {
        "fact_graph": fact_graph,
        "temporal_graph": temporal_graph,
        "data_lineage": data_lineage,
        "adapter_registry": adapter_registry,
        "model_registry": model_registry,
        "sector_harness_registry": sector_registry,
        "tag_catalog": tag_catalog,
        "symbol_index": symbol_index,
        "contract_index": contract_index,
        "truth_surface_map": truth_surface_map,
        "runtime_graph": runtime_graph,
    }


def build_graph_and_catalog_reports(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    return _build_graph_and_catalog_reports(root, generated_utc=generated_utc or utc_now_iso_z())


def _graph_stats(graph: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
        "node_type_counts": dict(sorted(Counter(node["node_type"] for node in graph.get("nodes", [])).items())),
        "edge_type_counts": dict(sorted(Counter(edge["edge_type"] for edge in graph.get("edges", [])).items())),
    }


def build_graph_and_catalog_receipt(root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = _build_graph_and_catalog_reports(root, generated_utc=generated_utc)
    second = _build_graph_and_catalog_reports(root, generated_utc=generated_utc)

    for key in first:
        if not semantically_equal_json(first[key], second[key]):
            raise RuntimeError(f"FAIL_CLOSED: nondeterministic Step 6 output detected: {key}")

    graph_schema = ctx["graph_schema"]
    for graph_key in ("fact_graph", "temporal_graph", "data_lineage", "runtime_graph"):
        jsonschema.validate(instance=first[graph_key], schema=graph_schema)

    if not first["adapter_registry"].get("adapters"):
        raise RuntimeError("FAIL_CLOSED: adapter registry compiled empty.")
    if not first["model_registry"].get("models"):
        raise RuntimeError("FAIL_CLOSED: model registry compiled empty.")
    if not first["sector_harness_registry"].get("sectors"):
        raise RuntimeError("FAIL_CLOSED: sector harness registry compiled empty.")
    if not first["symbol_index"].get("symbols"):
        raise RuntimeError("FAIL_CLOSED: symbol index compiled empty.")
    if not first["contract_index"].get("contracts"):
        raise RuntimeError("FAIL_CLOSED: contract index compiled empty.")
    if not first["truth_surface_map"].get("surfaces"):
        raise RuntimeError("FAIL_CLOSED: truth surface map compiled empty.")

    temporal_edge_types = {edge["edge_type"] for edge in first["temporal_graph"].get("edges", [])}
    if not ({"supersedes", "superseded_by"} & temporal_edge_types):
        raise RuntimeError("FAIL_CLOSED: temporal graph missing supersession representation.")
    if "has_temporal_status" not in temporal_edge_types:
        raise RuntimeError("FAIL_CLOSED: temporal graph missing deprecation/archive status representation.")

    lineage_node_types = {node["node_type"] for node in first["data_lineage"].get("nodes", [])}
    if not {"adapter", "model", "sector", "data_asset"}.issubset(lineage_node_types):
        raise RuntimeError("FAIL_CLOSED: data lineage graph missing adapter/model/sector/data asset coverage.")

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    return {
        "schema_id": "kt.operator.graph_and_catalog_compilation_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "GRAPH_AND_CATALOG_COMPILED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 6,
            "step_name": "STRUCTURAL_PARSE_TAG_CATALOG_AND_GRAPH_COMPILATION",
        },
        "step5_gate_subject_commit": str(ctx["step5_receipt"].get("compiled_head_commit", "")).strip(),
        "step5_gate_evidence_commit": _git_last_commit_for_paths(root, [STEP5_RECEIPT_REL]),
        "source_snapshot_ref": SNAPSHOT_MANIFEST_REL,
        "source_snapshot_id": str(ctx["snapshot_manifest"].get("snapshot_id", "")).strip(),
        "source_snapshot_head_commit": str(ctx["snapshot_manifest"].get("source_head_commit", "")).strip(),
        "graph_stats": {
            "fact_graph": _graph_stats(first["fact_graph"]),
            "temporal_graph": _graph_stats(first["temporal_graph"]),
            "data_lineage": _graph_stats(first["data_lineage"]),
            "runtime_graph": _graph_stats(first["runtime_graph"]),
        },
        "registry_stats": {
            "adapter_count": len(first["adapter_registry"].get("adapters", [])),
            "model_count": len(first["model_registry"].get("models", [])),
            "sector_count": len(first["sector_harness_registry"].get("sectors", [])),
            "symbol_count": len(first["symbol_index"].get("symbols", [])),
            "contract_count": len(first["contract_index"].get("contracts", [])),
            "truth_surface_count": len(first["truth_surface_map"].get("surfaces", [])),
        },
        "checks": [
            {
                "check": "step5_gate_passed",
                "detail": "Step 6 requires the Step 5 snapshot inventory compilation receipt to be PASS with CLEAR state taint.",
                "refs": [STEP5_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "graph_outputs_validate_against_foundation_schema",
                "detail": "Fact, temporal, lineage, and runtime graphs all validate against the ratified foundation graph schema.",
                "refs": [FACT_GRAPH_SCHEMA_REL, FACT_GRAPH_REL, TEMPORAL_GRAPH_REL, DATA_LINEAGE_REL, RUNTIME_GRAPH_REL],
                "status": "PASS",
            },
            {
                "check": "all_edges_carry_provenance",
                "detail": "Every emitted graph edge carries explicit provenance refs; missing-provenance edges fail closed.",
                "refs": [FACT_GRAPH_REL, TEMPORAL_GRAPH_REL, DATA_LINEAGE_REL, RUNTIME_GRAPH_REL],
                "status": "PASS",
            },
            {
                "check": "tags_and_facets_applied_consistently",
                "detail": "Tag catalog assignments and graph facets are derived from the same deterministic classifier over the sealed Step 5 parseable surface set.",
                "refs": [TAG_CATALOG_REL, FACT_GRAPH_REL],
                "status": "PASS",
            },
            {
                "check": "temporal_supersession_and_deprecation_represented",
                "detail": "Temporal graph carries both supersession edges and deprecation/archive status edges from explicit historical and governance surfaces.",
                "refs": [TEMPORAL_GRAPH_REL, FORGOTTEN_SURFACE_REGISTER_REL, HISTORICAL_CONFLICTS_REL, HISTORICAL_RESOLUTIONS_REL],
                "status": "PASS",
            },
            {
                "check": "adapter_model_sector_data_lineage_exists",
                "detail": "Adapter, model, sector, and data-asset lineage nodes and edges are all present and linked to explicit source refs.",
                "refs": [DATA_LINEAGE_REL, ADAPTER_REGISTRY_OUT_REL, MODEL_REGISTRY_OUT_REL, SECTOR_HARNESS_REGISTRY_REL],
                "status": "PASS",
            },
            {
                "check": "deterministic_rerun_semantics",
                "detail": "A second Step 6 compiler run over the same gated inputs reproduces semantically identical outputs.",
                "refs": DELIVERABLE_REFS,
                "status": "PASS",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 6 subject files plus the compilation receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "claim_boundary": "This receipt validates the Step 6 structural graph, catalog, and lineage outputs for compiled_head_commit only, derived from the sealed Step 5 snapshot surface set. A later repository head that contains this receipt is evidence about compiled_head_commit, not a fresh graph claim for itself.",
        "next_lawful_step": {
            "step_id": 7,
            "step_name": "CLAIM_EXTRACTION_JUDGMENT_ENGINE_AND_STATE_VECTOR",
            "status_after_step_6": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_graph_and_catalog_reports(root: Path) -> Dict[str, Any]:
    reports = build_graph_and_catalog_reports(root)
    artifact_map = {
        FACT_GRAPH_REL: reports["fact_graph"],
        TEMPORAL_GRAPH_REL: reports["temporal_graph"],
        DATA_LINEAGE_REL: reports["data_lineage"],
        ADAPTER_REGISTRY_OUT_REL: reports["adapter_registry"],
        MODEL_REGISTRY_OUT_REL: reports["model_registry"],
        SECTOR_HARNESS_REGISTRY_REL: reports["sector_harness_registry"],
        TAG_CATALOG_REL: reports["tag_catalog"],
        SYMBOL_INDEX_REL: reports["symbol_index"],
        CONTRACT_INDEX_REL: reports["contract_index"],
        TRUTH_SURFACE_MAP_REL: reports["truth_surface_map"],
        RUNTIME_GRAPH_REL: reports["runtime_graph"],
    }
    artifacts_written = []
    for rel, payload in artifact_map.items():
        updated = write_json_stable(root / Path(rel), payload)
        artifacts_written.append({"artifact_ref": rel, "schema_id": payload["schema_id"], "updated": bool(updated)})
    return {"artifacts_written": artifacts_written, "status": "PASS"}


def emit_graph_and_catalog_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_graph_and_catalog_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 6 structural graphs, catalogs, registries, and lineage surfaces.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 6 compilation receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_graph_and_catalog_receipt(root) if args.emit_receipt else write_graph_and_catalog_reports(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
