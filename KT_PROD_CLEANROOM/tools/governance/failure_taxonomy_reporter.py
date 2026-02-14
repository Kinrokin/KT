from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from schemas.schema_registry import validate_object_with_binding
from tools.verification.fl3_canonical import repo_root_from


class FailureTaxonomyError(RuntimeError):
    pass


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FailureTaxonomyError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FailureTaxonomyError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def load_failure_taxonomy(*, repo_root: Path, relpath: str = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json") -> Dict[str, Any]:
    path = (repo_root / relpath).resolve()
    obj = _read_json_dict(path, name="failure_taxonomy")
    validate_object_with_binding(obj)
    if obj.get("schema_id") != "kt.failure_taxonomy.v1":
        raise FailureTaxonomyError("FAIL_CLOSED: failure taxonomy schema_id mismatch")
    return obj


def summarize_reason_codes(*, taxonomy: Dict[str, Any], reason_codes: List[str]) -> Dict[str, Any]:
    mappings = taxonomy.get("mappings") if isinstance(taxonomy.get("mappings"), list) else []
    rc_to_cat = {str(m.get("reason_code")): str(m.get("category_id")) for m in mappings if isinstance(m, dict)}
    categories = taxonomy.get("categories") if isinstance(taxonomy.get("categories"), list) else []
    cat_title = {str(c.get("category_id")): str(c.get("title")) for c in categories if isinstance(c, dict)}

    counts: Dict[str, int] = {}
    unknown: List[str] = []
    for rc in reason_codes:
        r = str(rc).strip()
        if not r:
            continue
        cat = rc_to_cat.get(r)
        if not cat:
            unknown.append(r)
            continue
        counts[cat] = counts.get(cat, 0) + 1

    summary = {
        "status": "PASS" if not unknown else "FAIL",
        "unknown_reason_codes": sorted(set(unknown)),
        "category_counts": {k: counts[k] for k in sorted(counts.keys())},
        "category_titles": {k: cat_title.get(k, "") for k in sorted(counts.keys())},
    }
    return summary


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate and summarize KT failure taxonomy mappings (fail-closed).")
    ap.add_argument(
        "--taxonomy-relpath",
        default="KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
        help="Repo-relative taxonomy file path.",
    )
    ap.add_argument("--reason-codes", default=None, help="Comma-separated reason codes to summarize.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = repo_root_from(Path(__file__))
    taxonomy = load_failure_taxonomy(repo_root=repo_root, relpath=str(args.taxonomy_relpath))

    if args.reason_codes:
        codes = [x.strip() for x in str(args.reason_codes).split(",") if x.strip()]
    else:
        codes = []
    summary = summarize_reason_codes(taxonomy=taxonomy, reason_codes=codes)
    print(json.dumps(summary, sort_keys=True, ensure_ascii=True))
    return 0 if summary["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
