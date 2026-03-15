from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from schemas.schema_registry import validate_object_with_binding
from schemas.schema_hash import canonical_json

from tools.audit_intelligence.offline_guard import OfflineViolation, offline_guard


class AuditIntelError(RuntimeError):
    pass


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return _sha256_text(canonical_json(obj))


def _parse_utc_z(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AuditIntelError(f"FAIL_CLOSED: {field} must be non-empty string")
    s = value.strip()
    if not s.endswith("Z"):
        raise AuditIntelError(f"FAIL_CLOSED: {field} must end with 'Z'")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception as exc:  # noqa: BLE001
        raise AuditIntelError(f"FAIL_CLOSED: unable to parse {field} as UTC ISO-8601: {s}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _deterministic_run_time_z(events: List[Dict[str, Any]]) -> Tuple[str, datetime]:
    """
    Derive a deterministic "created_at" anchor from evidence:
    - If events are present: max(events[].created_at) truncated to seconds.
    - If no events: epoch sentinel (still valid UTC-Z).
    """
    if not events:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        return "1970-01-01T00:00:00Z", epoch

    latest = max(_parse_utc_z(ev.get("created_at"), field="audit_event.created_at") for ev in events)
    latest = latest.replace(microsecond=0)
    return latest.strftime("%Y-%m-%dT%H:%M:%SZ"), latest


def repo_root_from(path: Path) -> Path:
    p = path.resolve()
    for parent in [p] + list(p.parents):
        if (parent / "KT_PROD_CLEANROOM").is_dir():
            return parent
    raise AuditIntelError("FAIL_CLOSED: unable to locate repo root (expected KT_PROD_CLEANROOM/)")


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AuditIntelError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise AuditIntelError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _load_failure_taxonomy(*, repo_root: Path) -> Dict[str, str]:
    taxonomy_path = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS" / "FAILURE_TAXONOMY_FL3.json").resolve()
    obj = _read_json_dict(taxonomy_path, name="failure_taxonomy")
    validate_object_with_binding(obj)
    if obj.get("schema_id") != "kt.failure_taxonomy.v1":
        raise AuditIntelError("FAIL_CLOSED: failure taxonomy schema_id mismatch")
    mappings = obj.get("mappings")
    if not isinstance(mappings, list) or not mappings:
        raise AuditIntelError("FAIL_CLOSED: failure taxonomy mappings missing/invalid")
    out: Dict[str, str] = {}
    for m in mappings:
        if not isinstance(m, dict):
            continue
        rc = str(m.get("reason_code", "")).strip()
        cat = str(m.get("category_id", "")).strip()
        if rc and cat:
            out[rc] = cat
    if not out:
        raise AuditIntelError("FAIL_CLOSED: failure taxonomy contains 0 reason_code mappings")
    return out


def _iter_event_files(events_root: Path) -> Tuple[Path, ...]:
    files: List[Path] = []
    for p in events_root.rglob("*.json"):
        if p.is_file():
            files.append(p)
    files.sort(key=lambda p: p.relative_to(events_root).as_posix())
    return tuple(files)


def _write_create_once(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise AuditIntelError(f"FAIL_CLOSED: refusing to overwrite existing artifact: {path.as_posix()}") from exc


def _mk_index(*, vault_root_rel: str, entries: List[Dict[str, str]], created_at: str) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_event_index.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_event_index.v1.json"),
        "index_id": "",
        "vault_root_rel": vault_root_rel,
        "entries": entries,
        "created_at": created_at,
    }
    obj["index_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "index_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_config(
    *,
    min_cluster_size: int,
    proposal_cooldown_hours: int,
    reason_code_allowlist: Optional[List[str]],
    created_at: str,
) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_intelligence_config.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_intelligence_config.v1.json"),
        "config_id": "",
        "min_cluster_size": int(min_cluster_size),
        "proposal_cooldown_hours": int(proposal_cooldown_hours),
        "reason_code_allowlist": sorted({x.strip() for x in (reason_code_allowlist or []) if isinstance(x, str) and x.strip()}),
        "created_at": created_at,
    }
    obj["config_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "config_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_cluster(*, reason_code: str, event_ids: List[str], created_at: str) -> Dict[str, Any]:
    ids_sorted = sorted(event_ids)
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_pattern_cluster.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_pattern_cluster.v1.json"),
        "cluster_id": "",
        "reason_code": str(reason_code),
        "event_ids": ids_sorted,
        "count": len(ids_sorted),
        "notes": None,
        "created_at": created_at,
    }
    obj["cluster_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "cluster_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_probe_proposal(*, reason_code: str, event_ids: List[str], cooldown_hours: int, created_at: str, anchor_dt: datetime) -> Dict[str, Any]:
    earliest = (anchor_dt + timedelta(hours=int(cooldown_hours))).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids_sorted = sorted(event_ids)
    # Keep proposal small; include up to first 50 event ids.
    evidence_ids = ids_sorted[:50]
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_probe_proposal.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_probe_proposal.v1.json"),
        "proposal_id": "",
        "proposal_type": "NEW_DRILL",
        "title": f"Add drill for {reason_code}",
        "description": "Autogenerated proposal from repeated audited failures. Add a deterministic drill/test that triggers this reason code.",
        "reason_code": str(reason_code),
        "evidence_event_ids": evidence_ids,
        "requires_human_approval": True,
        "earliest_review_timestamp": earliest,
        "created_at": created_at,
    }
    obj["proposal_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "proposal_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_report(
    *,
    vault_root_rel: str,
    config_id: str,
    ingested_events: int,
    clusters: List[str],
    probe_proposals: List[str],
    doctrine_proposals: List[str],
    created_at: str,
) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_intelligence_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_intelligence_report.v1.json"),
        "report_id": "",
        "vault_root_rel": vault_root_rel,
        "config_id": str(config_id),
        "ingested_events": int(ingested_events),
        "clusters": sorted(clusters),
        "probe_proposals": sorted(probe_proposals),
        "doctrine_proposals": sorted(doctrine_proposals),
        "created_at": created_at,
    }
    obj["report_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "report_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_metrics(*, report_id: str, events_ingested: int, clusters: int, probe_proposals: int, doctrine_proposals: int, created_at: str) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.audit_intelligence_metrics.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_intelligence_metrics.v1.json"),
        "metrics_id": "",
        "report_id": str(report_id),
        "counts": {
            "events_ingested": int(events_ingested),
            "clusters": int(clusters),
            "probe_proposals": int(probe_proposals),
            "doctrine_proposals": int(doctrine_proposals),
        },
        "created_at": created_at,
    }
    obj["metrics_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "metrics_id"}})
    validate_object_with_binding(obj)
    return obj


def run_audit_intelligence(
    *,
    vault_root: Path,
    out_dir: Path,
    min_cluster_size: int,
    proposal_cooldown_hours: int,
    reason_code_allowlist: Optional[List[str]],
    allow_noncanonical_vault: bool,
) -> Dict[str, Any]:
    with offline_guard():
        repo_root = repo_root_from(Path(__file__))
        canonical_vault = (repo_root / "KT_ARCHIVE" / "vault").resolve()
        vault_root = vault_root.resolve()
        if not allow_noncanonical_vault:
            try:
                vault_root.relative_to(canonical_vault)
            except Exception as exc:  # noqa: BLE001
                raise AuditIntelError("FAIL_CLOSED: vault_root must be under KT_ARCHIVE/vault") from exc

        events_root = vault_root / "audit_events"
        if not events_root.exists() or not events_root.is_dir():
            raise AuditIntelError(f"FAIL_CLOSED: missing audit_events/ under vault_root: {events_root.as_posix()}")

        out_dir = out_dir.resolve()
        if out_dir.exists() and any(out_dir.iterdir()):
            raise AuditIntelError(f"FAIL_CLOSED: out_dir exists and is non-empty: {out_dir.as_posix()}")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Failure taxonomy is law-bound; unknown reason codes are fail-closed.
        reason_to_category = _load_failure_taxonomy(repo_root=repo_root)

        event_files = _iter_event_files(events_root)
        events: List[Dict[str, Any]] = []
        index_entries: List[Dict[str, str]] = []
        for p in event_files:
            obj = _read_json_dict(p, name="audit_event")
            validate_object_with_binding(obj)
            if obj.get("schema_id") != "kt.audit_event.v1":
                raise AuditIntelError(f"FAIL_CLOSED: non-audit_event schema in audit_events: {p.as_posix()}")
            rcs = obj.get("reason_codes") if isinstance(obj.get("reason_codes"), list) else []
            for rc in rcs:
                if not isinstance(rc, str) or not rc.strip():
                    continue
                if rc.strip() not in reason_to_category:
                    raise AuditIntelError(f"FAIL_CLOSED: unknown reason_code (taxonomy missing): {rc.strip()}")
            events.append(obj)
            rel = p.relative_to(vault_root).as_posix()
            digest = sha256_json(obj)
            index_entries.append({"path": rel, "sha256": digest, "event_id": str(obj.get("event_id", ""))})

        run_created_at_z, run_anchor_dt = _deterministic_run_time_z(events)
        index_entries.sort(key=lambda e: e["path"])
        try:
            vault_root_rel = vault_root.relative_to(repo_root).as_posix()
        except Exception:  # noqa: BLE001
            vault_root_rel = vault_root.as_posix()
        index = _mk_index(vault_root_rel=vault_root_rel, entries=index_entries, created_at=run_created_at_z)
        _write_create_once(out_dir / "audit_event_index.json", json.dumps(index, indent=2, sort_keys=True, ensure_ascii=True) + "\n")

        cfg = _mk_config(
            min_cluster_size=min_cluster_size,
            proposal_cooldown_hours=proposal_cooldown_hours,
            reason_code_allowlist=reason_code_allowlist,
            created_at=run_created_at_z,
        )
        _write_create_once(out_dir / "audit_intelligence_config.json", json.dumps(cfg, indent=2, sort_keys=True, ensure_ascii=True) + "\n")

        allow_set = set(cfg.get("reason_code_allowlist") or [])
        unknown_allow = sorted([rc for rc in allow_set if rc not in reason_to_category])
        if unknown_allow:
            raise AuditIntelError(f"FAIL_CLOSED: reason_code_allowlist contains unknown codes: {unknown_allow}")
        groups: Dict[str, List[str]] = {}
        for ev in events:
            rcs = ev.get("reason_codes") if isinstance(ev.get("reason_codes"), list) else []
            for rc in rcs:
                if not isinstance(rc, str) or not rc.strip():
                    continue
                r = rc.strip()
                if allow_set and r not in allow_set:
                    continue
                groups.setdefault(r, []).append(str(ev.get("event_id", "")))

        clusters_out: List[str] = []
        probe_out: List[str] = []
        doctrine_out: List[str] = []

        for reason_code, event_ids in sorted(groups.items(), key=lambda kv: kv[0]):
            ids = sorted({x for x in event_ids if isinstance(x, str) and len(x) == 64})
            if len(ids) < int(cfg.get("min_cluster_size", 1)):
                continue
            cluster = _mk_cluster(reason_code=reason_code, event_ids=ids, created_at=run_created_at_z)
            clusters_out.append(str(cluster["cluster_id"]))
            _write_create_once(
                out_dir / "clusters" / f"cluster_{cluster['cluster_id']}.json",
                json.dumps(cluster, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            )

            proposal = _mk_probe_proposal(
                reason_code=reason_code,
                event_ids=ids,
                cooldown_hours=int(cfg["proposal_cooldown_hours"]),
                created_at=run_created_at_z,
                anchor_dt=run_anchor_dt,
            )
            probe_out.append(str(proposal["proposal_id"]))
            _write_create_once(
                out_dir / "proposals" / f"probe_{proposal['proposal_id']}.json",
                json.dumps(proposal, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            )

        report = _mk_report(
            vault_root_rel=vault_root_rel,
            config_id=str(cfg["config_id"]),
            ingested_events=len(events),
            clusters=clusters_out,
            probe_proposals=probe_out,
            doctrine_proposals=doctrine_out,
            created_at=run_created_at_z,
        )
        _write_create_once(out_dir / "audit_intelligence_report.json", json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n")

        metrics = _mk_metrics(
            report_id=str(report["report_id"]),
            events_ingested=len(events),
            clusters=len(clusters_out),
            probe_proposals=len(probe_out),
            doctrine_proposals=len(doctrine_out),
            created_at=run_created_at_z,
        )
        _write_create_once(out_dir / "audit_intelligence_metrics.json", json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=True) + "\n")

        return {
            "status": "PASS",
            "out_dir": out_dir.as_posix(),
            "ingested_events": len(events),
            "clusters": len(clusters_out),
            "probe_proposals": len(probe_out),
        }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run EPIC_13 audit intelligence (offline, append-only, advisory-only).")
    ap.add_argument("--vault-root", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--min-cluster-size", type=int, default=3)
    ap.add_argument("--proposal-cooldown-hours", type=int, default=24)
    ap.add_argument("--reason-code-allowlist", default=None, help="Comma-separated list of reason codes to consider.")
    ap.add_argument("--allow-noncanonical-vault", action="store_true", help="Allow vault roots outside KT_ARCHIVE/vault (tests only).")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    allowlist = None
    if args.reason_code_allowlist:
        allowlist = [x.strip() for x in str(args.reason_code_allowlist).split(",") if x.strip()]
    result = run_audit_intelligence(
        vault_root=Path(args.vault_root),
        out_dir=Path(args.out_dir),
        min_cluster_size=int(args.min_cluster_size),
        proposal_cooldown_hours=int(args.proposal_cooldown_hours),
        reason_code_allowlist=allowlist,
        allow_noncanonical_vault=bool(args.allow_noncanonical_vault),
    )
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OfflineViolation as exc:
        raise SystemExit(str(exc)) from exc
    except AuditIntelError as exc:
        raise SystemExit(str(exc)) from exc
