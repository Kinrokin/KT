from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.schema_files import schema_version_hash
from schemas.schema_registry import validate_object_with_binding
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.worm_write import write_text_worm


class ProbeSynthesisError(RuntimeError):
    pass


def _parse_utc_z(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ProbeSynthesisError(f"FAIL_CLOSED: {field} must be non-empty string")
    s = value.strip()
    if not s.endswith("Z"):
        raise ProbeSynthesisError(f"FAIL_CLOSED: {field} must end with 'Z'")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception as exc:  # noqa: BLE001
        raise ProbeSynthesisError(f"FAIL_CLOSED: unable to parse {field} as UTC ISO-8601") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _deterministic_created_at(events: List[Dict[str, Any]]) -> Tuple[str, datetime]:
    if not events:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        return "1970-01-01T00:00:00Z", epoch
    latest = max(_parse_utc_z(ev.get("created_at"), field="audit_event.created_at") for ev in events)
    latest = latest.replace(microsecond=0)
    return latest.strftime("%Y-%m-%dT%H:%M:%SZ"), latest


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return _sha256_text(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ProbeSynthesisError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise ProbeSynthesisError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _iter_event_files(events_root: Path) -> Tuple[Path, ...]:
    files: List[Path] = []
    for p in events_root.rglob("*.json"):
        if p.is_file():
            files.append(p)
    files.sort(key=lambda p: p.relative_to(events_root).as_posix())
    return tuple(files)


def _mk_manifest(*, vault_root_rel: str, event_count: int, min_support: int, created_at: str) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "schema_id": "kt.probe_synthesis_manifest.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.probe_synthesis_manifest.v1.json"),
        "manifest_id": "",
        "vault_root_rel": vault_root_rel,
        "event_count": int(event_count),
        "min_support": int(min_support),
        "created_at": created_at,
        "notes": None,
    }
    obj["manifest_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "manifest_id"}})
    validate_object_with_binding(obj)
    return obj


def _mk_report(
    *,
    manifest_id: str,
    probes: List[Dict[str, Any]],
    created_at: str,
    anchor_dt: datetime,
    cooldown_hours: int,
) -> Dict[str, Any]:
    earliest = (anchor_dt + timedelta(hours=int(cooldown_hours))).strftime("%Y-%m-%dT%H:%M:%SZ")
    probes_sorted = sorted(probes, key=lambda p: (str(p.get("reason_code", "")), str(p.get("probe_id", ""))))
    obj: Dict[str, Any] = {
        "schema_id": "kt.probe_synthesis_report.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.probe_synthesis_report.v1.json"),
        "report_id": "",
        "manifest_id": manifest_id,
        "synthesizer_version": "probe_synthesizer.v1",
        "synthesized_probes": [
            dict(p, earliest_review_timestamp=earliest, requires_human_review=True) for p in probes_sorted
        ],
        "created_at": created_at,
        "notes": None,
    }
    obj["report_id"] = sha256_json({k: v for k, v in obj.items() if k not in {"created_at", "report_id"}})
    validate_object_with_binding(obj)
    return obj


def run_probe_synthesis(
    *,
    vault_root: Path,
    out_dir: Path,
    min_support: int,
    proposal_cooldown_hours: int,
    allow_noncanonical_vault: bool,
) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))
    canonical_vault = (repo_root / "KT_ARCHIVE" / "vault").resolve()
    vault_root = vault_root.resolve()
    if not allow_noncanonical_vault:
        try:
            vault_root.relative_to(canonical_vault)
        except Exception as exc:  # noqa: BLE001
            raise ProbeSynthesisError("FAIL_CLOSED: vault_root must be under KT_ARCHIVE/vault") from exc

    events_root = vault_root / "audit_events"
    if not events_root.exists() or not events_root.is_dir():
        raise ProbeSynthesisError(f"FAIL_CLOSED: missing audit_events/ under vault_root: {events_root.as_posix()}")

    out_dir = out_dir.resolve()
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ProbeSynthesisError(f"FAIL_CLOSED: out_dir exists and is non-empty: {out_dir.as_posix()}")
    out_dir.mkdir(parents=True, exist_ok=True)

    event_files = _iter_event_files(events_root)
    events: List[Dict[str, Any]] = []
    for p in event_files:
        obj = _read_json_dict(p, name="audit_event")
        validate_object_with_binding(obj)
        if obj.get("schema_id") != "kt.audit_event.v1":
            raise ProbeSynthesisError("FAIL_CLOSED: non-audit_event schema in audit_events/")
        events.append(obj)

    created_at, anchor_dt = _deterministic_created_at(events)
    try:
        vault_root_rel = vault_root.relative_to(repo_root).as_posix()
    except Exception:  # noqa: BLE001
        vault_root_rel = vault_root.as_posix()

    manifest = _mk_manifest(vault_root_rel=vault_root_rel, event_count=len(events), min_support=int(min_support), created_at=created_at)
    write_text_worm(
        path=out_dir / "probe_synthesis_manifest.json",
        text=json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="probe_synthesis_manifest.json",
    )

    counts: Dict[str, int] = {}
    for ev in events:
        rcs = ev.get("reason_codes") if isinstance(ev.get("reason_codes"), list) else []
        for rc in rcs:
            if isinstance(rc, str) and rc.strip():
                counts[rc.strip()] = counts.get(rc.strip(), 0) + 1

    probes: List[Dict[str, Any]] = []
    for reason_code, n in sorted(counts.items(), key=lambda kv: kv[0]):
        if n < int(min_support):
            continue
        probe_id = sha256_json({"reason_code": reason_code, "support": n, "anchor": created_at})
        probes.append(
            {
                "probe_id": probe_id,
                "reason_code": reason_code,
                "title": f"Drill for {reason_code}",
                "prompt": f"[DRILL] Trigger condition for reason_code={reason_code}.",
                "expected_behavior": f"System must fail-closed with reason_code {reason_code} under the relevant lane policy.",
            }
        )

    report = _mk_report(
        manifest_id=str(manifest["manifest_id"]),
        probes=probes,
        created_at=created_at,
        anchor_dt=anchor_dt,
        cooldown_hours=int(proposal_cooldown_hours),
    )
    write_text_worm(
        path=out_dir / "probe_synthesis_report.json",
        text=json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="probe_synthesis_report.json",
    )

    return {
        "status": "PASS",
        "out_dir": out_dir.as_posix(),
        "event_count": len(events),
        "probe_count": len(probes),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Synthesize candidate drill probes from audit events (advisory-only).")
    ap.add_argument("--vault-root", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--min-support", type=int, default=3)
    ap.add_argument("--proposal-cooldown-hours", type=int, default=24)
    ap.add_argument("--allow-noncanonical-vault", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    result = run_probe_synthesis(
        vault_root=Path(args.vault_root),
        out_dir=Path(args.out_dir),
        min_support=int(args.min_support),
        proposal_cooldown_hours=int(args.proposal_cooldown_hours),
        allow_noncanonical_vault=bool(args.allow_noncanonical_vault),
    )
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
