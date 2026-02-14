from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.audit_intelligence.offline_guard import (  # noqa: E402
    OfflineViolation,
    disable_offline_guard,
    enable_offline_guard,
)
from tools.audit_intelligence.run_audit_intelligence import (  # noqa: E402
    AuditIntelError,
    run_audit_intelligence,
)


def _mk_audit_event(*, run_id: str, created_at: str, reason_codes: list[str]) -> dict:
    obj = {
        "schema_id": "kt.audit_event.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.audit_event.v1.json"),
        "event_id": "0" * 64,
        "run_id": run_id,
        "lane_id": "FL4_SEAL",
        "event_kind": "FINALIZATION",
        "severity": "FAIL_CLOSED",
        "reason_codes": sorted(reason_codes),
        "component": "tools.verification.fl4_seal_verify",
        "summary": "fixture audit event",
        "evidence_paths": [],
        "created_at": created_at,
        "notes": None,
    }
    obj["event_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "event_id"})
    validate_object_with_binding(obj)
    return obj


def test_audit_intelligence_offline_guard_blocks_and_restores() -> None:
    orig_socket = socket.socket
    enable_offline_guard()
    try:
        try:
            socket.socket()
            assert False, "socket.socket() should have been blocked"
        except OfflineViolation:
            pass
    finally:
        disable_offline_guard()

    assert socket.socket is orig_socket
    s = socket.socket()
    s.close()


def test_audit_intelligence_no_enforcement_imports() -> None:
    audit_dir = (_REPO_ROOT / "KT_PROD_CLEANROOM" / "tools" / "audit_intelligence").resolve()
    assert audit_dir.is_dir()

    banned_prefixes = (
        "tools.verification",
        "tools.training",
        "tools.delivery",
        "tools.security",
        "policy_c",
        "core.",
    )

    offenders: list[str] = []
    for path in sorted(audit_dir.rglob("*.py"), key=lambda p: p.as_posix()):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module] if node.module else []
            else:
                continue
            for mod in mods:
                if any(mod.startswith(pref) for pref in banned_prefixes):
                    offenders.append(f"{path.as_posix()} :: {mod}")

    assert not offenders, f"Audit intelligence imported forbidden enforcement modules: {offenders}"


def test_audit_intelligence_runner_smoke(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events" / "fixtures"
    events_root.mkdir(parents=True, exist_ok=True)

    reason_code = "SECRET_LEAK_DETECTED"
    created_at = "2026-02-14T00:00:00Z"
    for i in range(3):
        ev = _mk_audit_event(run_id=f"RUN_{i}", created_at=created_at, reason_codes=[reason_code])
        (events_root / f"event_{i}.json").write_text(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")

    out_dir = tmp_path / "out"
    orig_socket = socket.socket
    result = run_audit_intelligence(
        vault_root=vault_root,
        out_dir=out_dir,
        min_cluster_size=3,
        proposal_cooldown_hours=1,
        reason_code_allowlist=None,
        allow_noncanonical_vault=True,
    )

    # Ensure offline guard is not left enabled for subsequent tests.
    assert socket.socket is orig_socket

    assert result["status"] == "PASS"
    assert result["ingested_events"] == 3
    assert result["clusters"] == 1
    assert result["probe_proposals"] == 1

    index = json.loads((out_dir / "audit_event_index.json").read_text(encoding="utf-8"))
    cfg = json.loads((out_dir / "audit_intelligence_config.json").read_text(encoding="utf-8"))
    report = json.loads((out_dir / "audit_intelligence_report.json").read_text(encoding="utf-8"))
    metrics = json.loads((out_dir / "audit_intelligence_metrics.json").read_text(encoding="utf-8"))
    for obj in (index, cfg, report, metrics):
        validate_object_with_binding(obj)

    cluster_files = list((out_dir / "clusters").glob("cluster_*.json"))
    proposal_files = list((out_dir / "proposals").glob("probe_*.json"))
    assert len(cluster_files) == 1
    assert len(proposal_files) == 1

    cluster = json.loads(cluster_files[0].read_text(encoding="utf-8"))
    proposal = json.loads(proposal_files[0].read_text(encoding="utf-8"))
    validate_object_with_binding(cluster)
    validate_object_with_binding(proposal)


def test_audit_intelligence_outputs_deterministic_for_same_inputs(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events" / "fixtures"
    events_root.mkdir(parents=True, exist_ok=True)

    reason_code = "SECRET_LEAK_DETECTED"
    created_at = "2026-02-14T00:00:00Z"
    for i in range(3):
        ev = _mk_audit_event(run_id=f"RUN_{i}", created_at=created_at, reason_codes=[reason_code])
        (events_root / f"event_{i}.json").write_text(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")

    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"

    r1 = run_audit_intelligence(
        vault_root=vault_root,
        out_dir=out1,
        min_cluster_size=3,
        proposal_cooldown_hours=1,
        reason_code_allowlist=None,
        allow_noncanonical_vault=True,
    )
    r2 = run_audit_intelligence(
        vault_root=vault_root,
        out_dir=out2,
        min_cluster_size=3,
        proposal_cooldown_hours=1,
        reason_code_allowlist=None,
        allow_noncanonical_vault=True,
    )
    assert r1["status"] == "PASS"
    assert r2["status"] == "PASS"

    def load(rel: str) -> dict:
        return json.loads((out1 / rel).read_text(encoding="utf-8")), json.loads((out2 / rel).read_text(encoding="utf-8"))

    idx1, idx2 = load("audit_event_index.json")
    cfg1, cfg2 = load("audit_intelligence_config.json")
    rep1, rep2 = load("audit_intelligence_report.json")
    met1, met2 = load("audit_intelligence_metrics.json")
    assert idx1 == idx2
    assert cfg1 == cfg2
    assert rep1 == rep2
    assert met1 == met2

    c1 = json.loads(next((out1 / "clusters").glob("cluster_*.json")).read_text(encoding="utf-8"))
    c2 = json.loads(next((out2 / "clusters").glob("cluster_*.json")).read_text(encoding="utf-8"))
    p1 = json.loads(next((out1 / "proposals").glob("probe_*.json")).read_text(encoding="utf-8"))
    p2 = json.loads(next((out2 / "proposals").glob("probe_*.json")).read_text(encoding="utf-8"))
    assert c1 == c2
    assert p1 == p2


def test_audit_intelligence_out_dir_nonempty_fails_closed(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events"
    events_root.mkdir(parents=True, exist_ok=True)
    # single event (cluster will not form, but runner must still refuse non-empty out_dir)
    ev = _mk_audit_event(run_id="RUN_X", created_at="2026-02-14T00:00:00Z", reason_codes=["X"])
    (events_root / "event.json").write_text(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")

    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "already.txt").write_text("x\n", encoding="utf-8", newline="\n")

    try:
        run_audit_intelligence(
            vault_root=vault_root,
            out_dir=out_dir,
            min_cluster_size=3,
            proposal_cooldown_hours=1,
            reason_code_allowlist=None,
            allow_noncanonical_vault=True,
        )
        assert False, "expected FAIL_CLOSED"
    except AuditIntelError as exc:
        assert "out_dir exists and is non-empty" in str(exc)


def test_audit_intelligence_unknown_reason_code_fails_closed(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events" / "fixtures"
    events_root.mkdir(parents=True, exist_ok=True)

    ev = _mk_audit_event(run_id="RUN_X", created_at="2026-02-14T00:00:00Z", reason_codes=["NOT_IN_TAXONOMY"])
    (events_root / "event.json").write_text(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")

    try:
        run_audit_intelligence(
            vault_root=vault_root,
            out_dir=tmp_path / "out",
            min_cluster_size=3,
            proposal_cooldown_hours=1,
            reason_code_allowlist=None,
            allow_noncanonical_vault=True,
        )
        assert False, "expected FAIL_CLOSED"
    except AuditIntelError as exc:
        assert "unknown reason_code" in str(exc)


def test_audit_intelligence_noncanonical_vault_rejected_without_flag(tmp_path: Path) -> None:
    vault_root = tmp_path / "vault"
    events_root = vault_root / "audit_events"
    events_root.mkdir(parents=True, exist_ok=True)
    ev = _mk_audit_event(run_id="RUN_X", created_at="2026-02-14T00:00:00Z", reason_codes=["X"])
    (events_root / "event.json").write_text(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")

    try:
        run_audit_intelligence(
            vault_root=vault_root,
            out_dir=tmp_path / "out",
            min_cluster_size=3,
            proposal_cooldown_hours=1,
            reason_code_allowlist=None,
            allow_noncanonical_vault=False,
        )
        assert False, "expected FAIL_CLOSED"
    except AuditIntelError as exc:
        assert "vault_root must be under KT_PROD_CLEANROOM/06_ARCHIVE_VAULT" in str(exc)
