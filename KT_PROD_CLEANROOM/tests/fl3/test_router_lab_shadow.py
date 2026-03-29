from __future__ import annotations

import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from tools.router.run_router_lab_shadow import build_router_lab_shadow_report  # noqa: E402


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_router_lab_policy_refs_known_adapters_and_yields_advantage_cases() -> None:
    policy = _load_json(
        _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_POLICY_V1.json"
    )
    suite = _load_json(
        _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_SUITE_V1.json"
    )
    registry = _load_json(_REPO_ROOT / "KT_PROD_CLEANROOM" / "reports" / "kt_adapter_registry.json")

    report = build_router_lab_shadow_report(
        root=_REPO_ROOT,
        policy=policy,
        suite=suite,
        adapter_registry=registry,
    )

    assert report["status"] == "PASS"
    assert report["mode"] == "LAB_ONLY_NONCANONICAL"
    assert report["summary"]["router_advantage_visible"] is True
    assert report["summary"]["opportunity_case_count"] >= 3


def test_router_lab_shadow_prefers_specialist_sequences_for_mixed_cases() -> None:
    policy = _load_json(
        _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_POLICY_V1.json"
    )
    suite = _load_json(
        _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_SUITE_V1.json"
    )
    registry = _load_json(_REPO_ROOT / "KT_PROD_CLEANROOM" / "reports" / "kt_adapter_registry.json")

    report = build_router_lab_shadow_report(
        root=_REPO_ROOT,
        policy=policy,
        suite=suite,
        adapter_registry=registry,
    )
    rows = {row["case_id"]: row for row in report["case_rows"]}

    assert rows["LAB_R01"]["routed_adapter_ids"] == ["lobe.scout.v1", "lobe.architect.v1", "lobe.muse.v1"]
    assert rows["LAB_R01"]["specialist_route_advantage"] is True
    assert rows["LAB_R01"]["best_single_adapter_id"] == "lobe.strategist.v1"

    assert rows["LAB_R02"]["routed_adapter_ids"] == ["lobe.architect.v1", "lobe.critic.v1"]
    assert rows["LAB_R02"]["specialist_route_advantage"] is True

    assert rows["LAB_R05"]["fallback_engaged"] is True
    assert rows["LAB_R05"]["routed_adapter_ids"] == ["lobe.strategist.v1"]
    assert rows["LAB_R05"]["specialist_route_advantage"] is False


def test_router_lab_shadow_cli_writes_report(tmp_path: Path) -> None:
    policy_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_POLICY_V1.json"
    suite_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "03_SYNTHESIS_LAB" / "ROUTER_LAB" / "ROUTER_SEQUENCE_LAB_SUITE_V1.json"
    registry_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "reports" / "kt_adapter_registry.json"
    out_path = tmp_path / "router_lab_shadow_report.json"

    from tools.router.run_router_lab_shadow import main

    rc = main(
        [
            "--policy",
            str(policy_path),
            "--suite",
            str(suite_path),
            "--adapter-registry",
            str(registry_path),
            "--output",
            str(out_path),
        ]
    )

    assert rc == 0
    payload = _load_json(out_path)
    assert payload["status"] == "PASS"
    assert payload["summary"]["router_advantage_visible"] is True
