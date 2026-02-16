from __future__ import annotations

import json
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.router.run_router_hat_demo import run_router_hat_demo  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402


def test_epic19_audited_policy_and_suite_are_schema_valid() -> None:
    p = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_POLICY_HAT_V1.json"
    s = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_DEMO_SUITE_V1.json"
    pol = json.loads(p.read_text(encoding="utf-8"))
    suite = json.loads(s.read_text(encoding="utf-8"))
    validate_object_with_binding(pol)
    validate_object_with_binding(suite)
    assert pol["schema_id"] == "kt.router_policy.v1"
    assert suite["schema_id"] == "kt.router_demo_suite.v1"


def test_epic19_router_hat_demo_emits_worm_receipts(tmp_path: Path) -> None:
    policy_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_POLICY_HAT_V1.json"
    suite_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_DEMO_SUITE_V1.json"

    out_dir = tmp_path / "router_out"
    report = run_router_hat_demo(policy_path=policy_path, suite_path=suite_path, run_id="TEST_ROUTER_RUN", out_dir=out_dir)
    validate_object_with_binding(report)
    assert report["schema_id"] == "kt.router_run_report.v1"
    assert report["status"] == "PASS"

    # Receipts exist.
    for case_id in ("R01", "R02", "R03", "R04"):
        rp = out_dir / f"routing_receipt_{case_id}.json"
        assert rp.exists()
        obj = json.loads(rp.read_text(encoding="utf-8"))
        validate_object_with_binding(obj)
        assert obj["schema_id"] == "kt.routing_receipt.v1"

    # WORM no-op: second identical run must not fail.
    report2 = run_router_hat_demo(policy_path=policy_path, suite_path=suite_path, run_id="TEST_ROUTER_RUN", out_dir=out_dir)
    assert report2["router_run_report_id"] == report["router_run_report_id"]


def test_epic19_mismatched_expectations_fail_closed(tmp_path: Path) -> None:
    policy_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_POLICY_HAT_V1.json"
    suite_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "ROUTER" / "ROUTER_DEMO_SUITE_V1.json"
    suite = json.loads(suite_path.read_text(encoding="utf-8"))
    suite2 = dict(suite)
    suite2["cases"] = [dict(c) for c in suite["cases"]]
    # Corrupt expected domain for R02.
    for c in suite2["cases"]:
        if c["case_id"] == "R02":
            c["expected_domain_tag"] = "math"
    bad_path = tmp_path / "bad_suite.json"
    bad_path.write_text(json.dumps(suite2, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    with pytest.raises(FL3ValidationError):
        _ = run_router_hat_demo(
            policy_path=policy_path,
            suite_path=bad_path,
            run_id="TEST_ROUTER_RUN",
            out_dir=tmp_path / "out",
        )

