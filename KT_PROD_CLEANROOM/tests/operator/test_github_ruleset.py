from __future__ import annotations

from pathlib import Path

from tools.operator.github_ruleset import _candidate_matches, _required_status_checks, _ruleset_summary
from tools.operator.titanium_common import load_json


def test_github_main_ruleset_has_expected_required_checks() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    ruleset = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    assert _required_status_checks(ruleset) == [
        "p0-program-catalog",
        "ws0-delivery-parity",
        "ws1-mai-conformance",
        "ws2-replay-bindingloop",
        "ws3-constitution",
    ]


def test_candidate_matches_passes_for_identical_ruleset() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    live = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    matched, failures = _candidate_matches(desired=desired, live=live)
    assert matched is True
    assert failures == []


def test_candidate_matches_fails_on_missing_status_check() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    live = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    live["rules"][-1]["parameters"]["required_status_checks"] = live["rules"][-1]["parameters"]["required_status_checks"][:-1]
    matched, failures = _candidate_matches(desired=desired, live=live)
    assert matched is False
    assert any("missing_checks:" in failure for failure in failures)


def test_ruleset_summary_reports_branch_target() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    summary = _ruleset_summary(desired)
    assert summary["target"] == "branch"
    assert summary["targets"] == ["refs/heads/main"]
