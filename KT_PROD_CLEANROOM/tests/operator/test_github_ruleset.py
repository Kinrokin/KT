from __future__ import annotations

from pathlib import Path

from tools.operator.github_ruleset import _candidate_matches, _required_status_checks, _ruleset_summary, verify_ruleset
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


def test_candidate_matches_fails_on_pull_request_rule_mismatch() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    live = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    live["rules"][2]["parameters"]["required_approving_review_count"] = 1
    matched, failures = _candidate_matches(desired=desired, live=live)
    assert matched is False
    assert "pull_request_rule:mismatch" in failures


def test_ruleset_summary_reports_branch_target() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")
    summary = _ruleset_summary(desired)
    assert summary["target"] == "branch"
    assert summary["targets"] == ["refs/heads/main"]


def test_verify_ruleset_uses_detail_endpoint(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    desired = load_json(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json")

    def fake_token() -> str:
        return "token"

    def fake_api_request(*, method: str, path: str, token: str, body=None):
        assert method == "GET"
        assert token == "token"
        if path == "/repos/Kinrokin/KT":
            return {"default_branch": "main", "private": False}
        if path == "/repos/Kinrokin/KT/rulesets":
            return [{"id": 42, "name": desired["name"], "target": desired["target"], "enforcement": desired["enforcement"]}]
        if path == "/repos/Kinrokin/KT/rulesets/42":
            return desired
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr("tools.operator.github_ruleset._github_token", fake_token)
    monkeypatch.setattr("tools.operator.github_ruleset._api_request", fake_api_request)

    receipt = verify_ruleset(repo_slug="Kinrokin/KT", ruleset_path=str(repo_root / "KT_PROD_CLEANROOM" / "governance" / "platform" / "github_main_ruleset.json"))
    assert receipt["status"] == "PASS"
    assert receipt["claim_admissible"] is True
    assert "/repos/Kinrokin/KT/rulesets/42" in "\n".join(receipt["attempted_api_calls"])
