from __future__ import annotations

import argparse
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z


DEFAULT_RULESET_PATH = "KT_PROD_CLEANROOM/governance/platform/github_main_ruleset.json"
DEFAULT_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/main_branch_protection_receipt.json"


def _resolve_path(rel_or_abs: str) -> Path:
    path = Path(str(rel_or_abs)).expanduser()
    if not path.is_absolute():
        path = (repo_root() / path).resolve()
    return path


def _run_gh_token() -> str:
    try:
        proc = subprocess.run(
            ["gh", "auth", "token"],
            cwd=str(repo_root()),
            check=True,
            text=True,
            capture_output=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("GitHub token not available via env or gh auth") from exc
    token = proc.stdout.strip()
    if not token:
        raise RuntimeError("GitHub token not available via env or gh auth")
    return token


def _github_token() -> str:
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = str(os.environ.get(key, "")).strip()
        if value:
            return value
    return _run_gh_token()


def _repo_slug(default: str = "") -> str:
    if str(default).strip():
        return str(default).strip()
    remote = subprocess.check_output(["git", "config", "--get", "remote.origin.url"], cwd=str(repo_root()), text=True).strip()
    if remote.startswith("git@github.com:"):
        tail = remote.split(":", 1)[1]
    elif "github.com/" in remote:
        tail = remote.split("github.com/", 1)[1]
    else:
        raise RuntimeError(f"Unsupported GitHub remote URL: {remote}")
    if tail.endswith(".git"):
        tail = tail[:-4]
    if tail.count("/") != 1:
        raise RuntimeError(f"Unable to derive owner/repo from remote URL: {remote}")
    return tail


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=str(repo_root()), text=True).strip()


def _api_request(*, method: str, path: str, token: str, body: Optional[Dict[str, Any]] = None) -> Any:
    url = f"https://api.github.com{path}"
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if body is not None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        raw = response.read().decode("utf-8")
        if not raw.strip():
            return {}
        return json.loads(raw)


def _load_live_ruleset_details(*, owner: str, repo: str, token: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    attempted_api_calls = [f"GET /repos/{owner}/{repo}/rulesets"]
    live_rulesets = _api_request(method="GET", path=f"/repos/{owner}/{repo}/rulesets", token=token)
    rows = live_rulesets if isinstance(live_rulesets, list) else []
    details: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ruleset_id = row.get("id")
        if ruleset_id in (None, ""):
            continue
        attempted_api_calls.append(f"GET /repos/{owner}/{repo}/rulesets/{ruleset_id}")
        detail = _api_request(method="GET", path=f"/repos/{owner}/{repo}/rulesets/{ruleset_id}", token=token)
        if isinstance(detail, dict):
            details.append(detail)
    return details, attempted_api_calls


def _required_status_checks(ruleset: Dict[str, Any]) -> List[str]:
    contexts: List[str] = []
    for rule in ruleset.get("rules", []):
        if not isinstance(rule, dict) or str(rule.get("type", "")).strip() != "required_status_checks":
            continue
        params = rule.get("parameters")
        if not isinstance(params, dict):
            continue
        for row in params.get("required_status_checks", []):
            if not isinstance(row, dict):
                continue
            context = str(row.get("context", "")).strip()
            if context:
                contexts.append(context)
    return sorted(set(contexts))


def _required_rule_types(ruleset: Dict[str, Any]) -> List[str]:
    out = []
    for rule in ruleset.get("rules", []):
        if isinstance(rule, dict):
            rule_type = str(rule.get("type", "")).strip()
            if rule_type:
                out.append(rule_type)
    return sorted(set(out))


def _matching_ref_targets(ruleset: Dict[str, Any]) -> List[str]:
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return []
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return []
    include = ref_name.get("include")
    if not isinstance(include, list):
        return []
    return [str(x).strip() for x in include if str(x).strip()]


def _ruleset_summary(ruleset: Dict[str, Any]) -> Dict[str, Any]:
    pull_request_rule: Dict[str, Any] = {}
    for rule in ruleset.get("rules", []):
        if not isinstance(rule, dict) or str(rule.get("type", "")).strip() != "pull_request":
            continue
        params = rule.get("parameters")
        if not isinstance(params, dict):
            continue
        pull_request_rule = {
            "dismiss_stale_reviews_on_push": bool(params.get("dismiss_stale_reviews_on_push")),
            "require_code_owner_review": bool(params.get("require_code_owner_review")),
            "require_last_push_approval": bool(params.get("require_last_push_approval")),
            "required_approving_review_count": int(params.get("required_approving_review_count", 0)),
            "required_review_thread_resolution": bool(params.get("required_review_thread_resolution")),
        }
        break
    return {
        "enforcement": str(ruleset.get("enforcement", "")).strip(),
        "name": str(ruleset.get("name", "")).strip(),
        "pull_request_rule": pull_request_rule,
        "required_checks": _required_status_checks(ruleset),
        "rule_types": _required_rule_types(ruleset),
        "target": str(ruleset.get("target", "")).strip(),
        "targets": _matching_ref_targets(ruleset),
    }


def _candidate_matches(*, desired: Dict[str, Any], live: Dict[str, Any]) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    desired_summary = _ruleset_summary(desired)
    live_summary = _ruleset_summary(live)
    for field in ("name", "target", "enforcement"):
        if desired_summary[field] != live_summary[field]:
            failures.append(f"{field}:expected={desired_summary[field]} actual={live_summary[field]}")
    if sorted(desired_summary["targets"]) != sorted(live_summary["targets"]):
        failures.append("ref_targets:mismatch")
    if desired_summary["pull_request_rule"] != live_summary["pull_request_rule"]:
        failures.append("pull_request_rule:mismatch")
    desired_rule_types = set(desired_summary["rule_types"])
    live_rule_types = set(live_summary["rule_types"])
    missing_rule_types = sorted(desired_rule_types - live_rule_types)
    if missing_rule_types:
        failures.append(f"missing_rule_types:{','.join(missing_rule_types)}")
    desired_checks = set(desired_summary["required_checks"])
    live_checks = set(live_summary["required_checks"])
    missing_checks = sorted(desired_checks - live_checks)
    if missing_checks:
        failures.append(f"missing_checks:{','.join(missing_checks)}")
    return (not failures, failures)


def _load_ruleset(path_arg: str) -> Dict[str, Any]:
    return load_json(_resolve_path(path_arg or DEFAULT_RULESET_PATH))


def _receipt_base(*, repo_slug: str, ruleset_path: str, command: str) -> Dict[str, Any]:
    return {
        "apply_program_id": "program.github.ruleset.apply",
        "branch_ref": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "command": command,
        "created_utc": utc_now_iso_z(),
        "desired_state_artifact": str(_resolve_path(ruleset_path).relative_to(repo_root())).replace("\\", "/"),
        "repo": repo_slug,
        "schema_id": "kt.main_branch_protection_receipt.v2",
        "validated_head_sha": _git("rev-parse", "HEAD"),
        "verify_program_id": "program.github.ruleset.verify",
    }


def verify_ruleset(*, repo_slug: str, ruleset_path: str) -> Dict[str, Any]:
    desired = _load_ruleset(ruleset_path)
    owner, repo = repo_slug.split("/", 1)
    token = _github_token()
    receipt = _receipt_base(repo_slug=repo_slug, ruleset_path=ruleset_path, command="verify")
    receipt["required_checks"] = _required_status_checks(desired)
    receipt["desired_ruleset"] = _ruleset_summary(desired)
    try:
        repo_info = _api_request(method="GET", path=f"/repos/{owner}/{repo}", token=token)
        rulesets, attempted_api_calls = _load_live_ruleset_details(owner=owner, repo=repo, token=token)
        receipt["visibility"] = "PRIVATE" if bool(repo_info.get("private")) else "PUBLIC"
        receipt["default_branch"] = str(repo_info.get("default_branch", "")).strip()
        receipt["attempted_api_calls"] = [f"GET /repos/{owner}/{repo}", *attempted_api_calls]
        matches: List[Dict[str, Any]] = []
        for row in rulesets:
            if not isinstance(row, dict):
                continue
            matched, failures = _candidate_matches(desired=desired, live=row)
            summary = _ruleset_summary(row)
            summary["id"] = row.get("id")
            summary["matched"] = matched
            summary["match_failures"] = failures
            summary["html_url"] = ((row.get("_links") or {}).get("html") or {}).get("href")
            matches.append(summary)
        active_matches = [row for row in matches if row.get("matched")]
        receipt["live_rulesets"] = matches
        if active_matches:
            receipt["status"] = "PASS"
            receipt["claim_admissible"] = True
            receipt["active_ruleset"] = active_matches[0]
            receipt["next_action"] = "Branch protection / ruleset enforcement is active on main."
        else:
            receipt["status"] = "BLOCKED"
            receipt["claim_admissible"] = False
            receipt["next_action"] = "Apply KT_PROD_CLEANROOM/governance/platform/github_main_ruleset.json through GitHub and rerun program.github.ruleset.verify."
        return receipt
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body
        try:
            parsed = json.loads(body)
            message = str(parsed.get("message", body))
        except Exception:  # noqa: BLE001
            pass
        receipt["attempted_api_calls"] = [f"GET /repos/{owner}/{repo}", f"GET /repos/{owner}/{repo}/rulesets"]
        receipt["status"] = "BLOCKED"
        receipt["claim_admissible"] = False
        receipt["platform_block"] = {"http_status": int(exc.code), "message": message}
        receipt["next_action"] = "Enable GitHub branch protection capability for this repository and apply the committed ruleset desired state."
        return receipt


def apply_ruleset(*, repo_slug: str, ruleset_path: str) -> Dict[str, Any]:
    desired = _load_ruleset(ruleset_path)
    owner, repo = repo_slug.split("/", 1)
    token = _github_token()
    receipt = _receipt_base(repo_slug=repo_slug, ruleset_path=ruleset_path, command="apply")
    receipt["required_checks"] = _required_status_checks(desired)
    receipt["desired_ruleset"] = _ruleset_summary(desired)
    try:
        repo_info = _api_request(method="GET", path=f"/repos/{owner}/{repo}", token=token)
        rulesets, attempted_api_calls = _load_live_ruleset_details(owner=owner, repo=repo, token=token)
        receipt["visibility"] = "PRIVATE" if bool(repo_info.get("private")) else "PUBLIC"
        receipt["default_branch"] = str(repo_info.get("default_branch", "")).strip()
        receipt["attempted_api_calls"] = [f"GET /repos/{owner}/{repo}", *attempted_api_calls]
        matching_row = None
        matching_id = None
        for row in rulesets:
            if not isinstance(row, dict):
                continue
            matched, _ = _candidate_matches(desired=desired, live=row)
            if matched:
                matching_row = row
                matching_id = row.get("id")
                break
            if str(row.get("name", "")).strip() == str(desired.get("name", "")).strip() and str(row.get("target", "")).strip() == str(
                desired.get("target", "")
            ).strip():
                matching_id = row.get("id")
        if matching_row is not None:
            receipt["status"] = "PASS"
            receipt["claim_admissible"] = True
            receipt["active_ruleset"] = _ruleset_summary(matching_row)
            receipt["active_ruleset"]["id"] = matching_row.get("id")
            receipt["next_action"] = "Ruleset already active; rerun program.github.ruleset.verify to mint active receipt."
            return receipt
        if matching_id is not None:
            applied = _api_request(
                method="PUT",
                path=f"/repos/{owner}/{repo}/rulesets/{matching_id}",
                token=token,
                body=desired,
            )
            receipt["attempted_api_calls"].append(f"PUT /repos/{owner}/{repo}/rulesets/{matching_id}")
        else:
            applied = _api_request(method="POST", path=f"/repos/{owner}/{repo}/rulesets", token=token, body=desired)
            receipt["attempted_api_calls"].append(f"POST /repos/{owner}/{repo}/rulesets")
        receipt["applied_ruleset"] = _ruleset_summary(applied if isinstance(applied, dict) else {})
        receipt["status"] = "PASS"
        receipt["claim_admissible"] = True
        receipt["next_action"] = "Ruleset apply completed; rerun program.github.ruleset.verify and attach the active receipt."
        return receipt
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body
        try:
            parsed = json.loads(body)
            message = str(parsed.get("message", body))
        except Exception:  # noqa: BLE001
            pass
        receipt["status"] = "BLOCKED"
        receipt["claim_admissible"] = False
        receipt["platform_block"] = {"http_status": int(exc.code), "message": message}
        receipt["next_action"] = "Enable GitHub branch protection capability for this repository and rerun program.github.ruleset.apply."
        return receipt


def _write_receipt(out_path: Path, receipt: Dict[str, Any]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Apply or verify the committed GitHub main ruleset desired state.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("apply", "verify"):
        sp = sub.add_parser(name)
        sp.add_argument("--repo-slug", default="")
        sp.add_argument("--ruleset", default=DEFAULT_RULESET_PATH)
        sp.add_argument("--out", default=DEFAULT_RECEIPT_PATH)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_slug = _repo_slug(str(args.repo_slug))
    out_path = _resolve_path(str(args.out))
    if args.cmd == "apply":
        receipt = apply_ruleset(repo_slug=repo_slug, ruleset_path=str(args.ruleset))
    else:
        receipt = verify_ruleset(repo_slug=repo_slug, ruleset_path=str(args.ruleset))
    _write_receipt(out_path, receipt)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
