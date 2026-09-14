from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from scripts import check_artifact_authority_registry as authority
from scripts import check_no_bloat as bloat


ROOT = Path(__file__).resolve().parents[1]


def write_json(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def row(path, identity):
    return {"artifact_id": identity, "path": path, "role": "canonical_source",
            "primary_class": "CANONICAL_SOURCE", "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PENDING", "controls_execution": False,
            "claim_authority": "NONE", "sha256": None, "current_authority": False,
            "current_file_sha256": hashlib.sha256(b"pass\n").hexdigest()}


@pytest.fixture
def checkout(tmp_path):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "source.py").write_bytes(b"pass\n")
    subprocess.run(["git", "add", "source.py"], cwd=tmp_path, check=True)
    write_json(tmp_path, "reports/repo_pristine_census_v1.json", {"duplicate_current_authority_status": "PASS"})
    write_json(tmp_path, "reports/repo_path_length_risk_index_v1.json", {"blocker_count": 0})
    write_json(tmp_path, "governance/repo_layout_contract.json", {"current_packet": None})
    write_json(tmp_path, "packets/current/manifest.json", {"packets": []})
    write_json(tmp_path, "registry/artifact_authority_registry.schema.json",
               json.loads((ROOT / "registry/artifact_authority_registry.schema.json").read_text(encoding="utf-8")))
    write_json(tmp_path, "registry/artifact_authority_registry.json",
               {"schema_id": "kt.artifact_authority_registry.v3", "current_head": "fixture",
                "generated_utc": "fixture", "artifact_count": 1,
                "digest_semantics": {"sha256": "HISTORICAL_REGISTRATION_BYTES",
                                     "current_file_sha256": "CURRENT_REPOSITORY_BYTES",
                                     "self_excluded_path": "registry/artifact_authority_registry.json"},
                "artifacts": [row("source.py", "one")]})
    return tmp_path


def change_registry(root, mutate):
    name = "registry/artifact_authority_registry.json"
    value = json.loads((root / name).read_text(encoding="utf-8"))
    mutate(value)
    write_json(root, name, value)


def test_valid_registry_and_shared_source_roles(checkout):
    (checkout / "other.py").write_bytes(b"pass\n")
    change_registry(checkout, lambda r: (r["artifacts"].append(row("other.py", "two")), r.update(artifact_count=2)))
    assert authority.check(checkout) == []
    assert bloat.check(checkout) == []


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: r["artifacts"][0].pop("primary_class"), "missing required field primary_class"),
    (lambda r: r["artifacts"][0].update(primary_class="INVENTED"), "outside declared enum"),
    (lambda r: r["artifacts"][0].update(controls_execution="false"), "invalid type"),
    (lambda r: r["artifacts"][0].update(current_authority="false"), "invalid type"),
    (lambda r: r.update(artifact_count=8), "artifact_count"),
    (lambda r: r.update(artifacts=[None]), "expected object"),
    (lambda r: r["artifacts"].append(row("source.py", "two")), "duplicate artifact path"),
    (lambda r: r["artifacts"].append(row("other.py", "one")), "duplicate artifact_id"),
    (lambda r: r["artifacts"][0].update(path="../source.py"), "repository-relative"),
])
def test_invalid_registry_fails_with_named_diagnostic(checkout, mutate, expected):
    change_registry(checkout, mutate)
    assert any(expected in error for error in authority.check(checkout))


def test_new_tracked_file_requires_registration(checkout):
    (checkout / "new.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "add", "new.py"], cwd=checkout, check=True)
    assert "registry missing tracked file: new.py" in authority.check(checkout)


def test_historical_digest_does_not_substitute_for_current_bytes(checkout):
    change_registry(checkout, lambda r: r["artifacts"][0].update(sha256="0" * 64))
    assert authority.check(checkout) == []
    (checkout / "source.py").write_bytes(b"changed\n")
    assert any("stale current file digest" in error for error in authority.check(checkout))


@pytest.mark.parametrize("state", ["ARCHIVE", "STALE", "SUPERSEDED", "RETIRED"])
def test_historical_execution_and_claim_escalation_fail(checkout, state):
    change_registry(checkout, lambda r: r["artifacts"][0].update(
        authority_state=state, controls_execution=True, current_authority=True,
        claim_authority="CURRENT_HEAD"))
    errors = authority.check(checkout)
    assert any("cannot control current execution" in error for error in errors)
    assert any("cannot elevate current claims" in error for error in errors)


@pytest.mark.parametrize("path", ["/absolute.py", "C:/escape.py", "nested/../../escape.py"])
def test_absolute_and_escaping_registered_paths_fail(checkout, path):
    change_registry(checkout, lambda r: r["artifacts"][0].update(path=path))
    assert any("repository-relative" in error for error in authority.check(checkout))


def test_link_escape_is_rejected(checkout, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "outside.py"
    outside.write_bytes(b"pass\n")
    link = checkout / "linked.py"
    link.symlink_to(outside)
    change_registry(checkout, lambda r: r["artifacts"][0].update(path="linked.py"))
    assert any("link/reparse" in error for error in authority.check(checkout))


@pytest.mark.parametrize("path", ["source.py.", "source.py ", "nested. /source.py"])
def test_windows_trailing_path_aliases_fail(checkout, path):
    change_registry(checkout, lambda r: r["artifacts"][0].update(path=path))
    assert any("nonportable trailing dot or space" in error for error in authority.check(checkout))


def test_global_packet_selection_does_not_create_permission(checkout):
    assert authority.current_packet_errors([]) == []
    packet = {**row("source.py", "one"), "primary_class": "CANONICAL_PACKET_CURRENT",
              "authority_state": "LIVE_CURRENT_HEAD_VALIDATED", "validation_status": "PASS",
              "controls_execution": True, "current_authority": True}
    assert authority.current_packet_errors([packet]) == []
    assert authority.current_packet_errors([packet, {**packet, "path": "other.py", "artifact_id": "two"}])
    assert authority.current_packet_errors([{**packet, "authority_scope": "invented_scope"}])
    assert authority.current_packet_errors([{**packet, "authority_state": "STALE"}])


def test_stale_manifest_cannot_resurrect_a_packet(checkout):
    write_json(checkout, "packets/current/manifest.json", {"packets": [
        {"path": "packets/ktbud100_v1.zip", "current_authority": True, "sha256": "0" * 64}]})
    assert any("no-packet selection conflicts" in e for e in authority.check(checkout))


def test_duplicate_report_keys_cannot_hide_a_blocker(checkout):
    (checkout / "reports/repo_path_length_risk_index_v1.json").write_text(
        '{"blocker_count": 1, "blocker_count": 0}', encoding="utf-8")
    assert any("duplicate JSON key" in error for error in bloat.check(checkout))


def test_duplicate_registry_keys_cannot_replace_authority(checkout):
    path = checkout / "registry/artifact_authority_registry.json"
    text = path.read_text(encoding="utf-8").replace('"controls_execution": false',
                                                  '"controls_execution": true, "controls_execution": false')
    path.write_text(text, encoding="utf-8")
    assert any("duplicate JSON key" in error for error in authority.check(checkout))


@pytest.mark.parametrize("root", bloat.GROWTH_ROOTS)
def test_force_added_runtime_output_fails_even_with_old_pass_reports(checkout, root):
    for policy in bloat.POLICY_FILES:
        path = checkout / policy
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("policy", encoding="utf-8")
        subprocess.run(["git", "add", "--", policy], cwd=checkout, check=True)
    assert bloat.check(checkout) == []
    leak = root + "run/receipt.json"
    write_json(checkout, leak, {"status": "PASS"})
    subprocess.run(["git", "add", "--force", "--", leak], cwd=checkout, check=True)
    assert f"tracked runtime output: {leak}" in bloat.check(checkout)


@pytest.mark.parametrize("value", [{}, {"blocker_count": False}, {"blocker_count": -1}, [], None])
def test_malformed_retained_report_does_not_default_to_pass(checkout, value):
    write_json(checkout, "reports/repo_path_length_risk_index_v1.json", value)
    assert any("blocker_count" in error for error in bloat.check(checkout))


@pytest.mark.parametrize("module_mode", [False, True])
def test_census_check_preserves_all_existing_bytes_and_paths(checkout, module_mode):
    (checkout / "scripts").mkdir()
    for name in ("repo_pristine_census.py", "check_no_bloat.py", "check_artifact_authority_registry.py"):
        shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
    # Preserve a deliberately noncanonical manifest: validation must never replace it with BUD100.
    write_json(checkout, "packets/current/manifest.json", {"packets": [], "preserve": "existing authority"})

    def snapshot():
        return {str(p.relative_to(checkout)): hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
                for p in checkout.rglob("*")}

    before = snapshot()
    argv = ["-m", "scripts.repo_pristine_census"] if module_mode else ["scripts/repo_pristine_census.py"]
    result = subprocess.run([sys.executable, "-B", *argv, "--check"], cwd=checkout,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr + result.stdout
    assert json.loads(result.stdout)["mode"] == "read_only"
    assert snapshot() == before
    change_registry(checkout, lambda registry: registry["artifacts"][0].pop("primary_class"))
    blocked_before = snapshot()
    blocked = subprocess.run([sys.executable, "-B", *argv, "--check"], cwd=checkout,
                             env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, text=True)
    assert blocked.returncode == 1, blocked.stderr + blocked.stdout
    assert json.loads(blocked.stdout)["mode"] == "read_only"
    assert snapshot() == blocked_before
