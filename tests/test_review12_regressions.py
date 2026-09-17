from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "KT_PROD_CLEANROOM/tools/growth/eval_harness_plus"))
sys.path.insert(0, str(ROOT / "KT_PROD_CLEANROOM/tools/growth/orchestrator"))

from KT_PROD_CLEANROOM.tools.growth import analyze_escalation
from KT_PROD_CLEANROOM.tools.growth.state import compute_epoch_regret, plan_suggester
from KT_PROD_CLEANROOM.tools.growth.orchestrator import epoch_orchestrator, epoch_schemas
from KT_PROD_CLEANROOM.tools.growth.eval_harness_plus import eval_plus_runner
from scripts.artifact_authority_registry_writer import merge_registry_entries


def test_growth_readers_follow_canonical_hyphenated_crucibles(tmp_path):
    epoch = tmp_path / "EPOCH-TEST"
    (epoch / "CRU-GOV-HONESTY-01").mkdir(parents=True)
    payload = {"steps": [{"domain": "governance"}, {"domain": "math"}]}
    (epoch / "CRU-GOV-HONESTY-01" / "micro_steps.json").write_text(json.dumps(payload), encoding="utf-8")
    entropy, domains = analyze_escalation.micro_stats(epoch)
    assert domains == 2 and entropy > 0
    assert compute_epoch_regret._collect_micro_steps(epoch)
    assert plan_suggester._collect_micro_steps(epoch)


def test_eval_plus_rejects_windows_portability_chars():
    import pytest
    with pytest.raises(ValueError, match="nonportable_path_component"):
        eval_plus_runner._reject_nonportable_path_components(path=Path("safe:alias"), label="epoch_dir")
    with pytest.raises(ValueError, match="nonportable_path_component"):
        eval_plus_runner._reject_nonportable_path_components(path=Path("safe\\alias"), label="epoch_dir")


def test_epoch_schema_rejects_boolean_integer():
    import pytest
    with pytest.raises(epoch_schemas.EpochSchemaError, match="must be an integer"):
        epoch_schemas._require_int(True, name="max_concurrency", lo=1, hi=4)


def test_growth_root_relative_override_is_cleanroom_anchored(monkeypatch):
    monkeypatch.setenv("KT_GROWTH_ARTIFACTS_ROOT", "relative-root")
    assert epoch_orchestrator._growth_artifacts_root() == epoch_orchestrator._CLEANROOM_ROOT / "relative-root"


def test_debug_run_roots_is_forwarded(monkeypatch, tmp_path):
    seen = {}
    def fake_run_epoch(*args, **kwargs):
        seen.update(kwargs)
        return {"epoch_id": "E", "epoch_profile": "P", "epoch_verdict": "V", "crucibles_passed": 0, "crucibles_total": 0}
    monkeypatch.setattr(epoch_orchestrator, "run_epoch", fake_run_epoch)
    epoch_orchestrator.run_epoch_from_plan(plan_path=tmp_path / "unused.json", debug_run_roots=True)
    assert seen["debug_run_roots"] is True


def test_registry_merge_rejects_normalized_alias():
    import pytest
    registry = {"artifacts": [{"artifact_id": "A", "path": "source.py"}]}
    with pytest.raises(ValueError, match="aliases admitted canonical path"):
        merge_registry_entries(registry, [{"artifact_id": "B", "path": "SOURCE.PY"}])
