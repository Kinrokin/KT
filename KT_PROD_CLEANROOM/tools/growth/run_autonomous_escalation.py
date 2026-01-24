import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
import tempfile

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_ORCH_DIR = _REPO_ROOT / "KT_PROD_CLEANROOM" / "tools" / "growth" / "orchestrator"
if str(_ORCH_DIR) not in sys.path:
    sys.path.insert(0, str(_ORCH_DIR))

ROOT = Path("KT_PROD_CLEANROOM")
ARTIFACT_EPOCHS = ROOT / "tools" / "growth" / "artifacts" / "epochs"
from tools.growth.state.lane_to_epoch import resolve_epoch_spec, lane_for_plan
from tools.growth.orchestrator.epoch_orchestrator import run_epoch_from_plan
from tools.growth.state.cce_state import update_state as update_cce_state
from tools.growth.state.oce_state import update_state as update_oce_state
from tools.growth.state.rwrp_state import update_state as update_rwrp_state

SESSION_TAG = int(time.time() * 1000)


def run_plan(plan_path: Path, *, quiet: bool = False) -> Dict[str, any]:
    """Execute a single epoch plan via orchestrator (canonical API)."""
    return run_epoch_from_plan(
        plan_path=plan_path,
        resume=False,
        mode="salvage",
        salvage_out_root=ROOT / "tools" / "growth" / "artifacts" / "salvage",
        auto_bump=True,
        quiet=quiet,
    )


def latest_epoch_root() -> Path:
    roots = [p for p in ARTIFACT_EPOCHS.iterdir() if p.is_dir()]
    return max(roots, key=lambda p: p.stat().st_mtime)


def run_plan_suggester() -> Dict[str, any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_REPO_ROOT)
    cmd = [
        "python",
        "-m",
        "tools.growth.state.plan_suggester",
        "--epochs-dir",
        str(ARTIFACT_EPOCHS),
        "--write-epoch",
        "--append-log",
    ]
    subprocess.run(cmd, env=env, check=True)
    plan = latest_epoch_root() / "plan_suggestion.json"
    if not plan.exists():
        raise RuntimeError("plan_suggestion.json missing after suggester run (fail-closed)")
    return json.loads(plan.read_text(encoding="utf-8"))


def select_plan(recommendation: Dict[str, any]) -> Path:
    internal = recommendation.get("recommended_lane_internal", "")
    if not internal:
        raise RuntimeError("recommended_lane_internal missing (fail-closed)")
    return resolve_epoch_spec(internal)


def parse_args():
    parser = argparse.ArgumentParser(description="Autonomous escalation run script.")
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="Number of autonomous epochs to execute.",
    )
    parser.add_argument(
        "--shadow-policy",
        action="store_true",
        help="Enable lane-policy shadow logging (observer-only; no execution authority).",
    )
    parser.add_argument(
        "--policy-log",
        type=Path,
        default=ROOT / "tools" / "growth" / "state" / "lane_policy_comparison.jsonl",
        help="Path to append policy-vs-heuristic audit rows (JSONL).",
    )
    return parser.parse_args()


def _append_jsonl(path: Path, payload: Dict[str, any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")


def _state_text_from_suggestion(suggestion: Dict[str, any]) -> str:
    signals = suggestion.get("signals") or {}
    parts = [
        "KT_STATE_V1",
        f"forced_resolve_count={signals.get('forced_resolve_count', 0)}",
        f"low_coherence_count={signals.get('low_coherence_count', 0)}",
        f"unique_domains={signals.get('unique_domains', 0)}",
        f"unique_subdomains={signals.get('unique_subdomains', 0)}",
        f"entropy_domains={signals.get('entropy_domains', 0.0)}",
        f"hop_entropy_domain={signals.get('hop_entropy_domain', 0.0) or 0.0}",
        f"domain_hop_rate={signals.get('domain_hop_rate', 0.0) or 0.0}",
        f"map_domain_count={signals.get('map_domain_count', 0)}",
    ]
    return "\n".join(parts)


def _write_baseline_suggestion(epoch_root: Path) -> None:
    """Emit a bootstrap plan_suggestion.json for the baseline run so history is well-formed."""
    payload = {
        "schema": "PLAN_SUGGESTION_V1",
        "epoch_id": epoch_root.name,
        "epoch_hash": None,
        "epoch_profile": None,
        "epoch_verdict": None,
        "kernel_target": None,
        "recommended_lane": "coverage_lane",
        "recommended_lane_internal": "COVERAGE_HOP_RECOVERY",
        "bootstrap": True,
        "triggered_rules": [],
        "confidence": 0.0,
        "signals": {"coverage_fatigue": 0.0},
        "constraints": {"advisory_only": True, "does_not_gate": True, "does_not_mutate_plans": True},
    }
    # Write as compact JSON (single line) to avoid multi-line parsing issues downstream.
    (epoch_root / "plan_suggestion.json").write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")


def _session_suffix(label: str, idx: int | None = None) -> str:
    parts = [label, str(SESSION_TAG)]
    if idx is not None:
        parts.append(f"RUN{idx:03d}")
    return "_".join(parts)


def _prepare_runtime_plan(base_plan: Path, suffix: str) -> Path:
    data = json.loads(base_plan.read_text(encoding="utf-8"))
    base_id = data.get("epoch_id") or base_plan.stem
    data["epoch_id"] = f"{base_id}_{suffix}"
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(data, tmp, sort_keys=True, indent=2, ensure_ascii=True)
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def main() -> None:
    args = parse_args()
    os.environ["KT_LIVE"] = "0"
    os.environ["KT_LIVE_PROOF"] = ""

    shadow_enabled = args.shadow_policy or (os.environ.get("KT_POLICY_SHADOW", "").strip() == "1")
    policy = None
    if shadow_enabled:
        try:
            from tools.growth.state.kt_lane_policy import build_default_policy

            policy = build_default_policy()
        except Exception as exc:
            print(f"[shadow-policy] disabled (could not load policy): {exc}")
            policy = None

    print("=== STEP A: baseline coverage ===")
    baseline_plan = resolve_epoch_spec("COVERAGE_HOP_RECOVERY")
    runtime_baseline = _prepare_runtime_plan(baseline_plan, _session_suffix("BASE"))
    try:
        baseline_summary = run_plan(runtime_baseline)
    finally:
        runtime_baseline.unlink(missing_ok=True)
    try:
        update_cce_state(executed_lane=lane_for_plan(baseline_plan), epoch_id=baseline_summary.get("epoch_id", "BOOTSTRAP"))
        update_oce_state(executed_lane=lane_for_plan(baseline_plan), epoch_id=baseline_summary.get("epoch_id", "BOOTSTRAP"))
    except Exception as exc:
        print(f"[baseline] CCE update failed: {exc}", file=sys.stderr)
    try:
        _write_baseline_suggestion(latest_epoch_root())
    except Exception as exc:
        print(f"[baseline] could not write bootstrap plan_suggestion.json: {exc}", file=sys.stderr)
    # Ensure at least two epochs exist so plan_suggester can run.
    epoch_roots = [p for p in ARTIFACT_EPOCHS.iterdir() if p.is_dir()]
    if len(epoch_roots) < 2:
        print("=== Seeding second baseline coverage for history ===")
        second_plan = resolve_epoch_spec("COVERAGE_HOP_RECOVERY")
        runtime_second = _prepare_runtime_plan(second_plan, _session_suffix("BASELINE"))
        try:
            run_plan(runtime_second)
        finally:
            runtime_second.unlink(missing_ok=True)
        try:
            _write_baseline_suggestion(latest_epoch_root())
        except Exception as exc:
            print(f"[baseline-2] could not write bootstrap plan_suggestion.json: {exc}", file=sys.stderr)

    records = []
    lane_counter = Counter()
    for idx in range(1, args.iterations + 1):
        suggestion = run_plan_suggester()
        suggested_lane = suggestion.get("recommended_lane")
        suggested_internal = suggestion.get("recommended_lane_internal")
        plan_path = select_plan(suggestion)
        plan_key = plan_path.name
        signals = suggestion.get("signals", {})
        record = {
            "iteration": idx,
            "epoch": suggestion.get("epoch_id"),
            "suggestion_consumed": True,
            "suggested_lane": suggested_lane,
            "suggested_lane_internal": suggested_internal,
            "forced": signals.get("forced_resolve_count", 0),
            "low_coherence": signals.get("low_coherence_count", 0),
            "entropy": signals.get("entropy_domains", 0.0),
            "plan_run": plan_key,
        }
        print(f"\n=== ITERATION {idx}: suggested {record['suggested_lane_internal']} -> running {plan_key} ===")

        if policy is not None:
            state_text = _state_text_from_suggestion(suggestion)
            try:
                policy_result = policy.predict(state_text)
                # ---- MERGE POLICY INTO RECORD (CRITICAL) ----
                record["policy_lane"] = policy_result.get("recommendation")
                record["policy_confidence"] = policy_result.get("confidence")
                record["policy_distribution"] = policy_result.get("probs")
                record["policy_used"] = policy_result.get("policy_used")
                _append_jsonl(
                    args.policy_log,
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "iteration": idx,
                        "epoch_id": suggestion.get("epoch_id"),
                        "heuristic_lane": suggested_lane,
                        "heuristic_lane_internal": suggested_internal,
                        "plan_run": plan_key,
                        "policy_lane": policy_result.get("recommendation"),
                        "policy_confidence": policy_result.get("confidence"),
                        "policy_distribution": policy_result.get("probs"),
                        "policy_used": policy_result.get("policy_used"),
                        "state_text": state_text,
                    },
                )
            except Exception as exc:
                record["policy_error"] = str(exc)

        runtime_plan = _prepare_runtime_plan(plan_path, _session_suffix("RUN", idx))
        try:
            summary = run_plan(runtime_plan)
        finally:
            runtime_plan.unlink(missing_ok=True)
        try:
            executed_lane = lane_for_plan(plan_path)
            updated = update_cce_state(executed_lane=executed_lane, epoch_id=summary.get("epoch_id", "UNKNOWN"))
            try:
                update_oce_state(executed_lane=executed_lane, epoch_id=summary.get("epoch_id", "UNKNOWN"))
            except Exception as exc:  # noqa: BLE001
                record["oce_update_error"] = str(exc)
                print(f"[OCE] update failed: {exc}", file=sys.stderr)
            record["cce_state"] = {
                "coverage_cost": updated.coverage_cost,
                "coverage_streak": updated.coverage_streak,
                "decay_events": updated.decay_events,
            }
        except Exception as exc:
            record["cce_update_error"] = str(exc)
            print(f"[CCE] update failed: {exc}", file=sys.stderr)
        # Regret-weighted replay penalty update requires regret; attempt best-effort
        try:
            rg = summary.get("regret_global") if isinstance(summary, dict) else None
            # If epoch_regret.json exists in epoch root, prefer that.
            epoch_root = latest_epoch_root()
            regret_path = epoch_root / "epoch_regret.json"
            if regret_path.exists():
                try:
                    rg = json.loads(regret_path.read_text(encoding="utf-8")).get("regret_global")
                except Exception:
                    pass
            if rg is not None:
                update_rwrp_state(executed_lane=executed_lane, epoch_id=summary.get("epoch_id", "UNKNOWN"), regret_global=rg)
        except Exception as exc:
            record["rwrp_update_error"] = str(exc)
            print(f"[RWRP] update failed: {exc}", file=sys.stderr)
        records.append(record)
        lane_counter[plan_key] += 1

    summary = {
        "runs": len(records),
        "forced_total": sum(r["forced"] for r in records),
        "low_total": sum(r["low_coherence"] for r in records),
        "consecutive_bad_coverage": _consecutive_bad_coverage(records),
    }
    summary["lane_counts"] = dict(lane_counter)
    print("\n=== AUTONOMOUS ESCALATION SUMMARY ===")
    print(json.dumps(summary, indent=2))
    Path("autonomous_escalation_log.json").write_text(json.dumps(records, indent=2))
    print("Details saved to autonomous_escalation_log.json")


def _consecutive_bad_coverage(records):
    max_streak = 0
    current = 0
    for rec in records:
        if rec["plan_run"] == "coverage" and (rec["forced"] > 0 or rec["low_coherence"] > 0):
            current += 1
            max_streak = max(max_streak, current)
        else:
            current = 0
    return max_streak


if __name__ == "__main__":
    main()
