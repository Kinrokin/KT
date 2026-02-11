from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.verification.fl3_canonical import repo_root_from


class ReplayError(RuntimeError):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ReplayError(f"Unreadable JSON (fail-closed): {path.as_posix()}") from exc


def _require_dict(obj: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ReplayError(f"{name} must be object (fail-closed)")
    return obj


def _truthy_bool(obj: Any, *, name: str) -> bool:
    if not isinstance(obj, bool):
        raise ReplayError(f"{name} must be boolean (fail-closed)")
    return obj


def replay_from_evidence_dir(*, evidence_dir: Path) -> Dict[str, Any]:
    evidence_dir = evidence_dir.resolve()
    job_dir = evidence_dir / "job_dir"
    if not job_dir.exists():
        raise ReplayError("Missing job_dir/ in evidence pack (fail-closed)")

    eval_report = _require_dict(_read_json(job_dir / "eval_report.json"), name="eval_report.json")
    promotion = _require_dict(_read_json(job_dir / "promotion.json"), name="promotion.json")

    utility_floor_pass = _truthy_bool(eval_report.get("utility_floor_pass"), name="eval_report.utility_floor_pass")
    utility_verdict = "PASS" if utility_floor_pass else "FAIL"

    probe_policy = _require_dict(eval_report.get("probe_policy"), name="eval_report.probe_policy")
    fail_on_disagreement = _truthy_bool(probe_policy.get("fail_on_disagreement"), name="probe_policy.fail_on_disagreement")
    try:
        tolerance = float(probe_policy.get("tolerance"))
    except Exception as exc:  # noqa: BLE001
        raise ReplayError("probe_policy.tolerance must be numeric (fail-closed)") from exc
    if tolerance < 0.0:
        raise ReplayError("probe_policy.tolerance must be >= 0 (fail-closed)")

    probes = eval_report.get("metric_probes")
    if not isinstance(probes, list) or len(probes) < 1:
        raise ReplayError("eval_report.metric_probes must be non-empty list (fail-closed)")

    disagreements = 0
    for idx, p in enumerate(probes):
        pd = _require_dict(p, name=f"metric_probe[{idx}]")
        if "agreement" in pd:
            agreement = _truthy_bool(pd.get("agreement"), name=f"metric_probe[{idx}].agreement")
        else:
            try:
                delta = float(pd.get("delta"))
            except Exception as exc:  # noqa: BLE001
                raise ReplayError(f"metric_probe[{idx}].delta must be numeric when agreement missing (fail-closed)") from exc
            agreement = delta <= tolerance
        if not agreement:
            disagreements += 1

    probe_verdict = "FAIL" if (fail_on_disagreement and disagreements > 0) else "PASS"
    combined_eval_verdict = "PASS" if (utility_verdict == "PASS" and probe_verdict == "PASS") else "FAIL"

    final_verdict = eval_report.get("final_verdict")
    if final_verdict not in {"PASS", "FAIL"}:
        raise ReplayError("eval_report.final_verdict must be PASS or FAIL (fail-closed)")
    if final_verdict != combined_eval_verdict:
        raise ReplayError("eval_report.final_verdict inconsistent with utility/probe receipts (fail-closed)")

    decision = str(promotion.get("decision", ""))
    if decision not in {"PROMOTE", "NO_PROMOTE"}:
        raise ReplayError("promotion.decision invalid (fail-closed)")

    report: Dict[str, Any] = {
        "status": "PASS",
        "inputs": {"evidence_dir": evidence_dir.as_posix()},
        "computed": {
            "utility_verdict": utility_verdict,
            "probe_agreement_verdict": probe_verdict,
            "final_eval_verdict": combined_eval_verdict,
            "promotion_decision": decision,
        },
        "checks": {
            "eval_report_final_verdict_consistent": True,
            "metric_probe_disagreements": disagreements,
        },
    }
    return report


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Replay FL4 receipts deterministically from an evidence pack directory.")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out", required=True)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _ = repo_root_from(Path(__file__))  # fail-fast if repo root is not detectable
    args = _parse_args(argv)
    evidence_dir = Path(args.evidence_dir)
    out_path = Path(args.out)
    report = replay_from_evidence_dir(evidence_dir=evidence_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReplayError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

