from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, repo_root, write_failure_artifacts, write_json_worm
from tools.operator.truth_authority import (
    CURRENT_POINTER_REL,
    active_truth_source_ref,
    compatibility_surface_is_non_authoritative,
    load_json_ref,
    truth_source_ref_is_active_or_compatibility_pointer,
)


POLICY_REL = "KT_PROD_CLEANROOM/governance/documentary_truth_policy.json"
BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"
READINESS_REL = "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"
CURRENT_STATE_REL = "KT_PROD_CLEANROOM/reports/current_state_receipt.json"
RUNTIME_AUDIT_REL = "KT_PROD_CLEANROOM/reports/runtime_closure_audit.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build_documentary_truth_report(*, root: Path) -> Dict[str, Any]:
    policy = _load_json(root / POLICY_REL)
    board = _load_json(root / BOARD_REL)
    readiness = _load_json(root / READINESS_REL)
    active_source = active_truth_source_ref(root=root)
    load_json_ref(root=root, ref=active_source)
    supporting = [str(item).strip() for item in policy.get("active_supporting_truth_surfaces", []) if str(item).strip()]
    documentary = [str(item).strip() for item in policy.get("documentary_only_patterns", []) if str(item).strip()]
    documentary_refs = [str(item).strip() for item in policy.get("documentary_only_refs", []) if str(item).strip()]
    board_source = str(board.get("authoritative_current_head_truth_source", "")).strip()
    readiness_source = str(readiness.get("authoritative_truth_source", "")).strip()
    main_pointer = _load_json(root / CURRENT_POINTER_REL) if active_source != CURRENT_POINTER_REL else {}

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def _check(check_id: str, ok: bool, **payload: Any) -> None:
        row = {"check": check_id, "status": "PASS" if ok else "FAIL"}
        row.update(payload)
        checks.append(row)
        if not ok:
            failures.append(check_id)

    _check(
        "active_current_head_truth_source_declared",
        bool(active_source),
        actual=active_source,
    )
    _check(
        "execution_board_uses_policy_active_source",
        truth_source_ref_is_active_or_compatibility_pointer(
            candidate_ref=board_source,
            active_source_ref=active_source,
            compatibility_payload=main_pointer,
        ),
        actual=board_source,
        expected=active_source,
    )
    _check(
        "readiness_scope_uses_policy_active_source",
        truth_source_ref_is_active_or_compatibility_pointer(
            candidate_ref=readiness_source,
            active_source_ref=active_source,
            compatibility_payload=main_pointer,
        ),
        actual=readiness_source,
        expected=active_source,
    )
    _check(
        "supporting_truth_surfaces_declared",
        bool(supporting),
        supporting_truth_surfaces=supporting,
    )
    _check(
        "current_pointer_not_documentary_only",
        all(entry != active_source for entry in documentary_refs),
        documentary_only_refs=documentary_refs,
        documentary_only_patterns=documentary,
    )
    _check(
        "active_truth_source_not_redeclared_as_supporting_surface",
        all(entry != active_source for entry in supporting),
        active_supporting_truth_surfaces=supporting,
    )

    if active_source != CURRENT_POINTER_REL:
        main_current_state = _load_json(root / CURRENT_STATE_REL)
        main_runtime_audit = _load_json(root / RUNTIME_AUDIT_REL)
        _check(
            "main_current_pointer_marked_documentary_only",
            compatibility_surface_is_non_authoritative(
                ref=CURRENT_POINTER_REL,
                active_source_ref=active_source,
                payload=main_pointer,
                documentary_refs=documentary_refs,
            ),
            documentary_only_refs=documentary_refs,
        )
        _check(
            "main_current_state_marked_documentary_only",
            compatibility_surface_is_non_authoritative(
                ref=CURRENT_STATE_REL,
                active_source_ref=active_source,
                payload=main_current_state,
                documentary_refs=documentary_refs,
            ),
            documentary_only_refs=documentary_refs,
        )
        _check(
            "main_runtime_audit_marked_documentary_only",
            compatibility_surface_is_non_authoritative(
                ref=RUNTIME_AUDIT_REL,
                active_source_ref=active_source,
                payload=main_runtime_audit,
                documentary_refs=documentary_refs,
            ),
            documentary_only_refs=documentary_refs,
        )

    return {
        "schema_id": "kt.operator.documentary_truth_validation_receipt.v1",
        "status": "PASS" if not failures else "FAIL",
        "active_current_head_truth_source": active_source,
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate active vs documentary truth policy boundaries.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="documentary-truth-validate", requested_run_root=str(args.run_root))
    try:
        report = build_documentary_truth_report(root=repo_root())
        write_json_worm(run_dir / "reports" / "documentary_truth_validation_receipt.json", report, label="documentary_truth_validation_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.documentary_truth.validate",
                failure_name="DOCUMENTARY_TRUTH_INVALID",
                message="; ".join(report.get("failures", [])),
                next_actions=[
                    "Point the execution board and readiness scope at the generated current pointer.",
                    "Keep documentary markdown surfaces out of active truth authority.",
                ],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.documentary_truth.validate",
            failure_name="DOCUMENTARY_TRUTH_INVALID",
            message=str(exc),
            next_actions=["Inspect documentary_truth_policy.json, execution_board.json, and readiness_scope_manifest.json."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
