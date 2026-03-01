from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _read_json_dict(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL_CLOSED: unreadable JSON {label}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        _fail_closed(f"{label} must be a JSON object: {path.as_posix()}")
    return obj


def _write_json_worm(path: Path, obj: Dict[str, Any], label: str) -> None:
    write_text_worm(path=path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label=label)


def _find_first(run_root: Path, rel: str) -> Optional[Path]:
    hits = sorted(run_root.rglob(rel))
    for p in hits:
        if p.is_file():
            return p.resolve()
    return None


def _proposal_id(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Titan feedback engine (proposal-only). Reads run artifacts and emits governed suggestions (no mutations)."
    )
    ap.add_argument("--run-root", required=True, help="Run root directory to scan for artifacts (read-only).")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM; must be empty).")
    ap.add_argument("--seed", type=int, default=0, help="Deterministic seed (reserved for future use).")
    args = ap.parse_args(argv)

    run_root = Path(args.run_root).resolve()
    if not run_root.is_dir():
        _fail_closed("run_root missing")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    _ = int(args.seed)

    # Optional evidence inputs.
    suite_fitness_path = _find_first(run_root, "suite_fitness_record.json")
    drift_path = _find_first(run_root, "mve_drift_report.json")
    capture_path = _find_first(run_root, "mve_capture_resistance_report.json")
    fitness_path = _find_first(run_root, "multiversal_fitness.json")

    proposals: List[Dict[str, Any]] = []

    if suite_fitness_path is not None:
        sf = _read_json_dict(suite_fitness_path, label="suite_fitness_record")
        region = str(sf.get("region", "")).strip().upper()
        pass_rate = sf.get("pass_rate")
        if region == "C" and isinstance(pass_rate, (int, float)) and float(pass_rate) > 0.97:
            prop = {
                "proposal_type": "METAMORPHIC_EXPLOSION",
                "why": "suite appears too easy (high pass rate); increase pressure and variance deterministically",
                "recommended_spec": {
                    "variants_per_case": 20,
                    "transforms": [
                        "whitespace",
                        "punctuation",
                        "format",
                        "order",
                        "synonyms",
                        "format_invert",
                        "language_hop",
                        "world_context_tag",
                    ],
                    "counterpressure_level": "mild",
                },
                "evidence_ref": suite_fitness_path.as_posix(),
                "requires_human_review": True,
            }
            prop["proposal_id"] = _proposal_id(prop)
            proposals.append(prop)

    if drift_path is not None:
        drift = _read_json_dict(drift_path, label="mve_drift_report")
        if bool(drift.get("terminal", False)):
            prop = {
                "proposal_type": "INVARIANT_STRENGTHENING",
                "why": "terminal cross-world drift detected; add or tighten invariants and reject at admission",
                "recommended_action": "AUTHOR_NEW_INVARIANTS_AND_ADMIT_VIA_REGISTRY",
                "evidence_ref": drift_path.as_posix(),
                "requires_human_review": True,
            }
            prop["proposal_id"] = _proposal_id(prop)
            proposals.append(prop)

    if capture_path is not None:
        cap = _read_json_dict(capture_path, label="mve_capture_resistance_report")
        if str(cap.get("status", "")).strip().upper() != "PASS":
            prop = {
                "proposal_type": "CAPTURE_RESISTANCE_TIGHTENING",
                "why": "capture-resistance hooks failed; tighten utility floor and anti-theater validators",
                "recommended_action": "AUTHOR_VALIDATOR_CONTRACTS_AND_BIND_THRESHOLDS",
                "evidence_ref": capture_path.as_posix(),
                "requires_human_review": True,
            }
            prop["proposal_id"] = _proposal_id(prop)
            proposals.append(prop)

    if fitness_path is not None:
        mf = _read_json_dict(fitness_path, label="multiversal_fitness")
        wf = mf.get("world_fitness") if isinstance(mf.get("world_fitness"), list) else []
        region_c_worlds = [str(r.get("world_id", "")).strip() for r in wf if isinstance(r, dict) and str(r.get("region", "")).strip().upper() == "C"]
        if region_c_worlds:
            prop = {
                "proposal_type": "QUARANTINE_RECOMMENDATION",
                "why": "Region C present in one or more worlds; promotion is forbidden",
                "world_ids": sorted({w for w in region_c_worlds if w}),
                "recommended_action": "QUARANTINE_AND_REQUIRE_NEW_EVIDENCE",
                "evidence_ref": fitness_path.as_posix(),
                "requires_human_review": True,
            }
            prop["proposal_id"] = _proposal_id(prop)
            proposals.append(prop)

    manifest = {
        "schema_id": "kt.titan_feedback_proposal_manifest.v1",
        "run_root": run_root.as_posix(),
        "inputs": {
            "suite_fitness_record": suite_fitness_path.as_posix() if suite_fitness_path else "",
            "mve_drift_report": drift_path.as_posix() if drift_path else "",
            "mve_capture_resistance_report": capture_path.as_posix() if capture_path else "",
            "multiversal_fitness": fitness_path.as_posix() if fitness_path else "",
        },
        "proposal_count": int(len(proposals)),
        "proposals": proposals,
    }
    _write_json_worm(path=out_dir / "proposal_manifest.json", obj=manifest, label="proposal_manifest.json")

    checklist_lines = [
        "# Titan Feedback Review Checklist",
        "",
        "- Confirm the input run root is admissible and pinned.",
        "- For each proposal: confirm it contains no sensitive payloads (hash references only).",
        "- Approve/reject proposals explicitly; no implicit adoption.",
        "- If approved: admit the resulting pack/world-set/invariants via the Suite Registry Admission Pipeline.",
        "- Record the decision as an append-only admission or rejection artifact.",
        "",
        f"proposals={len(proposals)}",
    ]
    write_text_worm(path=out_dir / "operator_review_checklist.md", text="\n".join(checklist_lines) + "\n", label="operator_review_checklist.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

