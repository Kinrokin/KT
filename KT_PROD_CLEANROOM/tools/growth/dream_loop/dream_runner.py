from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from dream_generator import generate_candidates, prompt_for_candidate
from dream_schemas import DreamRunResultSchema, DreamSchemaError, DreamSpecSchema, sha256_json, sha256_text


@dataclass(frozen=True)
class DreamCandidateRun:
    candidate_id: str
    crucible_path: Path
    run_id: str
    outcome: str
    artifacts_dir: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _growth_root() -> Path:
    return _repo_root() / "tools" / "growth"


def _artifacts_root() -> Path:
    return _growth_root() / "artifacts"


def _write_once(path: Path, text: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load_spec(path: Path) -> DreamSpecSchema:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(raw)
    elif path.suffix.lower() == ".json":
        payload = json.loads(raw)
    else:
        raise DreamSchemaError("dream spec must be .json or .yaml (fail-closed)")
    if not isinstance(payload, dict):
        raise DreamSchemaError("dream spec root must be an object (fail-closed)")
    return DreamSpecSchema.from_dict(payload)


def _c019_runner_cmd(*, crucible_path: Path, kernel_target: str, seed: int) -> List[str]:
    runner = _growth_root() / "crucible_runner.py"
    return [
        str(Path(sys.executable).resolve()),
        str(runner.resolve()),
        "--crucible",
        str(crucible_path.resolve()),
        "--kernel",
        kernel_target,
        "--seed",
        str(seed),
    ]


def _run_crucible(*, crucible_path: Path, kernel_target: str, seed: int) -> Dict[str, Any]:
    cmd = _c019_runner_cmd(crucible_path=crucible_path, kernel_target=kernel_target, seed=seed)
    proc = subprocess.run(cmd, cwd=str(_repo_root()), check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError("C019 runner failed (fail-closed)")
    obj = json.loads(proc.stdout)
    if not isinstance(obj, list) or not obj:
        raise RuntimeError("C019 runner stdout invalid (fail-closed)")
    rec = obj[0]
    if not isinstance(rec, dict):
        raise RuntimeError("C019 runner record invalid (fail-closed)")
    return rec


def _write_crucible_yaml(*, path: Path, crucible_id: str, kernel_target: str, prompt: str, budgets: Dict[str, Any]) -> None:
    payload = {
        "schema": "kt.crucible.spec",
        "schema_version": 1,
        "crucible_id": crucible_id,
        "title": "Dream Candidate Crucible (C020)",
        "domain": "dream",
        "tags": ["dream", "c020", "offline"],
        "kernel_targets": [kernel_target],
        "input": {"mode": "RAW_INPUT_STRING", "prompt": prompt, "redaction_policy": "ALLOW_RAW_IN_CRUCIBLE"},
        "budgets": budgets,
        "expect": {
            "expected_outcome": "PASS",
            "output_contract": {
                "must_be_json": True,
                "required_keys": ["status", "head_hash", "record_count", "thermodynamics"],
                "forbidden_substrings": ["chain-of-thought", "CoT:", "Reasoning:"],
            },
            "replay_verification": "REQUIRED_PASS",
            "governance_expectations": {
                "required_event_types": ["GOV_POLICY_APPLY"],
                "forbidden_event_types": ["STATE_MUTATION", "CURRICULUM_INGEST", "PROVIDER_CALL"],
                "event_count_min": 1,
                "event_count_max": 10,
            },
            "thermo_expectations": {"must_enforce_budget": True, "expected_budget_verdict": "WITHIN_BUDGET"},
        },
    }
    text = yaml.safe_dump(payload, sort_keys=True)
    _write_once(path, text)


def run_dream(*, dream_spec_path: Path) -> Dict[str, Any]:
    spec = _load_spec(dream_spec_path)
    generated = generate_candidates(spec)

    dream_root = _artifacts_root() / "dream_loop" / spec.dream_id
    _write_once(dream_root / "dream_spec.snapshot.yaml", dream_spec_path.read_text(encoding="utf-8"))

    result_path = dream_root / "dream_result.json"
    if result_path.exists():
        existing = json.loads(result_path.read_text(encoding="utf-8"))
        if isinstance(existing, dict):
            return existing
        raise DreamSchemaError("Existing dream_result.json invalid (fail-closed)")

    candidate_runs: List[DreamCandidateRun] = []
    receipt_refs: List[str] = []

    for candidate in generated.candidates[: spec.candidate_bounds.max_candidates]:
        prompt = prompt_for_candidate(spec=spec, candidate=candidate)
        crucible_id = f"DREAM-{spec.dream_id}-{candidate.candidate_id}"
        candidate_dir = dream_root / "candidates" / candidate.candidate_id
        crucible_path = candidate_dir / "crucible.yaml"
        _write_crucible_yaml(
            path=crucible_path,
            crucible_id=crucible_id,
            kernel_target=spec.kernel_target,
            prompt=prompt,
            budgets=spec.budget_caps.to_crucible_budgets(),
        )

        rec = _run_crucible(crucible_path=crucible_path, kernel_target=spec.kernel_target, seed=spec.seed)
        run_id = str(rec.get("run_id"))
        outcome = str(rec.get("outcome"))
        artifacts_dir = str(rec.get("artifacts_dir"))
        candidate_runs.append(DreamCandidateRun(candidate_id=candidate.candidate_id, crucible_path=crucible_path, run_id=run_id, outcome=outcome, artifacts_dir=artifacts_dir))
        receipt_refs.append(artifacts_dir.replace("\\", "/"))

    # Curriculum drafts: hash-only; do not sign or register.
    sys.path.insert(0, str((_growth_root() / "teacher_factory").resolve()))
    from curriculum_compiler import compile_bundle  # noqa: E402
    from teacher_schemas import CurriculumDraftSchema, TeacherInputBundleSchema  # noqa: E402

    bundle_path = dream_root / "teacher_bundle.json"
    runtime_registry_path = _repo_root() / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json"
    bundle_payload = {
        "schema_id": TeacherInputBundleSchema.SCHEMA_ID,
        "schema_version_hash": TeacherInputBundleSchema.SCHEMA_VERSION_HASH,
        "runtime_registry_path": str(runtime_registry_path.resolve()),
        "epoch_manifest_paths": [],
        "run_record_paths": [
            str((_repo_root() / Path(r.artifacts_dir) / "runner_record.json").resolve()) for r in candidate_runs
        ],
        "extract_types": ["RUN_RECORD"],
        "bounds": {"max_examples": 16, "max_instructions": 0, "max_constraints": 0},
    }
    TeacherInputBundleSchema.validate(bundle_payload)
    _write_once(bundle_path, json.dumps(bundle_payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n")

    compiled = compile_bundle(bundle_path)
    package_obj = compiled.package.to_dict()
    draft_payload = {
        "schema_id": CurriculumDraftSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumDraftSchema.SCHEMA_VERSION_HASH,
        "examples": list(package_obj.get("examples") or []),
        "instructions": [],
        "constraints": [],
    }
    CurriculumDraftSchema.validate(draft_payload)
    draft_path = dream_root / "curriculum_draft.json"
    _write_once(draft_path, json.dumps(draft_payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n")

    candidate_hashes = [sha256_json({"candidate_id": c.candidate_id, "scenario_descriptor": c.scenario_descriptor, "bounded_payload": c.bounded_payload}) for c in generated.candidates[: spec.candidate_bounds.max_candidates]]
    determinism_proof = sha256_json(
        {
            "dream_spec_hash": generated.dream_spec_hash,
            "candidate_hashes": sorted(candidate_hashes),
            "receipt_refs": sorted(receipt_refs),
            "draft_hash": sha256_text(draft_path.read_text(encoding="utf-8")),
        }
    )
    result = DreamRunResultSchema(
        dream_id=spec.dream_id,
        dream_spec_hash=generated.dream_spec_hash,
        candidate_ids=tuple(sorted([r.candidate_id for r in candidate_runs])),
        candidate_hashes=tuple(sorted(candidate_hashes)),
        evaluation_receipt_refs=tuple(sorted(receipt_refs)),
        curriculum_draft_refs=(draft_path.as_posix().replace("\\", "/"),),
        determinism_proof=determinism_proof,
        failure_state=None,
    )
    _write_once(result_path, json.dumps(result.to_dict(), sort_keys=True, indent=2, ensure_ascii=True) + "\n")
    return result.to_dict()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="C020 Dream Loop (tooling-only; bounded imagination under law)")
    p.add_argument("--spec", required=True, help="Dream spec YAML/JSON")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    out = run_dream(dream_spec_path=Path(args.spec).resolve())
    print(json.dumps(out, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
