from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


def _add_dream_to_syspath() -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))


_add_dream_to_syspath()

from dream_generator import generate_candidates, prompt_for_candidate  # noqa: E402
from dream_schemas import DreamSchemaError, DreamSpecSchema  # noqa: E402


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, ensure_ascii=True), encoding="utf-8")


class TestDreamLoop(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        payload = {
            "schema": "kt.dream.spec",
            "schema_version": 1,
            "dream_id": "DREAM-1",
            "hypothesis": "h",
            "kernel_target": "V2_SOVEREIGN",
            "seed": 0,
            "candidate_bounds": {"max_candidates": 2, "max_hypothesis_chars": 1024, "max_prompt_chars": 1024},
            "budget_caps": {"time_ms": 1000, "stdout_max_bytes": 1024, "stderr_max_bytes": 0, "runner_memory_max_mb": 64, "kernel_timeout_kill_ms": 1500},
            "extra": 1,
        }
        with self.assertRaises(DreamSchemaError):
            DreamSpecSchema.from_dict(payload)

    def test_deterministic_candidate_generation(self) -> None:
        payload = {
            "schema": "kt.dream.spec",
            "schema_version": 1,
            "dream_id": "DREAM-1",
            "hypothesis": "h",
            "kernel_target": "V2_SOVEREIGN",
            "seed": 0,
            "candidate_bounds": {"max_candidates": 2, "max_hypothesis_chars": 1024, "max_prompt_chars": 2048},
            "budget_caps": {"time_ms": 1000, "stdout_max_bytes": 1024, "stderr_max_bytes": 0, "runner_memory_max_mb": 64, "kernel_timeout_kill_ms": 1500},
        }
        spec = DreamSpecSchema.from_dict(payload)
        a = generate_candidates(spec)
        b = generate_candidates(spec)
        self.assertEqual([c.candidate_id for c in a.candidates], [c.candidate_id for c in b.candidates])

    def test_prompt_length_bound_enforced(self) -> None:
        payload = {
            "schema": "kt.dream.spec",
            "schema_version": 1,
            "dream_id": "DREAM-1",
            "hypothesis": "x" * 900,
            "kernel_target": "V2_SOVEREIGN",
            "seed": 0,
            "candidate_bounds": {"max_candidates": 2, "max_hypothesis_chars": 1024, "max_prompt_chars": 128},
            "budget_caps": {"time_ms": 1000, "stdout_max_bytes": 1024, "stderr_max_bytes": 0, "runner_memory_max_mb": 64, "kernel_timeout_kill_ms": 1500},
        }
        spec = DreamSpecSchema.from_dict(payload)
        gen = generate_candidates(spec)
        with self.assertRaises(Exception):
            prompt_for_candidate(spec=spec, candidate=gen.candidates[0])


if __name__ == "__main__":
    raise SystemExit(unittest.main())
