from __future__ import annotations

import json
from pathlib import Path

from eval_schemas import BenchmarkSuiteSchema, EvalSchemaError


def load_suite(path: Path) -> BenchmarkSuiteSchema:
    if path.suffix.lower() != ".json":
        raise EvalSchemaError("Benchmark suite must be .json (fail-closed)")
    raw = path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    return BenchmarkSuiteSchema.from_dict(payload)
