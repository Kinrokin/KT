
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

def emit_governance_verdict(artifact_dir: Path, verdict: str, rationale: str) -> None:
    """Emit a governance_verdict.json artifact with explicit PASS/FAIL and rationale."""
    artifact_path = artifact_dir / "governance_verdict.json"
    obj = {
        "schema_id": "governance.verdict",
        "schema_version": "1.0",
        "verdict": verdict,
        "rationale": rationale,
    }
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=True, indent=2)
