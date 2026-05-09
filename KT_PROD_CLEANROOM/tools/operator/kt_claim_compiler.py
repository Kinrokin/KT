from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from tools.operator.titanium_common import repo_root


AUTHORITY = "PREP_ONLY_TOOLING"
DEFAULT_ALLOWED = [
    "AFSH passed limited-runtime canary under bounded packet law.",
    "Canary evidence review is the next lawful move.",
    "Runtime cutover remains unauthorized.",
    "R6 remains closed.",
    "Package promotion remains unauthorized.",
    "Commercial activation claims remain unauthorized.",
]
DEFAULT_FORBIDDEN = [
    "AFSH is live.",
    "R6 is open.",
    "The router is in production.",
    "Package is promotion-ready.",
    "Commercial activation is authorized.",
]


def compile_claims(reports_root: Path) -> dict:
    allowed_path = reports_root / "kt_allowed_claims_current_state_prep_only.json"
    forbidden_path = reports_root / "kt_forbidden_claims_current_state_prep_only.json"
    allowed = DEFAULT_ALLOWED
    forbidden = DEFAULT_FORBIDDEN
    if allowed_path.exists():
        allowed = json.loads(allowed_path.read_text(encoding="utf-8")).get("allowed_claims", allowed)
    if forbidden_path.exists():
        forbidden = json.loads(forbidden_path.read_text(encoding="utf-8")).get("forbidden_claims", forbidden)
    return {
        "schema_id": "kt.claim_compiler.prep_only.v1",
        "artifact_id": "KT_CLAIM_COMPILER_OUTPUT",
        "authority": AUTHORITY,
        "allowed_claims": allowed,
        "forbidden_claims": forbidden,
        "runtime_cutover_authorized": False,
        "r6_open": False,
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compile KT current-state claims from prep-only claim artifacts.")
    parser.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    args = parser.parse_args(argv)
    reports_root = (repo_root() / args.reports_root).resolve()
    print(json.dumps(compile_claims(reports_root), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
