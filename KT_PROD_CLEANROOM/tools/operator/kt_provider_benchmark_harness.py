from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


BENCHMARK_GOVERNING_STATEMENT = (
    "KT does not claim small models are secretly giant models. KT tests where governed substrate makes smaller "
    "models act above class, and proves where it does not."
)

AUTHORITY = "PREP_ONLY"

PROVIDERS = (
    "CoreWeave / Kimi K2.6",
    "OpenAI model",
    "Anthropic model",
    "Gemini model",
    "local 7B",
    "local 14B",
    "local 32B",
    "best available open model",
)

WORKLOADS = (
    "author lane packet",
    "validate packet",
    "repair review finding",
    "generate tests",
    "parse JSON",
    "run proof replay",
    "create audit summary",
    "handle long-horizon repo task",
    "recover from failed review",
    "maintain claim ceiling",
)


def build_scorecard() -> Dict[str, Any]:
    return {
        "schema_id": "kt.provider_benchmark_harness.scorecard.v1",
        "artifact_id": "KT_PROVIDER_BENCHMARK_HARNESS_SCORECARD_PREP_ONLY",
        "generated_utc": utc_now_iso_z(),
        "authority": AUTHORITY,
        "status": "PREP_ONLY",
        "governing_statement": BENCHMARK_GOVERNING_STATEMENT,
        "metric": "lawful_replayable_progress_per_dollar",
        "providers": list(PROVIDERS),
        "workloads": list(WORKLOADS),
        "cannot_authorize_package_promotion": True,
        "cannot_authorize_commercial_activation_claims": True,
        "cannot_open_r6": True,
        "cannot_mutate_truth_engine_law": True,
        "cannot_mutate_trust_zone_law": True,
        "cannot_claim_7b_amplification_proven": True,
        "output_status": "schema_only_no_benchmark_run_executed",
    }


def run(*, output: Optional[Path] = None) -> Dict[str, Any]:
    root = repo_root()
    output = output or root / "KT_PROD_CLEANROOM/reports/kt_provider_bakeoff_scorecard_prep_only.json"
    payload = build_scorecard()
    write_json_stable(output, payload)
    return payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="KT provider/runtime benchmark harness prep-only scaffold")
    parser.add_argument("--output", default="KT_PROD_CLEANROOM/reports/kt_provider_bakeoff_scorecard_prep_only.json")
    args = parser.parse_args(argv)
    payload = run(output=(repo_root() / args.output).resolve())
    print(payload["output_status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
