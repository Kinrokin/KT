from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import run_bounded_forward_streams
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


LANE = "KT_LANGUAGE_NORMALIZATION_AND_BOUNDED_E2E_COMPLETION_SUPERLANE_V1"
POSTURE = (
    "H06_EXTERNAL_REAUDIT_DEFERRED__INDEPENDENT_ATTESTATION_REQUIRED__"
    "CONTINUE_PREP_SHADOW_AND_INTERNAL_CAPABILITY_COMPLETION_UNDER_CLAIM_CEILING"
)
TARGET_OUTCOME = (
    "KT_BOUNDED_LAUNCH_WEDGE_READY__INDEPENDENT_ATTESTATION_PENDING__"
    "ADAPTIVE_CAPABILITY_SHADOW_CONTINUES"
)

OUTPUTS = {
    "terminology_matrix": "governance/terminology_translation_matrix.json",
    "plain_glossary": "docs/current/kt_plain_language_glossary.md",
    "reviewer_readme": "external/reviewer_plain_language_readme.md",
    "bounded_launch_language_pack": "commercial/bounded_launch_language_pack.md",
    "blocked_claims_plain_language": "commercial/blocked_claims_plain_language.md",
    "current_vs_archive_context_policy": "repo_cleanup/current_vs_archive_context_policy.md",
    "live_context_budget_policy": "repo_cleanup/live_context_budget_policy.yaml",
    "language_normalization_receipt": "KT_PROD_CLEANROOM/reports/language_normalization_receipt.json",
    "bounded_launch_readiness_delta_receipt": "KT_PROD_CLEANROOM/reports/bounded_launch_readiness_delta_receipt.json",
}

CLAIM_SCANNED_OUTPUTS = (
    "plain_glossary",
    "reviewer_readme",
    "bounded_launch_language_pack",
    "blocked_claims_plain_language",
    "current_vs_archive_context_policy",
    "live_context_budget_policy",
)

TERMINOLOGY_ROWS: list[Dict[str, Any]] = [
    {
        "internal_term": "Truth Lock",
        "external_term": "Current State Lock",
        "usage": "Use for reviewer and buyer explanations of current canonical state.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Claim Ceiling",
        "external_term": "Allowed Claims Boundary",
        "usage": "Use when describing which statements are supported by current evidence.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Forbidden Claims",
        "external_term": "Blocked Claims",
        "usage": "Use for claims that current evidence does not support.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Superlane",
        "external_term": "End-to-End Workstream",
        "usage": "Use for a complete multi-step delivery corridor.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Highway",
        "external_term": "Execution Lane",
        "usage": "Use for a governed category of work with receipts and gates.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Gear",
        "external_term": "Internal Gate",
        "usage": "Use for an intermediate step inside a workstream.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "FP0",
        "external_term": "Runtime/Context Efficiency Overlay",
        "usage": "Use for no-claim-expansion runtime, local execution, and context-efficiency work.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Frontier Ingestion",
        "external_term": "Research Signal Intake",
        "usage": "Use for non-authoritative research-pattern tracking.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Authority World Model",
        "external_term": "Claim Impact Simulator",
        "usage": "Use for simulation of how a change could affect allowed claims.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Lobe",
        "external_term": "Specialist Module",
        "usage": "Use for bounded specialist components.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Router",
        "external_term": "Routing Controller",
        "usage": "Use for policy that selects a module or path.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Learned Router",
        "external_term": "Candidate Routing Policy",
        "usage": "Use until evaluation proves a stronger routing policy.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Crucible",
        "external_term": "Evaluation Scenario",
        "usage": "Use for preregistered stress or benchmark cases.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Epoch",
        "external_term": "Development Phase",
        "usage": "Use for staged development or training periods.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Civilization Stack",
        "external_term": "Adaptive Orchestration Stack",
        "usage": "Use for future adaptive modules; do not describe as production-complete.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "S-tier",
        "external_term": "Category Leadership Claim",
        "usage": "Blocked until readjudication evidence exists.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Beyond-SOTA",
        "external_term": "Do not use; blocked until independent benchmark evidence exists.",
        "usage": "Blocked phrase for public, reviewer, and buyer materials.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "7B Amplification",
        "external_term": "Small-Model Substrate Ablation Study",
        "usage": "Use for an ablation program only; proof remains unproven.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "Commercial Activation",
        "external_term": "Commercial Claim Authorization",
        "usage": "Use for claim authority, not payment or deployment availability.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "External Reaudit",
        "external_term": "Independent External Review",
        "usage": "Use while independent review acceptance remains pending.",
        "machine_label_preserved": True,
    },
    {
        "internal_term": "External Attestation",
        "external_term": "Independent Review Attestation",
        "usage": "Use for the outside reviewer artifact that KT must not self-author.",
        "machine_label_preserved": True,
    },
]


def _write_text_stable(path: Path, text: str) -> bool:
    normalized = text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    if path.exists() and path.read_text(encoding="utf-8-sig").replace("\r\n", "\n") == normalized:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized, encoding="utf-8", newline="\n")
    return True


def _read_output_text(root: Path, output_key: str) -> str:
    return (root / OUTPUTS[output_key]).read_text(encoding="utf-8-sig")


def _terminology_matrix() -> Dict[str, Any]:
    return {
        "schema_id": "kt.language_normalization.terminology_translation_matrix.v1",
        "artifact_id": "KT_TERMINOLOGY_TRANSLATION_MATRIX",
        "lane": LANE,
        "authority": "REFERENCE_ONLY_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "internal_machine_vocabulary_preserved": True,
        "machine_outcome_ids_must_not_be_renamed_without_migration": True,
        "human_facing_translation_required": True,
        "claim_expansion_allowed": False,
        "terms": TERMINOLOGY_ROWS,
    }


def _plain_glossary() -> str:
    rows = "\n".join(
        f"| {row['internal_term']} | {row['external_term']} | {row['usage']} |" for row in TERMINOLOGY_ROWS
    )
    return f"""# KT Plain-Language Glossary

This glossary is for reviewer, buyer, and operator-facing explanations. It does not rename machine outcome IDs, receipts, validator constants, or canonical lane labels.

Current state in plain language:

```text
Independent external review attestation is pending. Internal launch-wedge, shadow, benchmark, runtime/context-efficiency, and adaptive-development work may continue under the allowed claims boundary.
```

| Internal machine term | External/plain-language term | Use |
| --- | --- | --- |
{rows}

Machine labels remain authoritative inside validators and receipts. Human-facing materials should use the external terms unless quoting a machine identifier.
"""


def _reviewer_readme() -> str:
    return """# KT Reviewer Plain-Language Readme

KT is a governed evidence, replay, and claim-control system prepared for bounded pilot review.

Current review status:

- The current state lock has validated enough internal evidence to keep building under a bounded claim boundary.
- Independent external review attestation is still pending and must come from a reviewer outside KT.
- The launch wedge is limited to verifier, evidence-pack, and claim-compiler workflows.
- Runtime/context efficiency, execution-lane shadowing, adaptive orchestration, training, and benchmark work may continue as internal or shadow work without expanding claims.

What this does not claim:

- It does not claim independent external review acceptance.
- It does not authorize unrestricted commercial claims.
- It does not prove small-model substrate superiority.
- It does not claim category leadership.
- It does not claim an adaptive orchestration stack is production-complete.

Reviewer task:

Inspect the evidence pack, run the listed commands, compare public language against the allowed claims boundary, and return an independent review attestation only if the evidence supports it.
"""


def _bounded_launch_language_pack() -> str:
    return """# Bounded Launch Language Pack

Allowed short description:

```text
KT is a governed evidence, replay, and claim-control system available for bounded pilot review while independent external review attestation remains pending.
```

Allowed longer description:

```text
KT packages verifier, evidence-pack, and claim-compiler workflows so technical reviewers can inspect what happened, what evidence supports it, and which claims remain blocked by the current allowed claims boundary.
```

Use these substitutions in public, buyer, reviewer, and support materials:

- Use "current state lock" instead of internal state-lock terminology.
- Use "execution lane" or "end-to-end workstream" instead of internal routing metaphors.
- Use "runtime/context efficiency overlay" for FP0 work.
- Use "specialist module" for lobe work.
- Use "adaptive orchestration stack" for future adaptive architecture.
- Use "small-model substrate ablation study" for 7B-related benchmark work.

Boundary:

Independent external review remains pending. Commercial claim authorization remains blocked. Benchmark and adaptive claims remain evidence-gated.
"""


def _blocked_claims_plain_language() -> str:
    return """# Blocked Claims Plain-Language Guide

These claims are blocked by the current allowed claims boundary. Do not use them in buyer, reviewer, public, support, README, or launch materials.

Forbidden language:

```text
externally audited
independently certified
beyond-SOTA
S-tier
7B amplification proven
commercially activated without limitation
fully ratified autonomous civilization stack
```

Plain replacement:

- Say independent external review attestation is pending.
- Say bounded pilot review is available for verifier, evidence-pack, and claim-compiler workflows.
- Say runtime/context efficiency and adaptive capability work continue in internal, prep, or shadow mode.
- Say benchmark claims require preregistered evidence and independent review where applicable.
"""


def _current_vs_archive_context_policy() -> str:
    return """# Current vs Archive Context Policy

Purpose: keep agents, reviewers, and operators focused on current authority without deleting historical proof.

Current context should load first:

- current state and allowed claims boundary
- current blocker ledger
- current receipts and validation reports
- current launch-wedge documents
- current external attestation intake package
- active operator tools and tests

Archive context should be indexed, hashable, and searchable, but not default-loaded:

- old branch-bound artifacts
- superseded packet drafts
- historical generated reports
- old conversation exports
- forensic dumps
- stale proof bundles

Cleanup mode:

Demote, hash, archive, and index stale material. Do not delete proof unless a separate retention/deletion authority exists.
"""


def _live_context_budget_policy() -> str:
    return """schema_id: kt.repo_cleanup.live_context_budget_policy.v1
authority: PREP_ONLY_CONTEXT_POLICY
current_context_first: true
delete_authorized: false
archive_before_move_required: true
default_load:
  - governance/current_claim_ceiling.json
  - governance/allowed_launch_claims.json
  - governance/forbidden_launch_claims.json
  - KT_PROD_CLEANROOM/reports/bounded_launch_readiness_delta_receipt.json
  - KT_PROD_CLEANROOM/reports/language_normalization_receipt.json
  - external/attestation_collection_packet.json
  - commercial/bounded_launch_language_pack.md
  - docs/current/kt_plain_language_glossary.md
archive_index_first:
  - repo_cleanup/archive_manifest.json
  - repo_cleanup/historical_receipt_index.json
  - repo_cleanup/generated_artifact_retirement_plan.json
claim_boundary:
  external_audit_accepted: false
  commercial_claims_authorized: false
  seven_b_amplification_proven: false
  category_leadership_claim_authorized: false
"""


def _scan_outputs(root: Path, output_keys: Iterable[str]) -> Dict[str, Any]:
    violations: list[Dict[str, Any]] = []
    checked: list[str] = []
    for key in output_keys:
        raw_path = OUTPUTS[key]
        checked.append(raw_path)
        violations.extend(run_bounded_forward_streams.scan_claim_text(_read_output_text(root, key), source=raw_path))
    return {
        "checked_files": checked,
        "violation_count": len(violations),
        "violations": violations,
        "claim_boundary_passed": not violations,
    }


def _language_receipt(root: Path, claim_scan: Dict[str, Any]) -> Dict[str, Any]:
    matrix = root / OUTPUTS["terminology_matrix"]
    return {
        "schema_id": "kt.language_normalization.receipt.v1",
        "artifact_id": "KT_LANGUAGE_NORMALIZATION_RECEIPT",
        "lane": LANE,
        "authority": "HUMAN_FACING_TRANSLATION_NO_CLAIM_EXPANSION",
        "generated_utc": utc_now_iso_z(),
        "canonical_posture": POSTURE,
        "terminology_matrix_path": OUTPUTS["terminology_matrix"],
        "terminology_matrix_present": matrix.is_file(),
        "terminology_matrix_is_reference_not_claim_surface": True,
        "machine_outcome_ids_renamed": False,
        "validator_constants_renamed": False,
        "human_facing_language_normalized": True,
        "claim_scan": claim_scan,
        "claim_boundary_passed": bool(claim_scan.get("claim_boundary_passed")),
        "external_audit_accepted": False,
        "commercial_claims_authorized": False,
        "seven_b_amplification_proven": False,
        "category_leadership_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
    }


def _bounded_launch_delta_receipt(root: Path, claim_scan: Dict[str, Any]) -> Dict[str, Any]:
    required_paths = [
        OUTPUTS["plain_glossary"],
        OUTPUTS["reviewer_readme"],
        OUTPUTS["bounded_launch_language_pack"],
        OUTPUTS["blocked_claims_plain_language"],
        "commercial/quickstart.md",
        "commercial/operator_runbook.md",
        "commercial/deployment_profiles.yaml",
        "commercial/evidence_pack_manifest.json",
        "external/attestation_collection_packet.json",
        "repo_cleanup/archive_manifest.json",
        OUTPUTS["current_vs_archive_context_policy"],
        OUTPUTS["live_context_budget_policy"],
    ]
    missing = [path for path in required_paths if not (root / path).is_file()]
    ready = not missing and bool(claim_scan.get("claim_boundary_passed"))
    return {
        "schema_id": "kt.bounded_launch.readiness_delta_receipt.v1",
        "artifact_id": "KT_BOUNDED_LAUNCH_READINESS_DELTA_RECEIPT",
        "lane": LANE,
        "authority": "BOUNDED_LAUNCH_READINESS_NO_EXTERNAL_ATTESTATION",
        "generated_utc": utc_now_iso_z(),
        "canonical_posture": POSTURE,
        "target_outcome": TARGET_OUTCOME,
        "bounded_launch_wedge_ready_candidate": ready,
        "independent_attestation_pending": True,
        "external_audit_accepted": False,
        "commercial_claims_authorized": False,
        "seven_b_amplification_proven": False,
        "category_leadership_claim_authorized": False,
        "adaptive_capability_shadow_continues": True,
        "required_paths_checked": required_paths,
        "missing_paths": missing,
        "claim_scan_passed": bool(claim_scan.get("claim_boundary_passed")),
        "next_lawful_moves": [
            "COLLECT_INDEPENDENT_EXTERNAL_REVIEW_ATTESTATION",
            "CONTINUE_HIGHWAY_SHADOW_WARN_PROOF_UNDER_CLAIM_CEILING",
            "CONTINUE_RUNTIME_CONTEXT_EFFICIENCY_OVERLAY_WITHOUT_CLAIM_EXPANSION",
            "CONTINUE_ADAPTIVE_CAPABILITY_TRAINING_SHADOW_CORRIDOR",
            "CONTINUE_BENCHMARK_CONSTITUTION_PREP_AND_SCORECARDS",
        ],
    }


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    changed: list[str] = []
    if write_json_stable(root / OUTPUTS["terminology_matrix"], _terminology_matrix()):
        changed.append(OUTPUTS["terminology_matrix"])
    text_outputs = {
        "plain_glossary": _plain_glossary(),
        "reviewer_readme": _reviewer_readme(),
        "bounded_launch_language_pack": _bounded_launch_language_pack(),
        "blocked_claims_plain_language": _blocked_claims_plain_language(),
        "current_vs_archive_context_policy": _current_vs_archive_context_policy(),
        "live_context_budget_policy": _live_context_budget_policy(),
    }
    for key, text in text_outputs.items():
        if _write_text_stable(root / OUTPUTS[key], text):
            changed.append(OUTPUTS[key])

    claim_scan = _scan_outputs(root, CLAIM_SCANNED_OUTPUTS)
    language_receipt = _language_receipt(root, claim_scan)
    delta_receipt = _bounded_launch_delta_receipt(root, claim_scan)
    if write_json_stable(root / OUTPUTS["language_normalization_receipt"], language_receipt):
        changed.append(OUTPUTS["language_normalization_receipt"])
    if write_json_stable(root / OUTPUTS["bounded_launch_readiness_delta_receipt"], delta_receipt):
        changed.append(OUTPUTS["bounded_launch_readiness_delta_receipt"])

    summary = {
        "lane": LANE,
        "target_outcome": TARGET_OUTCOME,
        "changed_outputs": changed,
        "language_normalization_receipt": language_receipt,
        "bounded_launch_readiness_delta_receipt": delta_receipt,
    }
    if not claim_scan.get("claim_boundary_passed"):
        raise RuntimeError(f"FAIL_CLOSED: normalized language claim scan failed: {claim_scan['violations']}")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run KT language normalization and bounded E2E completion prep.")
    parser.add_argument("--json", action="store_true", help="Print a JSON summary.")
    args = parser.parse_args()
    summary = run()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(TARGET_OUTCOME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
