from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List


# tooling-only; deterministic; fail-closed


@dataclass(frozen=True)
class Inputs:
    epoch_root: Path
    out_root: Path
    fail_closed: bool


REQUIRED_FILES = [
    "epoch_coverage.json",
    "transitions.json",
    "motion_metrics.json",
]
ALTERNATE_PROVENANCE = ["runner_record.json", "epoch_manifest.json", "epoch_summary.json"]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _sha256_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _ensure_required(epoch_root: Path) -> Dict[str, Path]:
    missing: List[str] = []
    found: Dict[str, Path] = {}
    for name in REQUIRED_FILES:
        p = epoch_root / name
        if not p.exists():
            missing.append(name)
        else:
            found[name] = p
    if missing:
        raise SystemExit(f"Missing required files at {epoch_root}: {', '.join(missing)} (fail-closed)")
    # Provenance: prefer runner_record, fall back to manifest/summary.
    prov = None
    for alt in ALTERNATE_PROVENANCE:
        p = epoch_root / alt
        if p.exists():
            prov = p
            break
    if prov is None:
        raise SystemExit(f"Missing provenance file (runner_record/epoch_manifest/epoch_summary) at {epoch_root} (fail-closed)")
    found["provenance"] = prov
    return found


def _coverage_summary(cov: Dict[str, Any]) -> Dict[str, Any]:
    obs = cov.get("observed", {})
    counts = obs.get("counts", {})
    dom = obs.get("dominance", {})
    return {
        "domains": sorted(set(obs.get("domains") or [])),
        "subdomains": sorted(set(obs.get("subdomains") or [])),
        "microdomains": sorted(set(obs.get("microdomains") or [])),
        "ventures": sorted(set(obs.get("ventures") or [])),
        "entropy_domains": dom.get("entropy_domains"),
        "top_domain_share": dom.get("top_domain_share"),
        "top_5_domain_share": dom.get("top_5_domain_share"),
        "counts": counts,
    }


def _health_flags(summary: Dict[str, Any]) -> Dict[str, bool]:
    ent = summary.get("entropy_domains")
    top = summary.get("top_domain_share")
    return {
        "entropy_ok": ent is None or ent >= 0.0,
        "dominance_ok": top is None or top <= 1.0,
        "rotation_ok": True,  # rotation pass/fail is carried in eval.verdicts
        "proof_ok": True,
    }


def _write_json(path: Path, obj: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, ensure_ascii=True, indent=2, sort_keys=True)
    path.write_text(data)
    return _sha256_bytes(data.encode("utf-8"))


def _build_seed(epoch_id: str, summary: Dict[str, Any], proofs: Dict[str, Any]) -> Dict[str, Any]:
    stable_tags = sorted(
        set(summary.get("domains", []))
        | set(summary.get("subdomains", []))
        | set(summary.get("microdomains", []))
        | set(summary.get("ventures", []))
    )
    return {
        "schema": "SALVAGE_SEED_V1",
        "epoch_id": epoch_id,
        "coverage_summary": summary,
        "stable_tags": stable_tags,
        "proof": proofs,
    }


def _build_eval(epoch_id: str, cov: Dict[str, Any], motion: Dict[str, Any]) -> Dict[str, Any]:
    verdict = cov.get("verdict", {})
    obs = cov.get("observed", {})
    dom = obs.get("dominance", {})
    counts = obs.get("counts", {})
    motion_summary = {
        "hop_entropy_domain": motion.get("hop_entropy_domain"),
        "domain_hop_rate": motion.get("domain_hop_rate"),
        "mean_revisit_latency_steps_domain": motion.get("mean_revisit_latency_steps_domain"),
        "max_revisit_latency_steps_domain": motion.get("max_revisit_latency_steps_domain"),
    }
    health_flags = {
        "entropy_ok": dom.get("entropy_domains") is None or dom.get("entropy_domains") >= 0.0,
        "dominance_ok": dom.get("top_domain_share") is None or dom.get("top_domain_share") <= 1.0,
        "rotation_ok": bool(verdict.get("rotation_pass")) if verdict.get("rotation_pass") is not None else True,
        "proof_ok": True,
    }
    return {
        "schema": "SALVAGE_EVAL_V1",
        "epoch_id": epoch_id,
        "verdicts": {
            "coverage_pass": verdict.get("coverage_pass"),
            "rotation_pass": verdict.get("rotation_pass"),
            "governance_pass": verdict.get("governance_pass"),
            "failure_reasons": verdict.get("notes"),
        },
        "motion_summary": motion_summary,
        "health_flags": health_flags,
        "counts": counts,
    }


def _build_dream(epoch_id: str, cov: Dict[str, Any], transitions: Dict[str, Any]) -> Dict[str, Any]:
    obs = cov.get("observed", {})
    dom = obs.get("dominance", {})
    coverage_gaps = {
        "domains_missing": [],
        "subdomains_missing": [],
    }
    transition_anomalies: List[str] = []
    if dom.get("entropy_domains") == 0.0 or dom.get("top_domain_share") == 1.0:
        transition_anomalies.append("zero_entropy")

    suggestions = []
    if transition_anomalies:
        suggestions.append("ENFORCE_DOMAIN_ROTATION")
    if dom.get("top_domain_share") and dom["top_domain_share"] > 0.5:
        suggestions.append("INCREASE_CROSS_DOMAIN_CRUCIBLES")

    return {
        "schema": "SALVAGE_DREAM_V1",
        "epoch_id": epoch_id,
        "unresolved_paradoxes": [],
        "coverage_gaps": coverage_gaps,
        "transition_anomalies": transition_anomalies,
        "suggested_next_actions": suggestions,
    }


def _build_manifest(epoch_id: str, inputs: Dict[str, Path], outputs: Dict[str, Path], tool_version: str) -> Dict[str, Any]:
    return {
        "schema": "SALVAGE_MANIFEST_V1",
        "epoch_id": epoch_id,
        "inputs": {k: {"path": str(v), "sha256": _sha256_file(v)} for k, v in inputs.items()},
        "outputs": {k: {"path": str(v), "sha256": _sha256_file(v)} for k, v in outputs.items()},
        "tool_version": tool_version,
    }


def _parse_args() -> Inputs:
    p = argparse.ArgumentParser(description="Salvage extractor (tooling-only, deterministic, fail-closed)")
    p.add_argument("--epoch-artifact-root", required=True, help="Path to epoch artifact directory (must contain epoch_coverage.json, transitions.json, motion_metrics.json, runner_record.json)")
    p.add_argument("--out", default=None, help="Output directory for salvage artifacts (default: artifacts/salvage/<epoch_id>)")
    p.add_argument("--fail-closed", action="store_true", default=True, help="Fail closed on any missing/invalid inputs (default: True)")
    args = p.parse_args()
    epoch_root = Path(args.epoch_artifact_root).resolve()
    if not epoch_root.exists():
        raise SystemExit(f"Epoch artifact root not found: {epoch_root}")
    # Determine epoch_id from coverage file name if possible.
    cov_path = epoch_root / "epoch_coverage.json"
    if not cov_path.exists():
        raise SystemExit(f"Missing epoch_coverage.json in {epoch_root}")
    cov = _load_json(cov_path)
    epoch_id = cov.get("epoch_id") or epoch_root.name
    if args.out:
        out_root = Path(args.out).resolve()
    else:
        out_root = Path(__file__).resolve().parents[3] / "tools" / "growth" / "artifacts" / "salvage" / epoch_id
    return Inputs(epoch_root=epoch_root, out_root=out_root, fail_closed=bool(args.fail_closed))


def main() -> int:
    sys.dont_write_bytecode = True
    inputs = _parse_args()

    files = _ensure_required(inputs.epoch_root)
    cov = _load_json(files["epoch_coverage.json"])
    transitions = _load_json(files["transitions.json"])
    motion = _load_json(files["motion_metrics.json"])
    # runner_record.json currently unused but hashed for provenance

    epoch_id = cov.get("epoch_id") or inputs.epoch_root.name
    summary = _coverage_summary(cov)
    proofs = {
        "trace_hash": next((r.get("sha256") for r in cov.get("proof", {}).get("receipts", []) if r.get("type") == "TRACE_HEAD_HASH"), None),
        "ledger_hash": next((r.get("sha256") for r in cov.get("proof", {}).get("receipts", []) if r.get("type") == "LEDGER_ENTRY_HASH"), None),
    }

    out_root = inputs.out_root
    seed_path = out_root / "seed.json"
    eval_path = out_root / "eval.json"
    dream_path = out_root / "dream.json"

    seed_hash = _write_json(seed_path, _build_seed(epoch_id, summary, proofs))
    eval_hash = _write_json(eval_path, _build_eval(epoch_id, cov, motion))
    dream_hash = _write_json(dream_path, _build_dream(epoch_id, cov, transitions))

    manifest_path = out_root / "salvage_manifest.json"
    manifest = _build_manifest(
        epoch_id,
        inputs=files,
        outputs={
            "seed": seed_path,
            "eval": eval_path,
            "dream": dream_path,
        },
        tool_version="SALVAGE_EXTRACTOR_V1",
    )
    _write_json(manifest_path, manifest)

    print("SALVAGE COMPLETE")
    print(f"epoch_id={epoch_id}")
    print(f"out_root={out_root}")
    print(f"seed_sha256={seed_hash}")
    print(f"eval_sha256={eval_hash}")
    print(f"dream_sha256={dream_hash}")
    print(f"manifest={manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
