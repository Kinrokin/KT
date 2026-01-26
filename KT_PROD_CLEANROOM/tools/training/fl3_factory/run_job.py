from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from tools.training.fl3_factory.budget import (
    FL3BudgetError,
    default_budget_state_path,
    record_job_started,
    unlock_if_needed,
)
from tools.training.fl3_factory.contracts import enforce_allowlists, enforce_entrypoints, load_organ_contract
from tools.training.fl3_factory.io import read_json_object, write_schema_object
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, assert_relpath_under_exports, validate_schema_bound_object


EXIT_OK = 0
EXIT_CONTRACT = 2
EXIT_BUDGET = 3
EXIT_INTERNAL = 4


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True)
    ap.add_argument("--organ-contract", required=True)
    ap.add_argument("--budget-state", default=None)
    ap.add_argument("--unlock-artifact", default=None)
    args = ap.parse_args(argv)

    repo_root = repo_root_from(Path(__file__))

    try:
        job_path = Path(args.job)
        contract_path = Path(args.organ_contract)

        job = read_json_object(job_path)
        validate_schema_bound_object(job)
        contract = load_organ_contract(contract_path)

        budget_state_path = Path(args.budget_state) if args.budget_state else default_budget_state_path(repo_root)
        unlock_path = Path(args.unlock_artifact) if args.unlock_artifact else None
        _ = unlock_if_needed(repo_root=repo_root, budget_state_path=budget_state_path, unlock_artifact_path=unlock_path)
        _ = record_job_started(repo_root=repo_root, budget_state_path=budget_state_path)

        # Enforce entrypoint self-hash and phase entrypoint hashes.
        enforce_entrypoints(contract, repo_root=repo_root)

        # Enforce allowlists declared in the organ contract.
        run_kind = str(job["run_kind"])
        if run_kind == "TOURNAMENT":
            tournament = job.get("tournament")
            if not isinstance(tournament, dict):
                raise FL3ValidationError("tournament jobspec requires tournament object (fail-closed)")
            entrants = tournament.get("entrants")
            if not isinstance(entrants, list) or len(entrants) < 1:
                raise FL3ValidationError("tournament.entrants must be non-empty (fail-closed)")
            max_risk = float(tournament.get("max_risk", 0.5))
            max_strikes = int(tournament.get("max_strikes", 0))
            for ent in entrants:
                if not isinstance(ent, dict):
                    raise FL3ValidationError("tournament entrant must be object (fail-closed)")
                sq = ent.get("signal_quality")
                validate_schema_bound_object(sq)
                if sq.get("schema_id") != "kt.signal_quality.v1":
                    raise FL3ValidationError("tournament entrant signal_quality schema_id mismatch (fail-closed)")
                # Gate: any strikes or high risk blocks tournament entry.
                if int(sq.get("governance_strikes", 0)) > max_strikes:
                    raise FL3ValidationError("tournament entrant has governance strikes (fail-closed)")
                if float(sq.get("risk_estimate", 0.0)) >= max_risk:
                    raise FL3ValidationError("tournament entrant risk too high (fail-closed)")
        required_outputs = [
            "kt.factory.dataset.v1",
            "kt.factory.judgement.v1",
            "kt.factory.train_manifest.v1",
            "kt.factory.eval_report.v1",
        ]
        if run_kind == "TOURNAMENT":
            required_outputs.extend(
                [
                    "kt.blind_judgement_pack.v1",
                    "kt.reveal_mapping.v1",
                    "kt.tournament_manifest.v1",
                ]
            )
        # VRR is a repair lane: it must never produce promotion artifacts.
        if run_kind != "VRR":
            required_outputs.append("kt.factory.promotion.v1")
        enforce_allowlists(
            contract,
            base_model_id=str(job["base_model_id"]),
            training_mode=str(job["training_mode"]),
            output_schema_ids=required_outputs,
            export_roots=[str(job["export_shadow_root"]), str(job["export_promoted_root"])],
        )

        out_root = assert_relpath_under_exports(repo_root=repo_root, relpath=str(job["export_shadow_root"]), allow_promoted=True)
        job_dir = (out_root / str(job["job_id"])).resolve()
        assert_relpath_under_exports(repo_root=repo_root, relpath=str(job_dir.relative_to(repo_root)), allow_promoted=True)
        job_dir.mkdir(parents=True, exist_ok=True)

        # Phase: harvest -> dataset
        from tools.training.fl3_factory.harvest_stub import build_dataset
        dataset = build_dataset(job=job)
        dataset_path = job_dir / "dataset.json"
        dataset_hash = write_schema_object(path=dataset_path, obj=dataset)

        if run_kind == "TOURNAMENT":
            from tools.training.fl3_factory.tournament import (
                build_blind_pack,
                build_reveal_mapping,
                build_tournament_manifest,
                blind_items_from_dataset,
                validate_tournament_artifacts,
            )

            blind_items = blind_items_from_dataset(dataset)
            blind_pack = build_blind_pack(job_id=job["job_id"], items=blind_items)
            blind_pack_path = job_dir / "blind_pack.json"
            _ = write_schema_object(path=blind_pack_path, obj=blind_pack)

            # Sealed mapping exists before judgement but is not used by the judge.
            mappings = {it["candidate_hash"]: {"adapter_id": "UNKNOWN", "adapter_version": "0"} for it in blind_items}
            sealed_mapping = build_reveal_mapping(job_id=job["job_id"], mappings=mappings, sealed=True, verdict_ref=None)
            sealed_path = job_dir / "reveal_mapping.sealed.json"
            _ = write_schema_object(path=sealed_path, obj=sealed_mapping)

            manifest = build_tournament_manifest(
                job_id=job["job_id"],
                blind_pack_ref=str(blind_pack_path.relative_to(repo_root)),
                reveal_mapping_ref=str(sealed_path.relative_to(repo_root)),
            )
            manifest_path = job_dir / "tournament_manifest.json"
            _ = write_schema_object(path=manifest_path, obj=manifest)

            validate_tournament_artifacts(blind_pack=blind_pack, sealed_mapping=sealed_mapping, manifest=manifest)

        # Phase: judge -> judgement
        from tools.training.fl3_factory.judge_stub import build_judgement
        judgement = build_judgement(job=job, dataset=dataset)
        judgement_path = job_dir / "judgement.json"
        judgement_hash = write_schema_object(path=judgement_path, obj=judgement)

        if run_kind == "TOURNAMENT":
            # Unseal mapping only after judgement exists.
            from tools.training.fl3_factory.tournament import unseal_reveal_mapping

            unsealed = unseal_reveal_mapping(
                job_dir=job_dir,
                sealed_mapping=read_json_object(job_dir / "reveal_mapping.sealed.json"),
                verdict_ref=str(judgement_path.relative_to(job_dir)),
            )
            unsealed_path = job_dir / "reveal_mapping.json"
            _ = write_schema_object(path=unsealed_path, obj=unsealed)

        # Phase: train -> train_manifest
        from tools.training.fl3_factory.train_stub import build_train_manifest
        train_manifest = build_train_manifest(job=job, dataset=dataset, out_dir=job_dir)
        train_path = job_dir / "train_manifest.json"
        train_hash = write_schema_object(path=train_path, obj=train_manifest)

        # Phase: eval -> eval_report
        from tools.training.fl3_factory.eval_stub import build_eval_report
        eval_report = build_eval_report(job=job)
        eval_path = job_dir / "eval_report.json"
        eval_hash = write_schema_object(path=eval_path, obj=eval_report)

        if run_kind != "VRR":
            # Phase: promote (stub: always REJECT until FL3 blockers implemented)
            from tools.training.fl3_factory.promote import build_promotion

            promotion = build_promotion(
                job=job,
                decision="REJECT",
                reasons=[dataset_hash, judgement_hash, train_hash, eval_hash],
                links={
                    "dataset_id": dataset["dataset_id"],
                    "judgement_id": judgement["judgement_id"],
                    "train_id": train_manifest["train_id"],
                    "eval_id": eval_report["eval_id"],
                },
            )
            promotion_path = job_dir / "promotion.json"
            _ = write_schema_object(path=promotion_path, obj=promotion)

        return EXIT_OK

    except FL3BudgetError as exc:
        if os.environ.get("KT_FL3_DEBUG") == "1":
            print(f"FL3_BUDGET_FAIL: {exc}", file=sys.stderr)
        return EXIT_BUDGET
    except FL3ValidationError as exc:
        if os.environ.get("KT_FL3_DEBUG") == "1":
            print(f"FL3_CONTRACT_FAIL: {exc}", file=sys.stderr)
        return EXIT_CONTRACT
    except Exception:
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
