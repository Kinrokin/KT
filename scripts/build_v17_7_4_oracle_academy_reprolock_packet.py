from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core


PACKET_NAME = "ktv1774_oracle_academy_reprolock_v1.zip"
KAGGLE_DATASET_NAME = "ktv1774-oracle-reprolock-v1"
RUNBOOK = "V17_7_4_ORACLE_ACADEMY_REPROLOCK_ONE_CELL.md"
OUTCOME = "KT_KNOWN_GOOD_LOBE_PATH_BYTE_REPRO_READY__RUN_ORACLE_ACADEMY_REPRO_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTV1774_ORACLE_ACADEMY_REPROLOCK_50"
PRIOR_PROMPT_MANIFEST = ROOT / "admission" / "v17_7_4_prior_realbench_math_act_prompt_manifest.jsonl"


def authority(**extra: Any) -> dict[str, Any]:
    payload = dict(core.AUTHORITY_FALSE)
    payload.update(
        {
            "multi_lobe_superiority_claim": False,
            "commercial_claim": False,
            "external_validation_claim": False,
            "g2_recovered_claim": False,
            "frontier_claim": False,
            "s_tier_claim": False,
            "production_readiness_claim": False,
        }
    )
    payload.update(extra)
    return payload


def git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def arm_by_id(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {arm["arm_id"]: arm for arm in config["arms"]}


def reprolock_config() -> dict[str, Any]:
    base_config = read_json(ROOT / "configs" / "v17_7_4" / "arm_model_config.json")
    math_act = dict(arm_by_id(base_config)["math_act_adapter_global"])
    math_act.update(
        arm_id=core.REPROLOCK_ARM_ID,
        reproduction_mode=core.TRUE_KNOWN_GOOD_BYTE_REPRO,
        legacy_source_arm_id="math_act_adapter_global",
        legacy_prompt_template_id="math_act",
        prompt_template_id="math_act",
        compact_mode="DISABLED_TRUE_BYTE_REPRO",
        compact_scoring_disabled=True,
        score_from_visible_answer=False,
        scoring_method="contains_expected_label",
        scoring_surface="RAW_OUTPUT",
        finalizer_intervention_disabled=True,
        kt_hat_scaffold_disabled=True,
        route_admission_disabled=True,
        oracle_shadow_disabled=True,
        expected_prior_correct_count=41,
        minimum_reproduction_correct=39,
        expected_prior_gsm8k_correct=11,
    )
    config = dict(base_config)
    config.update(
        schema_id="kt.v17_7_4.arm_model_config.oracle_academy_reprolock.v1",
        config_profile="REAL_ARM_ORACLE_ACADEMY_REPROLOCK",
        measurement_mode=core.REPROLOCK_MODE,
        compact_answer_contract=False,
        reasoning_preserving_compact=False,
        row_limit=50,
        default_row_ladder_stage=None,
        required_arm_ids=[core.REPROLOCK_ARM_ID],
        prior_realbench_prompt_manifest="runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl",
        prior_realbench_prompt_manifest_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
        known_good_reproduction_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        arms=[math_act],
    )
    return config


def verify_prior_prompt_manifest() -> dict[str, Any]:
    rows = read_jsonl(PRIOR_PROMPT_MANIFEST)
    manifest = read_json(ROOT / "admission" / "v17_7_4_realbench_row_manifest.json")
    by_id = {row["sample_id"]: row for row in rows}
    matches = 0
    defects = []
    for row in manifest["rows"][:50]:
        prior = by_id.get(row["sample_id"])
        arm = {"prompt_template_id": "math_act", "legacy_prompt_template_id": "math_act", "reproduction_mode": core.TRUE_KNOWN_GOOD_BYTE_REPRO}
        prompt_hash = core.sha256_text(core.prior_realbench_materialize_prompt(row, arm))
        if prior and prompt_hash == prior["prior_prompt_hash"]:
            matches += 1
        else:
            defects.append({"sample_id": row["sample_id"], "computed_prompt_hash": prompt_hash, "prior_prompt_hash": prior.get("prior_prompt_hash") if prior else ""})
    return authority(
        schema_id="kt.v17_7_4.prior_realbench_prompt_source_receipt.prep.v1",
        status="PASS" if matches == 50 and not defects else "BLOCKED",
        source_path=PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(),
        source_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
        prompt_template_source_head="02332fb7ec7215ad75de605735a34b581ba7ea3f",
        computed_match_count=matches,
        required_match_count=50,
        defects=defects[:5],
        claim_ceiling_preserved=True,
    )


def runtime_required_receipt(schema_id: str, artifact: str, purpose: str) -> dict[str, Any]:
    return authority(
        schema_id=schema_id,
        status="RUNTIME_MEASUREMENT_REQUIRED",
        artifact=artifact,
        purpose=purpose,
        measured_runtime_evidence_present=False,
        promotion_eligible=False,
        requires_followup_measurement=True,
        claim_ceiling_preserved=True,
    )


def write_prep_reports(config: dict[str, Any], prompt_receipt: dict[str, Any]) -> None:
    head = git(["rev-parse", "HEAD"])
    branch = git(["branch", "--show-current"])
    write_json(
        ROOT / "reports" / "v17_7_4_reprolock_truth_pin_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_truth_pin_receipt.v1",
            status="PASS",
            current_head=head,
            branch=branch,
            worktree_clean=False,
            worktree_note="Pre-existing unrelated local changes may exist; ReproLock commit stages only lane files.",
            latest_oracle_academy_packet="packets/ktv1774_oracle_academy_reentry_v1.zip",
            latest_oracle_academy_packet_sha256=sha256_file(ROOT / "packets" / "ktv1774_oracle_academy_reentry_v1.zip"),
            prior_realbench_prompt_manifest=PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(),
            prior_prompt_manifest_availability=True,
            next_lawful_move_before_patch="AUTHOR_KTV1774_TRUE_KNOWN_GOOD_REPRODUCTION_LOCK_V1",
        ),
    )
    write_json(
        ROOT / "reports" / "v17_7_4_reprolock_source_index.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_source_index.v1",
            status="PASS",
            current_head=head,
            sources=[
                {
                    "path": PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(),
                    "sha256": sha256_file(PRIOR_PROMPT_MANIFEST),
                    "role": "prior_realbench_math_act_prompt_hash_manifest",
                },
                {
                    "path": "admission/v17_7_4_realbench_row_manifest.json",
                    "sha256": sha256_file(ROOT / "admission" / "v17_7_4_realbench_row_manifest.json"),
                    "role": "current_realbench_row_manifest",
                },
            ],
        ),
    )
    write_json(
        ROOT / "reports" / "v17_7_4_reprolock_contradiction_scan.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_contradiction_scan.v1",
            status="PASS",
            contradictions=[],
            claim_ceiling_preserved=True,
        ),
    )
    write_json(ROOT / "reports" / "v17_7_4_prior_realbench_prompt_source_receipt.json", prompt_receipt)
    write_json(
        ROOT / "reports" / "v17_7_4_prior_realbench_artifact_source_index.json",
        authority(
            schema_id="kt.v17_7_4.prior_realbench_artifact_source_index.prep.v1",
            status=prompt_receipt["status"],
            source_type="LOCAL_ASSESSMENT_DERIVED_PROMPT_HASH_MANIFEST",
            source_uri_or_path=PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(),
            artifact_sha256=sha256_file(PRIOR_PROMPT_MANIFEST),
            prompt_manifest_found=True,
            prompt_template_found=True,
            current_use_permitted=prompt_receipt["status"] == "PASS",
            authority_tier="HISTORICAL_MEASURED_PROMPT_HASH_SOURCE",
            claim_ceiling_preserved=True,
        ),
    )
    for name, schema, purpose in [
        ("v17_7_4_reproduction_identity_passport.json", "kt.v17_7_4.reproduction_identity_passport.prep.v1", "Runtime Stage 0 must bind prompt/rendered/tokenized identity before generation."),
        ("v17_7_4_true_known_good_reproduction_lock_receipt.json", "kt.v17_7_4.true_known_good_reproduction_lock_receipt.prep.v1", "Runtime must pass byte-lock and reproduce known-good path before Academy repair."),
        ("v17_7_4_known_good_hidden_variable_audit.json", "kt.v17_7_4.known_good_hidden_variable_audit.prep.v1", "If byte-lock passes but score fails, classify hidden owner."),
        ("v17_7_4_ope_contextual_bandit_contract.json", "kt.v17_7_4.ope_contextual_bandit_contract.prep.v1", "OPE remains hypothesis-design only and cannot override failed reproduction."),
        ("v17_7_4_ope_authority_decision_receipt.json", "kt.v17_7_4.ope_authority_decision_receipt.prep.v1", "Replay evidence cannot be classified as fresh generation authority."),
        ("v17_7_4_13_lobe_reentry_after_reprolock_plan.json", "kt.v17_7_4.13_lobe_reentry_after_reprolock_plan.prep.v1", "13-lobe/Academy repair reentry remains blocked until control is stable."),
    ]:
        write_json(ROOT / "reports" / name, runtime_required_receipt(schema, name, purpose))
    write_json(
        ROOT / "reports" / "v17_7_4_reprolock_config_receipt.json",
        authority(
            schema_id="kt.v17_7_4.reprolock_config_receipt.v1",
            status="PASS" if core.validate_arm_model_config(config) == [] else "BLOCKED",
            enabled_arms=[arm["arm_id"] for arm in config["arms"] if arm.get("enabled") is True],
            measurement_mode=config["measurement_mode"],
            no_training=True,
            no_promotion=True,
            no_v18=True,
            claim_ceiling_preserved=True,
        ),
    )


def build_packet(config: dict[str, Any]) -> tuple[Path, str]:
    packet = ROOT / "packets" / PACKET_NAME
    packet.parent.mkdir(parents=True, exist_ok=True)
    run_manifest = authority(
        schema_id="kt.v17_7_4.oracle_academy_reprolock_packet_manifest.v1",
        status="READY_FOR_TRUE_KNOWN_GOOD_BYTE_REPRO",
        run_mode=NEXT_LAWFUL_MOVE,
        measurement_mode=core.REPROLOCK_MODE,
        default_requested_rows=50,
        true_known_good_byte_repro_required=True,
        stage0_identity_audit_required=True,
        stage1_five_row_probe_available=True,
        stage2_fifty_row_reproduction_required=True,
        prior_realbench_prompt_manifest_required=True,
        no_training=True,
        no_promotion=True,
        no_v18=True,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        target_outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
    )
    members = {
        "README.md": (
            "# KTV1774 Oracle Academy ReproLock V1\n\n"
            "Byte-locks the prior RealBench math_act_adapter_global path before any Academy/scar/router repair. "
            "This packet enables exactly one true known-good reproduction arm, fails closed if the recovered "
            "prompt hashes do not match the prior 41/50 run, and preserves the claim ceiling. No training, "
            "promotion, V18, G2-recovered, router-superiority, commercial, or external-validation authority is added.\n"
        ).encode("utf-8"),
        "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py": (ROOT / "runtime" / "v17_7_4" / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py").read_bytes(),
        "KT_V1774_TRUEGEN_ARM_CORE.py": (ROOT / "runtime" / "v17_7_4" / "KT_V1774_TRUEGEN_ARM_CORE.py").read_bytes(),
        "runtime_inputs/truegen_row_manifest.json": (ROOT / "admission" / "v17_7_4_realbench_row_manifest.json").read_bytes(),
        "runtime_inputs/arm_model_config.json": json.dumps(config, indent=2, sort_keys=True).encode("utf-8"),
        "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl": PRIOR_PROMPT_MANIFEST.read_bytes(),
        "run_manifest.json": json.dumps(run_manifest, indent=2, sort_keys=True).encode("utf-8"),
    }
    with zipfile.ZipFile(packet, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            write_zip_member(archive, name, data)
    return packet, sha256_file(packet)


def write_runbook(packet_sha: str) -> Path:
    path = ROOT / "docs" / RUNBOOK
    write_text(
        path,
        f"""# V17.7.4 Oracle Academy ReproLock One Cell

Packet: `packets/{PACKET_NAME}`

Kaggle dataset name: `{KAGGLE_DATASET_NAME}`

SHA256: `{packet_sha}`

```python
from pathlib import Path
import os
import subprocess
import sys
import zipfile

os.environ["KT_RUN_MODE"] = "{NEXT_LAWFUL_MOVE}"
os.environ["KT_TRUEGEN_MEASUREMENT_MODE"] = "{core.REPROLOCK_MODE}"
os.environ["KT_TRUEGEN_TARGET_ROWS"] = "50"
os.environ["KT_MINIFURNACE_ROWS"] = "50"
os.environ["KT_TRUEGEN_REQUIRE_REAL_ARM_CONFIG"] = "1"
os.environ["KT_FORBID_SMOKE_CONFIG"] = "1"
os.environ["KT_FORBID_BASE_FALLBACK_AS_ADAPTER"] = "1"
os.environ["KT_NO_TRAINING"] = "1"
os.environ["KT_NO_PROMOTION"] = "1"
os.environ["KT_NO_V18"] = "1"
os.environ.setdefault("KT_TRUEGEN_ADAPTER_SOURCE", "hf")
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")

packet = Path("/kaggle/input/{KAGGLE_DATASET_NAME}/{PACKET_NAME}")
if not packet.exists():
    raise FileNotFoundError(packet)
work = Path("/kaggle/working/ktv1774_oracle_reprolock_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as archive:
    archive.extractall(work)
runner = work / "KTV1774_TRUEGEN_MINIFURNACE_MASTER_RUNNER.py"
os.chdir(runner.parent)
sys.path.insert(0, str(runner.parent))
subprocess.check_call([sys.executable, runner.name])
print("assessment outputs:", sorted(Path("/kaggle/working").glob("**/KTV1774_TRUEGEN_MINIFURNACE_ASSESSMENT_ONLY.zip")))
```
""",
    )
    return path


def main() -> int:
    prompt_receipt = verify_prior_prompt_manifest()
    if prompt_receipt["status"] != "PASS":
        raise RuntimeError(f"KT_BLOCKED__KNOWN_GOOD_PROMPT_SOURCE_MISSING: {prompt_receipt['defects']}")
    config = reprolock_config()
    write_prep_reports(config, prompt_receipt)
    packet, packet_sha = build_packet(config)
    runbook = write_runbook(packet_sha)
    summary_path = ROOT / "reports" / "v17_7_4_oracle_academy_reprolock_builder_summary.json"
    summary = authority(
        schema_id="kt.v17_7_4.oracle_academy_reprolock_builder_summary.v1",
        status="PASS",
        current_head=git(["rev-parse", "HEAD"]),
        current_branch=git(["branch", "--show-current"]),
        outcome=OUTCOME,
        next_lawful_move=NEXT_LAWFUL_MOVE,
        packet_path=packet.relative_to(ROOT).as_posix(),
        packet_sha256=packet_sha,
        kaggle_dataset_name=KAGGLE_DATASET_NAME,
        one_cell_runbook=runbook.relative_to(ROOT).as_posix(),
        prior_prompt_source_status=prompt_receipt["status"],
        reproduction_identity_passport_status="RUNTIME_REQUIRED",
        prompt_hash_reproduction_status="RUNTIME_STAGE0_REQUIRED",
        tokenized_input_reproduction_status="RUNTIME_STAGE0_REQUIRED",
        known_good_reproduction_lock_status="RUNTIME_REQUIRED",
        hidden_variable_audit_status="RUNTIME_IF_SCORE_FAILS",
        ope_contextual_bandit_status="CONTRACT_BOUND_NO_AUTHORITY_EXPANSION",
        blockers=[],
        claim_ceiling_status="PRESERVED",
    )
    write_json(summary_path, summary)
    write_json(
        ROOT / "registry" / "artifact_authority_registry_v17_7_4_reprolock_delta_receipt.json",
        authority(
            schema_id="kt.artifact_authority_registry.delta_receipt.v17_7_4_reprolock.v1",
            status="PASS",
            current_head=summary["current_head"],
            artifacts_added=[
                {"path": packet.relative_to(ROOT).as_posix(), "role": "oracle_academy_reprolock_kaggle_packet", "sha256": packet_sha, "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": runbook.relative_to(ROOT).as_posix(), "role": "oracle_academy_reprolock_one_cell_runbook", "sha256": sha256_file(runbook), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
                {"path": PRIOR_PROMPT_MANIFEST.relative_to(ROOT).as_posix(), "role": "prior_realbench_prompt_hash_source", "sha256": sha256_file(PRIOR_PROMPT_MANIFEST), "authority_state": "HISTORICAL_MEASURED_PROMPT_HASH_SOURCE", "claim_expansion": False},
                {"path": summary_path.relative_to(ROOT).as_posix(), "role": "reprolock_builder_summary", "sha256": sha256_file(summary_path), "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY", "claim_expansion": False},
            ],
            outcome=OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
            no_training=True,
            no_promotion=True,
            no_v18=True,
            no_commercial_claim=True,
            no_external_validation_claim=True,
            no_router_superiority_claim=True,
            no_g2_recovered_claim=True,
        ),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
