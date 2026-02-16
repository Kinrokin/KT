from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.eval.run_suite_eval import run_suite_eval  # noqa: E402
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical  # noqa: E402


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_epic17_catalog_policy_and_suites_are_schema_valid() -> None:
    # Validator catalog
    catalog_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "VALIDATOR_CATALOG_FL3.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    validate_object_with_binding(catalog)
    assert catalog["schema_id"] == "kt.validator_catalog.v1"

    # Scoring policies
    for name in ("AXIS_SCORING_POLICY_FORMAT_V1.json", "AXIS_SCORING_POLICY_SAFETY_V1.json"):
        p = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / name
        obj = json.loads(p.read_text(encoding="utf-8"))
        validate_object_with_binding(obj)
        assert obj["schema_id"] == "kt.axis_scoring_policy.v1"

    # Suite definitions
    suite_dir = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES"
    for fname in (
        "SUITE_FORMAT_CONTROL.v1.json",
        "SUITE_GOV_TOP150_REFUSAL.v1.json",
        "SUITE_GOV_TOP150_REFUSAL_ADV.v1.json",
    ):
        sp = suite_dir / fname
        suite = json.loads(sp.read_text(encoding="utf-8"))
        validate_object_with_binding(suite)
        assert suite["schema_id"] == "kt.suite_definition.v1"


def _mk_suite_outputs(*, suite_def_path: Path, outputs_by_case_id: dict[str, str]) -> dict:
    suite_root_hash = sha256_file_canonical(suite_def_path)
    outs = []
    for case_id in sorted(outputs_by_case_id.keys()):
        txt = outputs_by_case_id[case_id]
        outs.append({"case_id": case_id, "output_text": txt, "output_sha256": _sha256_text(txt)})

    obj = {
        "schema_id": "kt.suite_outputs.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.suite_outputs.v1.json"),
        "suite_outputs_id": "",
        "base_model_id": "mistral-7b",
        "subject": {"subject_kind": "ADAPTER", "subject_id": "lobe.architect.v1", "adapter_root_hash": None},
        "suite_id": "SUITE_FORMAT_CONTROL",
        "suite_root_hash": suite_root_hash,
        "decode_policy_id": "greedy_v1",
        "decode_cfg_hash": "0" * 64,
        "outputs": outs,
        "created_at": "1970-01-01T00:00:00Z",
        "notes": None,
    }
    obj["suite_outputs_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "suite_outputs_id"})
    validate_object_with_binding(obj)
    return obj


def test_epic17_suite_eval_pass_and_promote(tmp_path: Path) -> None:
    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"
    outputs_obj = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            "F01_JSON_EXACT": "{\"a\":1,\"b\":2,\"c\":3}",
            "F02_4_SENTENCES": "One. Two. Three. Four.",
            "F03_2_BULLETS": "- a\n- b",
        },
    )

    outputs_path = tmp_path / "suite_outputs.json"
    outputs_path.write_text(json.dumps(outputs_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    suite_eval, fitness = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=out_dir)

    assert suite_eval["status"] == "PASS"
    assert fitness["decision"] == "PROMOTE"

    # WORM outputs exist.
    assert (out_dir / "suite_eval_report.json").exists()
    assert (out_dir / "axis_fitness_report.json").exists()


def test_epic17_suite_eval_fail_but_hold(tmp_path: Path) -> None:
    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"
    outputs_obj = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            "F01_JSON_EXACT": "{\"a\":1,\"b\":2,\"c\":3}",
            "F02_4_SENTENCES": "One. Two. Three. Four.",
            # Wrong style: numbered list instead of hyphen bullets.
            "F03_2_BULLETS": "1. a\n2. b",
        },
    )

    outputs_path = tmp_path / "suite_outputs.json"
    outputs_path.write_text(json.dumps(outputs_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    suite_eval, fitness = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=out_dir)

    assert suite_eval["status"] == "FAIL"
    assert fitness["decision"] == "HOLD"

