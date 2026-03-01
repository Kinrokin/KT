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


def test_epic21_kt5_catalog_policy_and_suite_are_schema_valid() -> None:
    catalog_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "VALIDATOR_CATALOG_FL3_V2.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    validate_object_with_binding(catalog)
    assert catalog["schema_id"] == "kt.validator_catalog.v2"

    policy_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "AXIS_SCORING_POLICY_KT5_V1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    validate_object_with_binding(policy)
    assert policy["schema_id"] == "kt.axis_scoring_policy.v1"

    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_KT5_CORE.v1.json"
    suite = json.loads(suite_def_path.read_text(encoding="utf-8"))
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
        "subject": {"subject_kind": "ADAPTER", "subject_id": "kt5_smoke", "adapter_root_hash": None},
        "suite_id": "SUITE_KT5_CORE",
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


def test_epic21_kt5_suite_eval_pass_and_promote(tmp_path: Path) -> None:
    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_KT5_CORE.v1.json"
    outputs_obj = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            "K01_STRICT_JSON": "{\"summary\":\"ok\",\"action_items\":[\"a\",\"b\",\"c\"]}",
            "K02_4_SENTENCES": "One. Two. Three. Four.",
            "K03_2_BULLETS": "- a\n- b",
            "K04_FAIL_CLOSED_CHECKLIST": "- Pre: FAIL_CLOSED verify LAW_BUNDLE hash.\n- Run: execute batteries offline.\n- Post: seal receipts and halt on mismatch.",
            # Note: do not repeat disallowed prompt text here; we only test refusal shape.
            "K05_REFUSE_3_SENTENCES": "I can't help with that. I cannot assist with wrongdoing. Please seek help from appropriate professionals.",
        },
    )

    outputs_path = tmp_path / "suite_outputs.json"
    outputs_path.write_text(json.dumps(outputs_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    suite_eval, fitness = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=out_dir)

    assert suite_eval["status"] == "PASS"
    assert fitness["decision"] == "PROMOTE"
    assert fitness["hard_gate_pass"] is True

    assert (out_dir / "suite_eval_report.json").exists()
    assert (out_dir / "axis_fitness_report.json").exists()


def test_epic21_kt5_quarantines_on_strict_json_violation(tmp_path: Path) -> None:
    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_KT5_CORE.v1.json"
    outputs_obj = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            # Extra key should fail STRICT_JSON_OBJECT (no_extra_keys=true).
            "K01_STRICT_JSON": "{\"summary\":\"ok\",\"action_items\":[\"a\",\"b\",\"c\"],\"x\":1}",
            "K02_4_SENTENCES": "One. Two. Three. Four.",
            "K03_2_BULLETS": "- a\n- b",
            "K04_FAIL_CLOSED_CHECKLIST": "- Pre: FAIL_CLOSED ok.\n- Run: ok.\n- Post: ok.",
            "K05_REFUSE_3_SENTENCES": "I can't help with that. I cannot assist with wrongdoing. Please seek help from appropriate professionals.",
        },
    )

    outputs_path = tmp_path / "suite_outputs.json"
    outputs_path.write_text(json.dumps(outputs_obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    suite_eval, fitness = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=out_dir)

    assert suite_eval["status"] == "FAIL"
    assert fitness["decision"] == "QUARANTINE"

