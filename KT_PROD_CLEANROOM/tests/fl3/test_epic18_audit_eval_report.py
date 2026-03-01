from __future__ import annotations

import json
import os
import hashlib
from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()

from schemas.fl3_schema_common import sha256_hex_of_obj  # noqa: E402
from schemas.schema_files import schema_version_hash  # noqa: E402
from schemas.schema_registry import validate_object_with_binding  # noqa: E402
from tools.eval.run_suite_eval import run_suite_eval  # noqa: E402
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402
from tools.verification.generate_audit_eval_report import generate_audit_eval_report  # noqa: E402


def _mk_suite_outputs(*, suite_def_path: Path, outputs_by_case_id: dict[str, str]) -> dict:
    suite_root_hash = sha256_file_canonical(suite_def_path)
    outs = []
    for case_id in sorted(outputs_by_case_id.keys()):
        txt = outputs_by_case_id[case_id]
        outs.append({"case_id": case_id, "output_text": txt, "output_sha256": hashlib.sha256(txt.encode("utf-8")).hexdigest()})

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


def test_epic18_generate_audit_eval_report_promote(tmp_path: Path) -> None:
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

    eval_out = tmp_path / "eval_out"
    _suite_eval, _fitness = run_suite_eval(
        suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=eval_out
    )

    audit_out = tmp_path / "audit_out"
    report = generate_audit_eval_report(
        suite_def_paths=[suite_def_path],
        suite_eval_report_paths=[eval_out / "suite_eval_report.json"],
        axis_fitness_report_paths=[eval_out / "axis_fitness_report.json"],
        run_id="TEST_RUN",
        out_dir=audit_out,
        attestation_mode="SIMULATED",
    )

    validate_object_with_binding(report)
    assert report["schema_id"] == "kt.audit_eval_report.v1"
    assert report["decision"] == "PROMOTE"
    assert "KT_AUDIT_EVAL_VERDICT_V1" in report["one_line_verdict"]
    assert (audit_out / "audit_eval_report.json").exists()
    assert (audit_out / "audit_eval_verdict.txt").exists()

    # WORM no-op: second identical run must not fail.
    report2 = generate_audit_eval_report(
        suite_def_paths=[suite_def_path],
        suite_eval_report_paths=[eval_out / "suite_eval_report.json"],
        axis_fitness_report_paths=[eval_out / "axis_fitness_report.json"],
        run_id="TEST_RUN",
        out_dir=audit_out,
        attestation_mode="SIMULATED",
    )
    assert report2["audit_eval_report_id"] == report["audit_eval_report_id"]


def test_epic18_duplicate_axis_id_is_illegal(tmp_path: Path) -> None:
    suite_def_path = _REPO_ROOT / "KT_PROD_CLEANROOM" / "AUDITS" / "SUITES" / "SUITE_FORMAT_CONTROL.v1.json"

    # Run A: PROMOTE
    outputs_a = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            "F01_JSON_EXACT": "{\"a\":1,\"b\":2,\"c\":3}",
            "F02_4_SENTENCES": "One. Two. Three. Four.",
            "F03_2_BULLETS": "- a\n- b",
        },
    )
    outputs_a_path = tmp_path / "suite_outputs_a.json"
    outputs_a_path.write_text(json.dumps(outputs_a, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    out_a = tmp_path / "out_a"
    _ = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_a_path, out_dir=out_a)

    # Run B: HOLD (wrong bullet style)
    outputs_b = _mk_suite_outputs(
        suite_def_path=suite_def_path,
        outputs_by_case_id={
            "F01_JSON_EXACT": "{\"a\":1,\"b\":2,\"c\":3}",
            "F02_4_SENTENCES": "One. Two. Three. Four.",
            "F03_2_BULLETS": "1. a\n2. b",
        },
    )
    outputs_b_path = tmp_path / "suite_outputs_b.json"
    outputs_b_path.write_text(json.dumps(outputs_b, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    out_b = tmp_path / "out_b"
    _ = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_b_path, out_dir=out_b)

    with pytest.raises(FL3ValidationError):
        _ = generate_audit_eval_report(
            suite_def_paths=[suite_def_path],
            suite_eval_report_paths=[out_a / "suite_eval_report.json", out_b / "suite_eval_report.json"],
            axis_fitness_report_paths=[out_a / "axis_fitness_report.json", out_b / "axis_fitness_report.json"],
            run_id="TEST_RUN",
            out_dir=tmp_path / "audit_out",
            attestation_mode="SIMULATED",
        )


def test_epic18_canonical_lane_requires_hmac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    eval_out = tmp_path / "eval_out"
    _ = run_suite_eval(suite_def_path=suite_def_path, suite_outputs_path=outputs_path, out_dir=eval_out)

    monkeypatch.setenv("KT_CANONICAL_LANE", "1")
    with pytest.raises(FL3ValidationError):
        _ = generate_audit_eval_report(
            suite_def_paths=[suite_def_path],
            suite_eval_report_paths=[eval_out / "suite_eval_report.json"],
            axis_fitness_report_paths=[eval_out / "axis_fitness_report.json"],
            run_id="TEST_RUN",
            out_dir=tmp_path / "audit_out",
            attestation_mode="SIMULATED",
        )
    monkeypatch.delenv("KT_CANONICAL_LANE", raising=False)
