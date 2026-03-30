from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.operator import router_readiness_reconsideration_input_validate as validate
from tools.router.run_router_readiness_reconsideration_input import (
    SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
    SANCTIONED_EMITTER_ENTRYPOINT,
    build_router_readiness_reconsideration_input,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _gate_packet(*, material_change: bool = True, semantic_bypass: bool = False, candidate_ref: str = "candidate.json") -> dict:
    return {
        "schema_id": "kt.lab_readiness_reconsideration_gate_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "questions": {
            "material_change_earned": material_change,
            "semantic_bypass_risk": semantic_bypass,
            "same_head_as_ceiling": False,
            "introduced_new_terminal_adapter": True,
            "expanded_terminal_adapter_count": True,
            "introduced_new_route_pair": True,
            "expanded_route_pair_count": True,
        },
        "source_packet_refs": {
            "candidate_refresh_packet_ref": candidate_ref,
        },
    }


def _candidate_refresh() -> dict:
    return {
        "schema_id": "kt.later_lab_readiness_refresh_packet.v1",
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": "PASS",
        "source_lab_heads": {
            "code_terminal_lab_head": "HEAD_C",
            "math_terminal_lab_head": "HEAD_C",
        },
        "terminal_summary": {
            "combined_terminal_adapters": [
                "lobe.code.specialist.v1",
                "lobe.math.specialist.v1",
                "lobe.writer.specialist.v1",
            ],
            "combined_terminal_adapter_count": 3,
        },
    }


def test_reconsideration_input_validation_receipt_passes_for_clean_packet() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    receipt = validate.build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        packet_ref="reconsideration.json",
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert receipt["status"] == "PASS"
    assert receipt["sanctioned_path_contract"]["sanctioned_emitter_entrypoint"] == SANCTIONED_EMITTER_ENTRYPOINT
    assert receipt["sanctioned_path_contract"]["sanctioned_consumer_validator_entrypoint"] == SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT
    assert receipt["detected_schema_emitters"] == [SANCTIONED_EMITTER_ENTRYPOINT]
    assert receipt["detected_schema_touchers"] == [
        SANCTIONED_CONSUMER_VALIDATOR_ENTRYPOINT,
        SANCTIONED_EMITTER_ENTRYPOINT,
    ]


def test_reconsideration_input_validation_receipt_fails_on_contract_tamper() -> None:
    root = _repo_root()
    packet = build_router_readiness_reconsideration_input(
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
    )
    packet["single_sanctioned_path_contract"]["sanctioned_consumer_validator_entrypoint"] = (
        "KT_PROD_CLEANROOM/tools/operator/alternate_validator.py"
    )

    receipt = validate.build_router_readiness_reconsideration_input_validation_receipt(
        root=root,
        packet=packet,
        gate_packet=_gate_packet(material_change=True, semantic_bypass=False),
        candidate_refresh_packet=_candidate_refresh(),
        packet_ref="reconsideration.json",
        gate_packet_ref="gate.json",
        candidate_refresh_packet_ref="candidate.json",
    )

    assert receipt["status"] == "FAIL"
    failed = {item["check_id"] for item in receipt["checks"] if not item["pass"]}
    assert "single_sanctioned_path_contract_matches_expected_pair" in failed


def test_reconsideration_input_validator_cli_emits_pass_receipt(tmp_path: Path) -> None:
    gate_path = tmp_path / "gate.json"
    candidate_path = tmp_path / "candidate.json"
    packet_path = tmp_path / "reconsideration.json"
    receipt_path = tmp_path / "validation.json"

    gate_packet = _gate_packet(material_change=True, semantic_bypass=False, candidate_ref=str(candidate_path))
    candidate_refresh = _candidate_refresh()
    packet = build_router_readiness_reconsideration_input(
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_refresh,
        gate_packet_ref=str(gate_path),
        candidate_refresh_packet_ref=str(candidate_path),
    )

    gate_path.write_text(json.dumps(gate_packet, indent=2), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate_refresh, indent=2), encoding="utf-8")
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.router_readiness_reconsideration_input_validate",
            "--input",
            str(packet_path),
            "--output",
            str(receipt_path),
        ],
        cwd=str(_repo_root() / "KT_PROD_CLEANROOM"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert payload["status"] == "PASS"
    assert payload["detected_schema_emitters"] == [SANCTIONED_EMITTER_ENTRYPOINT]


def test_load_validated_reconsideration_input_fails_closed_through_validator_contract(tmp_path: Path) -> None:
    gate_path = tmp_path / "gate.json"
    candidate_path = tmp_path / "candidate.json"
    packet_path = tmp_path / "reconsideration.json"

    gate_packet = _gate_packet(material_change=True, semantic_bypass=False, candidate_ref=str(candidate_path))
    candidate_refresh = _candidate_refresh()
    packet = build_router_readiness_reconsideration_input(
        gate_packet=gate_packet,
        candidate_refresh_packet=candidate_refresh,
        gate_packet_ref=str(gate_path),
        candidate_refresh_packet_ref=str(candidate_path),
    )

    gate_path.write_text(json.dumps(gate_packet, indent=2), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate_refresh, indent=2), encoding="utf-8")
    packet_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")

    loaded = validate.load_validated_router_readiness_reconsideration_input(
        root=_repo_root(),
        packet_ref=str(packet_path),
    )

    assert loaded["schema_id"] == "kt.router_readiness_reconsideration_input.v1"
