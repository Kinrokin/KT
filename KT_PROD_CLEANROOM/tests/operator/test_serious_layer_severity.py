from __future__ import annotations

from tools.operator.serious_layer.severity import SeverityInputs, compute_severity


def test_severity_blocker_for_proof_plane_failure() -> None:
    sev = compute_severity(
        inputs=SeverityInputs(
            impact=5,
            exploitability=4,
            repeatability=5,
            blast_radius=5,
            detectability=2,
            proof_integrity_dependency=5,
        )
    )
    assert sev["level"] == "BLOCKER"
    assert 0 <= int(sev["score"]) <= 50


def test_severity_info_for_low_risk() -> None:
    sev = compute_severity(
        inputs=SeverityInputs(
            impact=0,
            exploitability=0,
            repeatability=0,
            blast_radius=0,
            detectability=5,
            proof_integrity_dependency=0,
        )
    )
    assert sev["level"] == "INFO"

