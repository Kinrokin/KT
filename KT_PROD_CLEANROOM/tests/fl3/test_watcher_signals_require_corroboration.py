from __future__ import annotations

from pathlib import Path

import pytest

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

_REPO_ROOT = bootstrap_syspath()


def _scan_forbidden_references(*, root: Path, needles: list[str]) -> list[str]:
    hits: list[str] = []
    for p in root.rglob("*.py"):
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if any(n in text for n in needles):
            hits.append(p.relative_to(_REPO_ROOT).as_posix())
    return hits


@pytest.mark.parametrize(
    "path",
    [
        "KT_PROD_CLEANROOM/tools/verification",
        "KT_PROD_CLEANROOM/tools/training",
    ],
)
def test_watcher_signals_do_not_gate_without_corroboration(path: str) -> None:
    """
    Protocol rule (NN-6): Watcher/SPC signals must never alter a verdict unless corroborated.

    Phase 1B implements Watcher/SPC as NCON/diagnostic-only. The safest enforcement is structural:
    canonical gating code must not consult Watcher/SPC reports at all.
    """
    root = _REPO_ROOT / path
    needles = [
        "drift_map.json",
        "spc_report.json",
        "watcher_drift_map",
        "watcher_spc_report",
    ]
    hits = _scan_forbidden_references(root=root, needles=needles)
    # Allow a single centralized validator module to reference these filenames.
    allow = {"KT_PROD_CLEANROOM/tools/verification/watcher_spc_validators.py"}
    filtered = [h for h in hits if h not in allow]
    assert not filtered, f"Watcher/SPC references detected outside validator module: {filtered}"
