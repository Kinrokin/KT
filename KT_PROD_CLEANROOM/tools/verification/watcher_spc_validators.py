from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


class WatcherSPCValidationError(RuntimeError):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise WatcherSPCValidationError(f"Unreadable JSON (fail-closed): {path.as_posix()}") from exc


def _iter_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_strings(k)
            yield from _iter_strings(v)
        return
    if isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
        return


def assert_runtime_registry_has_no_watcher_spc(*, registry_path: Path) -> None:
    """
    Watcher/SPC are NCON and must not be invokable via canonical runtime routing.

    Minimal enforcement surface:
    - runtime_import_roots must not add a 'watcher' import root
    - registry contents must not reference watcher/SPC module names or entrypoints
    """
    reg = _read_json(registry_path)
    if not isinstance(reg, dict):
        raise WatcherSPCValidationError("runtime registry must be object (fail-closed)")

    roots = reg.get("runtime_import_roots")
    if isinstance(roots, list) and any(str(x).strip() == "watcher" for x in roots):
        raise WatcherSPCValidationError("runtime_import_roots must not include 'watcher' in canonical registry (fail-closed)")

    for s in _iter_strings(reg):
        low = s.lower()
        if "tools.watcher" in low or low.startswith("watcher.") or low == "watcher":
            raise WatcherSPCValidationError("runtime registry references watcher modules (fail-closed)")
        if "spc" in low and ("social" in low or "pressure" in low or "crucible" in low or "spc_" in low or low.startswith("spc")):
            raise WatcherSPCValidationError("runtime registry references SPC modules (fail-closed)")


def _find_optional_json(evidence_dir: Path, names: Iterable[str]) -> List[Path]:
    found: List[Path] = []
    for name in names:
        p = evidence_dir / name
        if p.exists():
            found.append(p)
    return found


def validate_watcher_spc_artifacts_if_present(*, evidence_dir: Path) -> None:
    """
    Conditional enforcement:
    - If Watcher/SPC artifacts are absent: no effect.
    - If present but malformed: FAIL_CLOSED.

    The protocol requires evidence provenance and monotonic drift scoring when such artifacts exist.
    """
    evidence_dir = evidence_dir.resolve()
    watcher_files = _find_optional_json(evidence_dir, names=("drift_map.json", "watcher_drift_map.json", "spc_report.json", "watcher_spc_report.json"))
    if not watcher_files:
        return

    for p in watcher_files:
        obj = _read_json(p)
        if not isinstance(obj, dict):
            raise WatcherSPCValidationError(f"Watcher/SPC artifact must be object (fail-closed): {p.name}")

        # Silence allowed: absence of alerts is not evidence of PASS.
        # We only validate structure if scores are present.
        if "scores" not in obj:
            continue

        scores = obj.get("scores")
        if not isinstance(scores, list):
            raise WatcherSPCValidationError("scores must be list (fail-closed)")

        for idx, entry in enumerate(scores):
            if not isinstance(entry, dict):
                raise WatcherSPCValidationError(f"scores[{idx}] must be object (fail-closed)")
            if "evidence" not in entry or "score" not in entry:
                raise WatcherSPCValidationError("score entries must include evidence[] and score (fail-closed)")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list):
                raise WatcherSPCValidationError("score entry evidence must be list (fail-closed)")

            weights: List[float] = []
            for eidx, ev in enumerate(evidence):
                if not isinstance(ev, dict):
                    raise WatcherSPCValidationError(f"evidence[{eidx}] must be object (fail-closed)")
                ptr = ev.get("pointer")
                if not isinstance(ptr, dict):
                    raise WatcherSPCValidationError("evidence.pointer must be object (fail-closed)")
                # Provenance requirement: transcript offsets + per-line hashes + graph edge identifiers/hashes.
                required_ptr = {"transcript_relpath", "start_line", "end_line", "line_hashes", "edge_ids"}
                if not required_ptr.issubset(set(ptr.keys())):
                    raise WatcherSPCValidationError("evidence.pointer missing required provenance fields (fail-closed)")
                if not isinstance(ptr.get("transcript_relpath"), str) or not ptr["transcript_relpath"].strip():
                    raise WatcherSPCValidationError("pointer.transcript_relpath invalid (fail-closed)")
                if not isinstance(ptr.get("start_line"), int) or not isinstance(ptr.get("end_line"), int):
                    raise WatcherSPCValidationError("pointer.start_line/end_line must be ints (fail-closed)")
                if not isinstance(ptr.get("line_hashes"), list) or len(ptr["line_hashes"]) < 1:
                    raise WatcherSPCValidationError("pointer.line_hashes must be non-empty list (fail-closed)")
                if not isinstance(ptr.get("edge_ids"), list):
                    raise WatcherSPCValidationError("pointer.edge_ids must be list (fail-closed)")

                try:
                    w = float(ev.get("weight"))
                except Exception as exc:  # noqa: BLE001
                    raise WatcherSPCValidationError("evidence.weight must be numeric (fail-closed)") from exc
                if w < 0.0:
                    raise WatcherSPCValidationError("evidence.weight must be >= 0 (fail-closed)")
                weights.append(w)

            # Bolt-tightener: monotonic drift scoring (score must be sum of non-negative weights).
            computed = sum(weights)
            try:
                reported = float(entry.get("score"))
            except Exception as exc:  # noqa: BLE001
                raise WatcherSPCValidationError("score must be numeric (fail-closed)") from exc
            if abs(reported - computed) > 1e-9:
                raise WatcherSPCValidationError("score inconsistent with sum(weights) monotone rule (fail-closed)")

        # SPC probe influence radius: if probe candidates exist, they must be quarantined/non-gating.
        probes = obj.get("spc_probe_candidates")
        if probes is None:
            continue
        if not isinstance(probes, list):
            raise WatcherSPCValidationError("spc_probe_candidates must be list (fail-closed)")
        for pidx, cand in enumerate(probes):
            if not isinstance(cand, dict):
                raise WatcherSPCValidationError(f"spc_probe_candidates[{pidx}] must be object (fail-closed)")
            if cand.get("quarantined") is not True:
                raise WatcherSPCValidationError("SPC probe candidates must be quarantined (fail-closed)")
            if cand.get("gating") is True:
                raise WatcherSPCValidationError("SPC probe candidates must not be gating (fail-closed)")


def iter_python_files(paths: Iterable[Path]) -> Iterator[Path]:
    for root in paths:
        if not root.exists():
            continue
        for p in root.rglob("*.py"):
            if p.is_file():
                yield p


def assert_no_watcher_imports_in_paths(*, paths: Iterable[Path]) -> None:
    """
    Hard firewall: canonical modules must not import Watcher/SPC modules.
    This is a simple string-level scan to prevent accidental coupling.
    """
    offenders: List[Tuple[str, str]] = []
    for p in iter_python_files(paths):
        # This module necessarily contains the sentinel strings used for scanning; it is not
        # an import-site and must not self-trigger.
        if p.name == "watcher_spc_validators.py":
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if (
            "tools.watcher" in text
            or "from watcher " in text
            or "from watcher." in text
            or "import watcher " in text
            or "import watcher." in text
            or "import watcher\n" in text
            or "import watcher\r\n" in text
            or "from spc " in text
            or "from spc." in text
            or "import spc " in text
            or "import spc." in text
            or "import spc\n" in text
            or "import spc\r\n" in text
        ):
            offenders.append((p.as_posix(), "watcher/spc import reference"))
    if offenders:
        lines = "\n".join([f"{fp}: {why}" for fp, why in offenders[:50]])
        raise WatcherSPCValidationError(f"Watcher/SPC imports detected in canonical code paths (fail-closed):\n{lines}")
