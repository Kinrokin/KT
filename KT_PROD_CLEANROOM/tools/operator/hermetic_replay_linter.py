from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import make_run_dir, operator_fingerprint, write_failure_artifacts, write_json_worm


def lint_hermetic_replay(*, delivery_dir: Path, mve_json: Path, run_dir: Path) -> Dict[str, Any]:
    mve = json.loads(mve_json.read_text(encoding="utf-8"))
    if not isinstance(mve, dict):
        raise RuntimeError("FAIL_CLOSED: mve json must be object")
    for field in ("container_image_digest", "python_version", "os_release", "runtime_fingerprint"):
        if not str(mve.get(field, "")).strip():
            raise RuntimeError(f"FAIL_CLOSED: missing mve field {field}")
    proc = subprocess.run(
        [sys.executable, "-m", "tools.delivery.delivery_contract_validator", "--delivery-dir", str(delivery_dir)],
        text=True,
        capture_output=True,
    )
    log_text = (proc.stdout or "") + (proc.stderr or "")
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    (run_dir / "transcripts" / "replay_linter.log").write_text(log_text, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError("FAIL_CLOSED: delivery contract validator failed inside hermetic replay lint")
    current_fp = operator_fingerprint()["runtime_fingerprint"]
    if str(mve.get("runtime_fingerprint", "")).strip() != current_fp:
        raise RuntimeError("FAIL_CLOSED: hermetic replay runtime fingerprint mismatch")
    return {
        "mve_environment_fingerprint": current_fp,
        "schema_id": "kt.operator.hermetic_replay_receipt.v1",
        "status": "PASS",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Hermetic replay linter.")
    ap.add_argument("--delivery-dir", required=True)
    ap.add_argument("--mve", required=True)
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="hermetic-replay-linter", requested_run_root=str(args.run_root))
    try:
        report = lint_hermetic_replay(delivery_dir=Path(args.delivery_dir), mve_json=Path(args.mve), run_dir=run_dir)
        write_json_worm(run_dir / "reports" / "replay_receipt.json", report, label="replay_receipt.json")
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.replay.lint.hermetic",
            failure_name="REPLAY_NONDETERMINISTIC",
            message=str(exc),
            next_actions=["Re-run inside the pinned MVE container with a matching runtime fingerprint."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
