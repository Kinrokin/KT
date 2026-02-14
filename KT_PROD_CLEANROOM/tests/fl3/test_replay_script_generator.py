from __future__ import annotations

from pathlib import Path

from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath

bootstrap_syspath()

from tools.verification.fl3_canonical import sha256_json, sha256_text  # noqa: E402
from tools.verification.fl3_validators import FL3ValidationError  # noqa: E402
from tools.verification.replay_script_generator import render_replay_ps1, render_replay_sh, write_replay_scripts  # noqa: E402


def test_replay_script_hash_bundle_is_stable(tmp_path: Path) -> None:
    cmd = "python -m tools.verification.fl4_replay_from_receipts --evidence-dir out --out out/replay.json"
    sh = render_replay_sh(replay_command=cmd)
    ps1 = render_replay_ps1(replay_command=cmd)
    sh_hash = sha256_text(sh)
    ps1_hash = sha256_text(ps1)
    bundle = sha256_json({"replay_ps1_sha256": ps1_hash, "replay_sh_sha256": sh_hash})

    _, _, hashes = write_replay_scripts(out_dir=tmp_path, replay_command=cmd)
    assert hashes["replay_sh_sha256"] == sh_hash
    assert hashes["replay_ps1_sha256"] == ps1_hash
    assert hashes["replay_script_hash"] == bundle

    # Identical rerun must no-op.
    _, _, hashes2 = write_replay_scripts(out_dir=tmp_path, replay_command=cmd)
    assert hashes2 == hashes

    # Different replay command must fail closed (WORM semantics).
    try:
        write_replay_scripts(out_dir=tmp_path, replay_command=cmd + " --extra")
        assert False, "expected FAIL_CLOSED"
    except FL3ValidationError:
        pass
