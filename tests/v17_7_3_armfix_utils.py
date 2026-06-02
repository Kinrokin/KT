from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_core():
    path = ROOT / "runtime" / "v17_7_3" / "KT_V1773_MEASURED_ARM_CORE.py"
    spec = importlib.util.spec_from_file_location("kt_v1773_measured_arm_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load measured arm core: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def read_jsonl(relative: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / relative).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def packet_names(relative: str) -> set[str]:
    with zipfile.ZipFile(ROOT / relative) as archive:
        return set(archive.namelist())


def runtime_root_from_packet(tmp_path: Path) -> Path:
    packet = ROOT / "packets" / "ktv1773_measured_arm_v1.zip"
    out = tmp_path / "packet"
    with zipfile.ZipFile(packet) as archive:
        archive.extractall(out)
    return out


def run_runtime(tmp_path: Path) -> tuple[object, Path]:
    core = load_core()
    runtime_root = runtime_root_from_packet(tmp_path)
    output_dir = tmp_path / "out"
    result = core.run_measured_arm_runtime(runtime_root, output_dir)
    assert result["status"] == "PASS"
    return core, output_dir
