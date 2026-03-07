from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Optional, Sequence

from tools.verification.strict_json import load_no_dupes


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_value(v) for v in value]
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n")
    return value


def canonicalize_json_text(obj: Any) -> str:
    normalized = _normalize_value(obj)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonicalize_bytes(input_json: Any) -> bytes:
    if isinstance(input_json, (bytes, bytearray)):
        input_json = json.loads(bytes(input_json).decode("utf-8"))
    elif isinstance(input_json, str):
        input_json = json.loads(input_json)
    return canonicalize_json_text(input_json).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalize_path(path: Path) -> bytes:
    obj = load_no_dupes(path)
    return canonicalize_bytes(obj)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Canonicalize JSON to stable UTF-8 bytes.")
    ap.add_argument("path", help="JSON file path.")
    ap.add_argument("--sha256", action="store_true", help="Print sha256 of canonical bytes instead of bytes.")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    data = canonicalize_path(Path(args.path))
    if bool(args.sha256):
        print(sha256_hex(data))
    else:
        print(data.decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
