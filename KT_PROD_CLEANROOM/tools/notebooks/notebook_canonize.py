from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.verification.attestation_hmac import env_key_name_for_key_id, sign_hmac
from tools.verification.worm_write import write_text_worm


def _fail_closed(msg: str) -> int:
    raise SystemExit(f"FAIL_CLOSED: {msg}")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _scan_blocked_patterns(*, text: str) -> List[str]:
    """
    Conservative notebook scan for disallowed operational surfaces.

    This is not a security scanner; it is a fail-closed guardrail for golden notebooks.
    """
    blocked = [
        "http://",
        "https://",
        "requests.get(",
        "requests.post(",
        "curl ",
        "Invoke-WebRequest",
        "wget ",
        "pip install",
    ]
    hits: List[str] = []
    t = text.lower()
    for pat in blocked:
        if pat.lower() in t:
            hits.append(pat)
    return hits


def _extract_imports_from_python(code: str) -> List[str]:
    imports: List[str] = []
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m1 = re.match(r"^import\s+([A-Za-z0-9_\.]+)", s)
        if m1:
            imports.append(m1.group(1).split(".")[0])
            continue
        m2 = re.match(r"^from\s+([A-Za-z0-9_\.]+)\s+import\s+", s)
        if m2:
            imports.append(m2.group(1).split(".")[0])
            continue
    return sorted({x for x in imports if x})


def _canonize_ipynb(path: Path) -> Tuple[int, str, List[str]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        _fail_closed("ipynb is not a JSON object")
    cells = obj.get("cells")
    if not isinstance(cells, list):
        _fail_closed("ipynb missing cells array")

    cell_digests: List[str] = []
    imports: List[str] = []
    for c in cells:
        if not isinstance(c, dict):
            _fail_closed("ipynb cell is not object")
        cell_type = str(c.get("cell_type", "")).strip()
        src = c.get("source")
        if isinstance(src, list):
            source = "".join(str(x) for x in src)
        elif isinstance(src, str):
            source = src
        else:
            source = ""
        source = source.replace("\r\n", "\n").replace("\r", "\n")

        h = hashlib.sha256()
        h.update(cell_type.encode("utf-8"))
        h.update(b"\n")
        h.update(source.encode("utf-8"))
        cell_digests.append(h.hexdigest())

        if cell_type == "code":
            imports.extend(_extract_imports_from_python(source))

    order_digest = hashlib.sha256(("\n".join(cell_digests) + "\n").encode("utf-8")).hexdigest()
    return len(cells), order_digest, sorted({x for x in imports if x})


def _canonize_markdown(path: Path) -> Tuple[int, str, List[str]]:
    txt = _read_text(path).replace("\r\n", "\n").replace("\r", "\n")
    # Treat fenced python blocks as cells.
    cells: List[str] = []
    cur: List[str] = []
    in_py = False
    for ln in txt.splitlines():
        if ln.startswith("```"):
            fence = ln.strip().lower()
            if not in_py and fence.startswith("```python"):
                in_py = True
                cur = []
                continue
            if in_py and fence == "```":
                in_py = False
                cells.append("\n".join(cur) + "\n")
                cur = []
                continue
        if in_py:
            cur.append(ln)

    cell_digests: List[str] = []
    imports: List[str] = []
    for source in cells:
        h = hashlib.sha256(source.encode("utf-8")).hexdigest()
        cell_digests.append(h)
        imports.extend(_extract_imports_from_python(source))

    order_digest = hashlib.sha256(("\n".join(cell_digests) + "\n").encode("utf-8")).hexdigest()
    return len(cells), order_digest, sorted({x for x in imports if x})


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Golden notebook canonizer (hash, import graph, cell order; optional HMAC signoff).")
    ap.add_argument("--notebook", required=True, help="Path to notebook (.ipynb) or notebook-plan markdown (.md).")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM; must be empty).")
    ap.add_argument("--signing-key-id", default="", help="Optional HMAC key_id to sign manifest (env: KT_HMAC_KEY_<KEYID>).")
    ap.add_argument("--require-signature", action="store_true", help="Fail-closed if signing key missing.")
    ap.add_argument("--strict-scan", action="store_true", help="Fail-closed if blocked patterns are present in notebook bytes.")
    args = ap.parse_args(argv)

    nb_path = Path(args.notebook).resolve()
    if not nb_path.is_file():
        _fail_closed("notebook missing")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.iterdir()):
        _fail_closed("out_dir is not empty (WORM directory reuse forbidden)")

    raw = nb_path.read_bytes()
    fmt = nb_path.suffix.lower().lstrip(".")
    if fmt not in {"ipynb", "md"}:
        _fail_closed("unsupported notebook format (expected .ipynb or .md)")

    if bool(args.strict_scan):
        hits = _scan_blocked_patterns(text=raw.decode("utf-8", errors="ignore"))
        if hits:
            _fail_closed("blocked patterns present: " + ",".join(sorted(set(hits))))

    if fmt == "ipynb":
        cell_count, cell_order_sha256, imports = _canonize_ipynb(nb_path)
    else:
        cell_count, cell_order_sha256, imports = _canonize_markdown(nb_path)

    manifest: Dict[str, Any] = {
        "schema_id": "kt.golden_notebook_manifest.v1",
        "version": "1.0.0",
        "notebook_path": nb_path.as_posix(),
        "format": fmt,
        "notebook_sha256": _sha256_bytes(raw),
        "cell_count": int(cell_count),
        "cell_order_sha256": cell_order_sha256,
        "imports": imports,
        "env_fingerprint": {
            "python": sys.version.split()[0],
            "python_implementation": platform.python_implementation(),
            "pythonhashseed": os.environ.get("PYTHONHASHSEED", ""),
            "pythonpath": os.environ.get("PYTHONPATH", ""),
        },
        "signoff": {},
    }

    key_id = str(args.signing_key_id).strip()
    if key_id:
        env_name = env_key_name_for_key_id(key_id)
        key = os.environ.get(env_name, "")
        if not key:
            if bool(args.require_signature):
                _fail_closed(f"missing signing key env var: {env_name}")
        else:
            payload_hash = hashlib.sha256(_canonical_json({k: v for k, v in manifest.items() if k != "signoff"}).encode("utf-8")).hexdigest()
            sig, fp = sign_hmac(key_bytes=key.encode("utf-8"), key_id=key_id, payload_hash=payload_hash)
            manifest["signoff"] = {
                "key_id": key_id,
                "payload_hash": payload_hash,
                "hmac_signature": sig,
                "hmac_key_fingerprint": fp,
            }

    write_text_worm(
        path=out_dir / "notebook_manifest.json",
        text=json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="notebook_manifest.json",
    )
    # Convenience hash file for the manifest itself.
    mh = _sha256_file(out_dir / "notebook_manifest.json")
    write_text_worm(
        path=out_dir / "notebook_manifest.json.sha256.txt",
        text=mh + "  notebook_manifest.json\n",
        label="notebook_manifest.json.sha256.txt",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
