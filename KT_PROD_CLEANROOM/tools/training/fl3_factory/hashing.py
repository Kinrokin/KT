from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file_normalized(path: Path) -> str:
    """
    Stable across platforms: interpret as text, normalize CRLF->LF, encode UTF-8, then hash.
    Used for entrypoint self-hash enforcement.
    """
    data = path.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()

