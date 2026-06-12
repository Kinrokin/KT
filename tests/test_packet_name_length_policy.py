from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_packet_names_are_short_lowercase_and_versioned() -> None:
    for path in (ROOT / "packets").glob("**/*.zip"):
        assert len(path.name) <= 64
        assert path.name == path.name.lower()
        assert "_v" in path.name
