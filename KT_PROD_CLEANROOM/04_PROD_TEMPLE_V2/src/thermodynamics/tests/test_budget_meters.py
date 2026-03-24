from __future__ import annotations

import sys
import unittest
from pathlib import Path


def _add_src_to_syspath() -> None:
    src_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from thermodynamics.meters.duration_fuse import remaining_millis  # noqa: E402
from thermodynamics.meters.memory_meter import remaining_bytes  # noqa: E402
from thermodynamics.meters.step_meter import remaining_branches, remaining_steps  # noqa: E402
from thermodynamics.meters.token_meter import remaining_tokens  # noqa: E402


class TestBudgetMeters(unittest.TestCase):
    def test_remaining_values_are_deterministic(self) -> None:
        self.assertEqual(remaining_tokens(ceiling_tokens=10, used_tokens=3), 7)
        self.assertEqual(remaining_steps(ceiling_steps=5, used_steps=2), 3)
        self.assertEqual(remaining_branches(ceiling_branches=4, used_branches=1), 3)
        self.assertEqual(remaining_bytes(ceiling_bytes=1024, used_bytes=24), 1000)
        self.assertEqual(remaining_millis(ceiling_millis=100, used_millis=15), 85)

    def test_negative_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            remaining_tokens(ceiling_tokens=-1, used_tokens=0)
        with self.assertRaises(ValueError):
            remaining_steps(ceiling_steps=1, used_steps=-1)
        with self.assertRaises(ValueError):
            remaining_branches(ceiling_branches=-1, used_branches=0)
        with self.assertRaises(ValueError):
            remaining_bytes(ceiling_bytes=1, used_bytes=-1)
        with self.assertRaises(ValueError):
            remaining_millis(ceiling_millis=-1, used_millis=0)
