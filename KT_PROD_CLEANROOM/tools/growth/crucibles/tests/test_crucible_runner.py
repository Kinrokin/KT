from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import yaml

import sys


def _add_growth_to_syspath() -> None:
    # .../tools/growth/crucibles/tests/test_crucible_runner.py -> .../tools/growth/crucibles
    crucibles_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(crucibles_root))


_add_growth_to_syspath()

from crucible_dsl_schemas import CrucibleBudgets, CrucibleSchemaError, CrucibleSpec  # noqa: E402
from crucible_dsl_schemas import budgets_hash, run_id, sha256_text  # noqa: E402
from crucible_loader import load_crucible  # noqa: E402
from crucible_runner import _check_output_contract, _run_subprocess_capped  # noqa: E402


def _minimal_spec() -> dict:
    return {
        "schema": "kt.crucible.spec",
        "schema_version": 1,
        "crucible_id": "CRU-TEST-01",
        "title": "t",
        "domain": "d",
        "tags": {
            "domains": [],
            "subdomains": [],
            "microdomains": [],
            "ventures": [],
            "reasoning_modes": [],
            "modalities": [],
            "tools": [],
            "paradox_classes": [],
        },
        "kernel_targets": ["V2_SOVEREIGN"],
        "input": {"mode": "RAW_INPUT_STRING", "prompt": "x"},
        "budgets": {"time_ms": 1000},
        "expect": {
            "expected_outcome": "PASS",
            "output_contract": {"must_be_json": True, "required_keys": []},
            "replay_verification": "NOT_APPLICABLE",
            "governance_expectations": {"required_event_types": [], "forbidden_event_types": [], "event_count_min": 0, "event_count_max": 0},
            "thermo_expectations": {"must_enforce_budget": False, "expected_budget_verdict": "BUDGET_NOT_ASSERTED"},
        },
    }


class TestCrucibleDSL(unittest.TestCase):
    def test_unknown_fields_rejected(self) -> None:
        data = _minimal_spec()
        data["extra"] = "nope"
        with self.assertRaises(CrucibleSchemaError):
            CrucibleSpec.from_dict(data)

    def test_hash_stable_across_load(self) -> None:
        data = _minimal_spec()
        data["crucible_id"] = "CRU-TEST-02"
        data["title"] = "Hash stable"
        data["domain"] = "ops.provenance"
        data["input"]["prompt"] = "hello"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.yaml"
            p.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
            a = load_crucible(p).crucible_spec_hash
            b = load_crucible(p).crucible_spec_hash
            self.assertEqual(a, b)


class TestOutputContract(unittest.TestCase):
    def test_output_contract_required_keys(self) -> None:
        ok, obj, err = _check_output_contract(
            stdout_text='{"status":"OK","explanation":"x"}',
            must_be_json=True,
            required_keys=("status", "explanation"),
            forbidden_substrings=(),
        )
        self.assertTrue(ok)
        self.assertIsInstance(obj, dict)
        self.assertIsNone(err)

        ok2, obj2, err2 = _check_output_contract(
            stdout_text='{"status":"OK"}',
            must_be_json=True,
            required_keys=("status", "explanation"),
            forbidden_substrings=(),
        )
        self.assertFalse(ok2)
        self.assertIsInstance(obj2, dict)
        self.assertEqual(err2, "missing_key:explanation")

    def test_output_contract_forbidden_substrings(self) -> None:
        ok, _obj, err = _check_output_contract(
            stdout_text='{"status":"OK","explanation":"chain-of-thought"}',
            must_be_json=True,
            required_keys=("status", "explanation"),
            forbidden_substrings=("chain-of-thought",),
        )
        self.assertFalse(ok)
        self.assertEqual(err, "forbidden_substring:chain-of-thought")


class TestRunnerCaps(unittest.TestCase):
    def test_timeout_kills_process_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
            res = _run_subprocess_capped(
                command=cmd,
                cwd=cwd,
                env=dict(os.environ),
                stdin_bytes=b"",
                time_ms=50,
                kill_grace_ms=100,
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                memory_max_mb=256,
            )
            self.assertTrue(res.was_killed)
            self.assertEqual(res.kill_reason, "TIMEOUT")

    def test_output_limit_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            # Print enough bytes to exceed the cap quickly.
            cmd = [sys.executable, "-c", "print('x' * 2000000)"]
            res = _run_subprocess_capped(
                command=cmd,
                cwd=cwd,
                env=dict(os.environ),
                stdin_bytes=b"",
                time_ms=5_000,
                kill_grace_ms=5_100,
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                memory_max_mb=256,
            )
            self.assertTrue(res.stdout_truncated)
            self.assertEqual(len(res.stdout), 1024)

    def test_memory_limit_kills_process_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            cmd = [
                sys.executable,
                "-c",
                "import time\n"
                "x = bytearray(128 * 1024 * 1024)\n"
                "time.sleep(10)\n",
            ]
            res = _run_subprocess_capped(
                command=cmd,
                cwd=cwd,
                env=dict(os.environ),
                stdin_bytes=b"",
                time_ms=5_000,
                kill_grace_ms=5_100,
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                memory_max_mb=32,
            )
            self.assertTrue(res.was_killed)
            self.assertEqual(res.kill_reason, "MEMORY_LIMIT")


class TestDeterminism(unittest.TestCase):
    def test_run_id_changes_by_kernel_target(self) -> None:
        spec_hash = "a" * 64
        prompt_hash = sha256_text("hello")
        budgets = budgets_hash(CrucibleBudgets.from_dict({"time_ms": 1000}))
        a = run_id(kernel_target="V2_SOVEREIGN", crucible_spec_hash_hex=spec_hash, prompt_hash_hex=prompt_hash, seed=0, budgets_hash_hex=budgets)
        b = run_id(kernel_target="V1_ARCHIVAL", crucible_spec_hash_hex=spec_hash, prompt_hash_hex=prompt_hash, seed=0, budgets_hash_hex=budgets)
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
