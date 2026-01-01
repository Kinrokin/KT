from __future__ import annotations

import builtins
import socket
import sys
import unittest
from pathlib import Path


class NetworkCallAttempted(RuntimeError):
    pass


def _src_root() -> Path:
    return Path(__file__).resolve().parents[2]


sys.path.insert(0, str(_src_root()))

from curriculum.curriculum_ingest import CurriculumIngest  # noqa: E402
from curriculum.curriculum_schemas import (  # noqa: E402
    CurriculumPackageSchema,
    REFUSE_EXECUTABLE_CONTENT,
    REFUSE_FORBIDDEN_IMPORT,
    REFUSE_ILLEGAL_FIELD,
    REFUSE_POLICY_OVERRIDE,
    REFUSE_STUDENT_TO_TEACHER_FLOW,
    STATUS_OK,
    STATUS_REFUSED,
)
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH  # noqa: E402


def _valid_context() -> dict:
    return {
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
        "constitution_version_hash": "0" * 64,
    }


def _minimal_package() -> dict:
    return {
        "schema_id": CurriculumPackageSchema.SCHEMA_ID,
        "schema_version_hash": CurriculumPackageSchema.SCHEMA_VERSION_HASH,
        "package_id": "curr.pkg.v2",
        "runtime_registry_hash": "1" * 64,
        "examples": ["2" * 64],
        "instructions": ["3" * 64],
        "constraints": ["4" * 64],
    }


class TestCurriculumBoundary(unittest.TestCase):
    def test_schema_unknown_fields_refused(self) -> None:
        payload = _minimal_package()
        payload["unknown"] = "x"
        res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=payload).receipt.to_dict()
        self.assertEqual(res["status"], STATUS_REFUSED)
        self.assertEqual(res["refusal_code"], REFUSE_ILLEGAL_FIELD)

    def test_student_to_teacher_flow_refused(self) -> None:
        payload = _minimal_package()
        payload["runtime_receipt_hash"] = "0" * 64
        res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=payload).receipt.to_dict()
        self.assertEqual(res["status"], STATUS_REFUSED)
        self.assertEqual(res["refusal_code"], REFUSE_STUDENT_TO_TEACHER_FLOW)

    def test_executable_content_refused(self) -> None:
        payload = _minimal_package()
        payload["script"] = "echo hi"
        res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=payload).receipt.to_dict()
        self.assertEqual(res["status"], STATUS_REFUSED)
        self.assertEqual(res["refusal_code"], REFUSE_EXECUTABLE_CONTENT)

    def test_policy_override_refused(self) -> None:
        payload = _minimal_package()
        payload["policy_override"] = True
        res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=payload).receipt.to_dict()
        self.assertEqual(res["status"], STATUS_REFUSED)
        self.assertEqual(res["refusal_code"], REFUSE_POLICY_OVERRIDE)

    def test_no_network_calls(self) -> None:
        original = socket.socket

        class GuardedSocket(socket.socket):  # type: ignore[misc]
            def connect(self, *args, **kwargs):  # type: ignore[no-untyped-def]
                raise NetworkCallAttempted("Network attempt (fail-closed)")

        socket.socket = GuardedSocket  # type: ignore[assignment]
        try:
            res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=_minimal_package()).receipt.to_dict()
            self.assertIn(res["status"], {STATUS_OK, STATUS_REFUSED})
        finally:
            socket.socket = original  # type: ignore[assignment]

    def test_deterministic_receipt_hash(self) -> None:
        payload = _minimal_package()
        ctx = _valid_context()
        hashes = set()
        for _ in range(25):
            receipt = CurriculumIngest.accept_payload(context=ctx, package_payload=payload).receipt.to_dict()
            hashes.add(receipt["receipt_hash"])
        self.assertEqual(len(hashes), 1)

    def test_isolation_no_cognition_or_council_imports(self) -> None:
        original_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if isinstance(name, str) and (name.startswith("cognition") or name.startswith("council")):
                raise AssertionError(f"Unexpected import during curriculum ingestion: {name}")
            return original_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import  # type: ignore[assignment]
        try:
            _ = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=_minimal_package())
        finally:
            builtins.__import__ = original_import  # type: ignore[assignment]

    def test_forbidden_training_lib_loaded_refuses(self) -> None:
        # If a forbidden training lib is already loaded, ingestion refuses (fail-closed).
        original = sys.modules.get("torch")
        sys.modules["torch"] = object()
        try:
            res = CurriculumIngest.accept_payload(context=_valid_context(), package_payload=_minimal_package()).receipt.to_dict()
            self.assertEqual(res["status"], STATUS_REFUSED)
            self.assertEqual(res["refusal_code"], REFUSE_FORBIDDEN_IMPORT)
        finally:
            if original is None:
                sys.modules.pop("torch", None)
            else:
                sys.modules["torch"] = original

