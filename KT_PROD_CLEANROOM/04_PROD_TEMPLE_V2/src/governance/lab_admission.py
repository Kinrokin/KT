"""Opt-in operator admission for a finite local inference laboratory.

An operator supplies and independently pins a reviewed execution contract. The
untrusted runtime request cannot activate a session or supply its own grant.
The pin establishes byte identity, not a human signature. Operator/OS ownership
is the trust boundary; this is not canonical artifact promotion or training law.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any, Iterator

from memory.lab_effect import read_record, write_record, write_bytes_once
from schemas.checked_task import canonical_bytes, identity, strict_json, validate_task
from schemas.trusted_local_path import assert_no_link_or_reparse_path


_SESSION: ContextVar[LabSession | None] = ContextVar("kt_operator_lab_session", default=None)
_HEX = re.compile(r"[0-9a-f]{64}\Z")
CONTRACT_SCHEMA = "kt.lab.execution_contract.v1"
REQUEST_SCHEMA = "kt.lab.checked_request.v1"
STRATEGIES = {"direct", "self_review", "kt_diagnostic", "sham", "nonconsuming"}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def _positive_int(value: Any, maximum: int, name: str) -> None:
    _require(type(value) is int and 0 < value <= maximum, "LAB_LIMIT_" + name)


def validate_contract(value: Any) -> dict[str, Any]:
    expected = {"schema_id", "run_id", "authority_sha256", "authority_basis", "output_root",
                "expires_at", "source_files", "runtime_registry_sha256", "backend", "limits", "operations"}
    _require(type(value) is dict and set(value) == expected, "LAB_CONTRACT_FIELDS")
    _require(value["schema_id"] == CONTRACT_SCHEMA, "LAB_CONTRACT_SCHEMA")
    _require(type(value["run_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["run_id"]) is not None, "LAB_RUN_ID")
    _require(type(value["authority_sha256"]) is str and _HEX.fullmatch(value["authority_sha256"]) is not None, "LAB_AUTHORITY_REF")
    _require(value["authority_basis"] == "OWNER_ADOPTED_PRIVATE_NONPAID_EXPERIMENT", "LAB_AUTHORITY_SCOPE")
    _require(type(value["expires_at"]) is int and value["expires_at"] > 0, "LAB_EXPIRY")
    _require(type(value["runtime_registry_sha256"]) is str and _HEX.fullmatch(value["runtime_registry_sha256"]) is not None,
             "LAB_RUNTIME_REGISTRY_PIN")
    root = value["output_root"]
    _require(type(root) is str and Path(root).is_absolute(), "LAB_ROOT")
    limits = value["limits"]
    ceilings = {"calls": 6000, "generated_tokens": 3000000, "attempts_per_task": 3,
                "max_new_tokens": 4096, "timeout_seconds": 600, "wall_seconds": 7200}
    _require(type(limits) is dict and set(limits) == set(ceilings), "LAB_LIMIT_FIELDS")
    for name, ceiling in ceilings.items():
        _positive_int(limits[name], ceiling, name)
    operations = value["operations"]
    _require(type(operations) is dict and 0 < len(operations) <= 6000, "LAB_OPERATIONS")
    for key, op in operations.items():
        _require(type(key) is str and _HEX.fullmatch(key) is not None, "LAB_OPERATION_ID")
        _require(type(op) is dict and set(op) == {"task", "strategy", "attempts", "consume"}, "LAB_OPERATION_FIELDS")
        validate_task(op["task"])
        _require(type(op["strategy"]) is str and op["strategy"] in STRATEGIES, "LAB_STRATEGY")
        _positive_int(op["attempts"], limits["attempts_per_task"], "attempts")
        _require(op["strategy"] != "direct" or op["attempts"] == 1, "LAB_DIRECT_ONE_ATTEMPT")
        _require(type(op["consume"]) is bool, "LAB_CONSUME")
        _require(not (op["strategy"] == "nonconsuming" and op["consume"]), "LAB_NONCONSUMING_EFFECT")
        _require(key == identity(op), "LAB_OPERATION_BINDING")
    source = value["source_files"]
    _require(type(source) is dict and bool(source), "LAB_SOURCE_PINS")
    for path, digest in source.items():
        _require(type(path) is str and not Path(path).is_absolute() and ".." not in Path(path).parts
                 and "\\" not in path and ":" not in path and type(digest) is str
                 and _HEX.fullmatch(digest) is not None, "LAB_SOURCE_PIN")
    backend = value["backend"]
    _require(type(backend) is dict and backend.get("kind") == "local_qwen_nf4", "LAB_BACKEND_KIND")
    # Backend validates all exact model/file/config keys before any process is started.
    return strict_json(canonical_bytes(value), max_bytes=2 * 1024 * 1024)


class LabSession:
    def __init__(self, path: Path, expected_hash: str):
        assert_no_link_or_reparse_path(path, label="operator lab contract")
        raw = path.read_bytes()
        _require(hashlib.sha256(raw).hexdigest() == expected_hash, "LAB_OPERATOR_PIN_MISMATCH")
        self.contract = validate_contract(strict_json(raw, max_bytes=2 * 1024 * 1024))
        self.contract_path, self.contract_hash = path, expected_hash
        self.root = Path(self.contract["output_root"])
        assert_no_link_or_reparse_path(self.root, label="lab output")
        _require(self.root.is_dir(), "LAB_OUTPUT_ROOT_MUST_EXIST")
        _require(self.root.resolve(strict=True) == self.root and ".." not in self.root.parts, "LAB_ROOT_NONCANONICAL")
        source_root = Path(__file__).resolve().parents[1]
        registry_path = source_root.parent / "docs" / "RUNTIME_REGISTRY.json"
        assert_no_link_or_reparse_path(registry_path, label="laboratory runtime registry")
        _require(hashlib.sha256(registry_path.read_bytes()).hexdigest() == self.contract["runtime_registry_sha256"],
                 "LAB_RUNTIME_REGISTRY_BYTES")
        _require(not self.root.is_relative_to(source_root.parents[2]), "LAB_OUTPUT_MUST_BE_EXTERNAL")
        # Complete canonical source pins, not a caller-selected subset of critical functions.
        required = {str(p.relative_to(source_root)).replace(os.sep, "/")
                    for p in source_root.rglob("*.py") if "tests" not in p.parts}
        _require(set(self.contract["source_files"]) == required, "LAB_SOURCE_COVERAGE")
        for rel, digest in self.contract["source_files"].items():
            candidate = source_root / rel
            assert_no_link_or_reparse_path(candidate, label="lab source")
            _require(hashlib.sha256(candidate.read_bytes()).hexdigest() == digest, "LAB_SOURCE_BYTES")
        self.started_at = time.time()
        self.started_monotonic = time.monotonic()
        self.backend = None
        self._lock = None

    def authority(self, operation_id: str, *, effect: bool = False) -> dict[str, Any]:
        _require(operation_id in self.contract["operations"], "LAB_OPERATION_NOT_ADMITTED")
        _require(self._lock is not None and not self._lock.closed, "LAB_SESSION_NOT_LOCKED")
        _require(time.time() < self.contract["expires_at"], "LAB_AUTHORITY_EXPIRED")
        _require(time.time() - self.started_at < self.contract["limits"]["wall_seconds"], "LAB_WALL_LIMIT")
        _require(time.monotonic() - self.started_monotonic < self.contract["limits"]["wall_seconds"], "LAB_MONOTONIC_WALL_LIMIT")
        assert_no_link_or_reparse_path(self.contract_path, label="lab authority")
        _require(hashlib.sha256(self.contract_path.read_bytes()).hexdigest() == self.contract_hash, "LAB_AUTHORITY_CHANGED")
        _require(not (self.root / "REVOKED").exists(), "LAB_AUTHORITY_REVOKED")
        _require(not effect or self.contract["operations"][operation_id]["consume"], "LAB_EFFECT_NOT_AUTHORIZED")
        return {"schema_id": "kt.lab.current_authority.v1", "operation_id": operation_id,
                "contract_sha256": self.contract_hash, "authority_sha256": self.contract["authority_sha256"],
                "checked_at": time.time(), "action": "BOUNDED_SANDBOX_EFFECT" if effect else "LOCAL_INFERENCE",
                "assurance": "TRUSTED_OPERATOR_ADOPTION_NOT_CRYPTOGRAPHIC_HUMAN_SIGNATURE"}

    def remaining_seconds(self) -> float:
        remaining = min(self.contract["expires_at"] - time.time(),
                        self.started_at + self.contract["limits"]["wall_seconds"] - time.time(),
                        self.contract["limits"]["wall_seconds"] - (time.monotonic() - self.started_monotonic))
        _require(remaining > 0, "LAB_NO_TIME_REMAINING")
        return min(self.contract["limits"]["timeout_seconds"], remaining)

    def reserve(self, operation_id: str, attempt: int, prompt_hash: str) -> Path:
        self.authority(operation_id)
        op = self.contract["operations"][operation_id]
        _require(type(attempt) is int and 0 <= attempt < op["attempts"], "LAB_ATTEMPT_LIMIT")
        reservations = list(self.root.glob("*/attempt_*_reserved.json"))
        limits = self.contract["limits"]
        # Pessimistic charging survives failed calls, crashes and restarts.
        _require(len(reservations) < limits["calls"], "LAB_CALL_LIMIT")
        _require((len(reservations) + 1) * limits["max_new_tokens"] <= limits["generated_tokens"], "LAB_TOKEN_RESERVATION_LIMIT")
        root = self.root / operation_id
        assert_no_link_or_reparse_path(root, label="lab operation")
        root.mkdir(exist_ok=True)
        path = root / f"attempt_{attempt}_reserved.json"
        write_record(path, {"operation_id": operation_id, "attempt": attempt, "prompt_hash": prompt_hash,
                           "max_new_tokens": limits["max_new_tokens"], "contract_sha256": self.contract_hash})
        return root


@contextmanager
def operator_session(contract_path: Path, *, expected_sha256: str) -> Iterator[LabSession]:
    """Trusted operator API; deliberately unavailable through a runtime request."""
    import fcntl

    _require(_SESSION.get() is None, "NESTED_LAB_SESSION")
    session = LabSession(contract_path, expected_sha256)
    lock_path = session.root / "session.lock"
    assert_no_link_or_reparse_path(lock_path, label="lab session lock")
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        session._lock = lock
        preserved = session.root / "operator_contract.json"
        if preserved.exists():
            _require(hashlib.sha256(preserved.read_bytes()).hexdigest() == expected_sha256, "LAB_PRESERVED_CONTRACT_MISMATCH")
        else:
            write_bytes_once(preserved, session.contract_path.read_bytes())
        receipt = session.root / "admission.json"
        admission = {"contract_sha256": expected_sha256, "contract": session.contract,
                     "started_at": session.started_at}
        if receipt.exists():
            prior = read_record(receipt)
            _require(prior.get("contract_sha256") == expected_sha256 and prior.get("contract") == session.contract,
                     "LAB_RESUME_CONTRACT_MISMATCH")
            session.started_at = prior["started_at"]
        else:
            write_record(receipt, admission)
        token = _SESSION.set(session)
        try:
            yield session
        finally:
            _SESSION.reset(token)
            if session.backend is not None:
                session.backend.close()
            session._lock = None


def current_session() -> LabSession:
    session = _SESSION.get()
    _require(session is not None, "LAB_OPERATOR_ADMISSION_REQUIRED")
    return session
