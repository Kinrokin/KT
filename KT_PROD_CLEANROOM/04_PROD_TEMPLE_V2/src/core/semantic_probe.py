from __future__ import annotations

import base64
from contextvars import ContextVar, Token
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any, Dict, Iterable

from schemas.semantic_vertical_schemas import SemanticVerticalError
from schemas.trusted_local_path import assert_no_link_or_reparse_path, is_link_or_reparse_point


EVENT_ROOTS = {
    "entry.invoke": "kt",
    "spine.semantic_dispatch": "core",
    "versioning.constitution_binding": "versioning",
    "thermodynamics.precheck": "thermodynamics",
    "council.route": "council",
    "provider.transport_receipt_observed": "council",
    "provider.typed_message_observed": "schemas",
    "council.admission_observed": "council",
    "evidence.prepared": "versioning",
    "memory.consumer_decision_observed": "memory",
    "memory.semantic_effect_receipt_observed": "memory",
    "memory.rollback_receipt_observed": "memory",
    "governance.policy_receipt_observed": "governance",
    "evidence.finalized": "versioning",
}
REQUIRED_CORRELATED_ROOTS = {
    "kt",
    "core",
    "schemas",
    "versioning",
    "thermodynamics",
    "council",
    "governance",
    "memory",
}
EXPECTED_NO_CORRELATED_EVENT_ROOTS = {"cognition", "curriculum", "multiverse", "paradox", "temporal"}
EVENT_BINDING_KEYS = {
    "entry.invoke": "entry_attestation_hash",
    "spine.semantic_dispatch": "occurrence_hash",
    "versioning.constitution_binding": "constitution_version_hash",
    "thermodynamics.precheck": "allocation_hash",
    "council.route": "plan_hash",
    "provider.transport_receipt_observed": "provider_receipt_hash",
    "provider.typed_message_observed": "message_hash",
    "council.admission_observed": "meaning_hash",
    "evidence.prepared": "transcript_hash",
    "memory.consumer_decision_observed": "decision_hash",
    "memory.semantic_effect_receipt_observed": "effect_receipt_hash",
    "memory.rollback_receipt_observed": "rollback_receipt_hash",
    "governance.policy_receipt_observed": "governance_event_hash",
    "evidence.finalized": "terminal_evidence_hash",
}
REQUIRED_ARTIFACT_BINDINGS = {
    "entry_attestation_hash",
    "context_hash",
    "occurrence_hash",
    "semantic_request_id",
    "execution_id",
    "subject_hash",
    "runtime_registry_hash",
    "constitution_version_hash",
    "allocation_hash",
    "plan_hash",
    "manifest_hash",
    "prompt_hash",
    "routing_record_hash",
    "raw_response_hash",
    "provider_receipt_hash",
    "message_hash",
    "meaning_hash",
    "decision_hash",
    "transcript_hash",
    "effect_id",
    "effect_receipt_hash",
    "rollback_receipt_hash",
    "effect_post_state_hash",
    "effect_restored_state_hash",
    "effect_journal_hash",
    "result_hash",
    "terminal_evidence_hash",
    "adapter_invocation_id",
    "governance_event_hash",
}


PROBE_CONTRACT = {
    "schema_id": "kt.prb.semantic_probe_contract.v1",
    "required_events": list(EVENT_ROOTS),
    "event_roots": EVENT_ROOTS,
    "probe_may_change_route_provider_meaning_or_decision": False,
    "probe_is_mandatory_claim_gate": True,
    "probe_failure_may_hold_before_effect_but_never_changes_semantic_values": True,
    "probe_off_status": "FUNCTIONAL_ONLY_NO_PROBE_CLAIM",
    "unknown_paths_allowed": 0,
    "unexpected_organs_allowed": 0,
}
PROBE_CONTRACT_HASH = hashlib.sha256(
    json.dumps(PROBE_CONTRACT, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
).hexdigest()
MAX_EVIDENCE_REPLAY_BYTES = 256 * 1024
RUN_PROOF_STATUS = "PASS_OFFLINE_CORRELATED_PROBE"
RUN_CLAIM_CEILING = "ONE_OFFLINE_CANONICAL_COUNCIL_SEMANTIC_ARTERY_ONLY"
COVERAGE_OBSERVATION_CEILING = "CORRELATED_PRB_EVENTS_ONLY__NOT_GLOBAL_MODULE_EXECUTION_PROOF"
RESULT_PROOF_STATUS = "SEMANTIC_RESULT_ONLY_NOT_FINAL_PROOF"
TERMINAL_SEMANTIC_TRUTH_CEILING = (
    "CAUSAL_PLUMBING_FROM_DETACHED_FIXTURE_ONLY__SUBJECT_TRUTH_NOT_PROVEN"
)
TERMINAL_DURABILITY_CEILING = "IN_PROCESS_ROLLBACK_ONLY__PROCESS_KILL_DURABILITY_NOT_PROVEN"
TERMINAL_FILESYSTEM_CEILING = "TRUSTED_FRESH_LOCAL_ROOT__HOSTILE_LOCAL_RACE_NOT_PROVEN"
EFFECT_STATUS = "APPLIED_AT_MOST_ONCE_IN_THIS_EXECUTION_AND_RESTORED"
EFFECT_DURABILITY_CEILING = "IN_PROCESS_ROLLBACK_PROVEN__PROCESS_KILL_DURABILITY_NOT_PROVEN"


_CANONICAL_ENTRY_SCOPE: ContextVar[tuple[str, str, str] | None] = ContextVar(
    "kt_prb_canonical_entry_scope",
    default=None,
)


ROOT_CLASSIFICATIONS = {
    "kt": "REQUIRED_OBSERVED_AND_CONSUMED",
    "core": "REQUIRED_OBSERVED_AND_CONSUMED",
    "schemas": "REQUIRED_OBSERVED_AND_CONSUMED",
    "versioning": "REQUIRED_CONTRACT_BINDING_OBSERVED",
    "thermodynamics": "REQUIRED_OBSERVED_AND_CONSUMED",
    "council": "REQUIRED_OBSERVED_AND_CONSUMED",
    "governance": "REQUIRED_OBSERVED_AND_CONSUMED",
    "memory": "REQUIRED_OBSERVED_AND_CONSUMED",
    "cognition": "EXPECTED_NO_CORRELATED_EVENT_IN_THIS_PRB_LEDGER",
    "curriculum": "EXPECTED_NO_CORRELATED_EVENT_IN_THIS_PRB_LEDGER",
    "multiverse": "EXPECTED_NO_CORRELATED_EVENT_IN_THIS_PRB_LEDGER",
    "paradox": "EXPECTED_NO_CORRELATED_EVENT_IN_THIS_PRB_LEDGER",
    "temporal": "EXPECTED_NO_CORRELATED_EVENT_IN_THIS_PRB_LEDGER",
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _context_hash(context: Dict[str, Any]) -> str:
    try:
        return _sha256_bytes(_canonical_bytes(context))
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("canonical entry context is not hashable (fail-closed)") from exc


def _begin_canonical_entry_scope(context: Dict[str, Any]) -> Token[tuple[str, str, str] | None]:
    """Mint route evidence only for the exact `kt.entrypoint.invoke` caller frame."""
    try:
        caller = sys._getframe(1)
        entry_module = sys.modules.get("kt.entrypoint")
        entry_globals = getattr(entry_module, "__dict__", None)
        entry_invoke = getattr(entry_module, "invoke", None)
        entry_code = getattr(entry_invoke, "__code__", None)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("canonical entry caller inspection failed (fail-closed)") from exc
    if (
        entry_module is None
        or caller.f_globals is not entry_globals
        or caller.f_code.co_name != "invoke"
        or caller.f_code is not entry_code
    ):
        raise SemanticVerticalError("canonical entry scope may be minted only by kt.entrypoint.invoke (fail-closed)")
    if _CANONICAL_ENTRY_SCOPE.get() is not None:
        raise SemanticVerticalError("nested canonical entry scope forbidden (fail-closed)")
    context_hash = _context_hash(context)
    execution_id = secrets.token_hex(32)
    attestation_hash = _sha256_bytes(
        _canonical_bytes(
            {
                "schema_id": "kt.prb.canonical_entry_attestation.v1",
                "entry": "kt.entrypoint.invoke",
                "context_hash": context_hash,
                "execution_id": execution_id,
            }
        )
    )
    return _CANONICAL_ENTRY_SCOPE.set((context_hash, attestation_hash, execution_id))


def _end_canonical_entry_scope(token: Token[tuple[str, str, str] | None]) -> None:
    _CANONICAL_ENTRY_SCOPE.reset(token)


def require_canonical_entry_attestation(context: Dict[str, Any]) -> tuple[str, str]:
    scoped = _CANONICAL_ENTRY_SCOPE.get()
    if scoped is None:
        raise SemanticVerticalError("semantic claim requires kt.entrypoint.invoke (fail-closed)")
    context_hash, attestation_hash, execution_id = scoped
    if context_hash != _context_hash(context):
        raise SemanticVerticalError("canonical entry context binding mismatch (fail-closed)")
    return attestation_hash, execution_id


def _assert_no_symlink_path(path: Path) -> None:
    try:
        assert_no_link_or_reparse_path(path, label="semantic evidence path")
    except RuntimeError as exc:
        raise SemanticVerticalError(str(exc)) from exc


def _safe_root(artifact_root: Path) -> Path:
    if not artifact_root.is_absolute():
        raise SemanticVerticalError("semantic evidence root must be absolute (fail-closed)")
    _assert_no_symlink_path(artifact_root)
    try:
        root = artifact_root.resolve(strict=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("semantic evidence root missing (fail-closed)") from exc
    semantic_root = root / "semantic_vertical"
    _assert_no_symlink_path(semantic_root)
    try:
        semantic_root.mkdir(parents=False, exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("unable to prepare semantic evidence root (fail-closed)") from exc
    _assert_no_symlink_path(semantic_root)
    return semantic_root


def _atomic_write(path: Path, data: bytes, *, identity: str) -> None:
    if path.exists() and path.is_symlink():
        raise SemanticVerticalError("semantic evidence target symlink forbidden (fail-closed)")
    temp = path.with_name(f".{path.name}.{identity}.tmp")
    if temp.exists() or temp.is_symlink():
        raise SemanticVerticalError("semantic evidence temp collision (fail-closed)")
    fd = None
    try:
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise SemanticVerticalError("semantic evidence write failed (fail-closed)")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temp, path)
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        try:
            temp.unlink()
        except Exception:
            pass
        raise


class SemanticProbeRecorder:
    """Mandatory claim evidence gate; it cannot choose semantic execution values."""

    def __init__(self, *, artifact_root: Path, request_id: str, execution_id: str, enabled: bool) -> None:
        if len(request_id) != 64 or any(ch not in "0123456789abcdef" for ch in request_id):
            raise SemanticVerticalError("semantic probe request_id invalid (fail-closed)")
        if len(execution_id) != 64 or any(ch not in "0123456789abcdef" for ch in execution_id):
            raise SemanticVerticalError("semantic probe execution_id invalid (fail-closed)")
        self._enabled = bool(enabled)
        self._request_id = request_id
        self._execution_id = execution_id
        self._sequence = 0
        self._head = "GENESIS"
        self._events: list[str] = []
        self._terminal_attempted = False
        base_semantic_root = _safe_root(artifact_root)
        runs_root = base_semantic_root / "runs"
        _assert_no_symlink_path(runs_root)
        try:
            runs_root.mkdir(parents=False, exist_ok=True)
            run_artifact_root = runs_root / execution_id
            run_artifact_root.mkdir(parents=False, exist_ok=False)
        except FileExistsError as exc:
            raise SemanticVerticalError("semantic execution_id collision/reuse (fail-closed)") from exc
        except Exception as exc:  # noqa: BLE001
            raise SemanticVerticalError("unable to initialize exclusive semantic run (fail-closed)") from exc
        _assert_no_symlink_path(run_artifact_root)
        self._run_artifact_root = run_artifact_root
        self._root = _safe_root(run_artifact_root)
        self._path: Path | None = None
        if self._enabled:
            self._path = self._root / "probe_ledger.jsonl"
            try:
                self._path.touch(mode=0o600, exist_ok=False)
            except Exception as exc:  # noqa: BLE001
                raise SemanticVerticalError("unable to initialize probe sink (fail-closed)") from exc

    @property
    def run_artifact_root(self) -> Path:
        return self._run_artifact_root

    def observe(self, event: str, *, organ_root: str, identity_hash: str) -> None:
        if self._terminal_attempted:
            raise SemanticVerticalError("probe already entered terminal court (fail-closed)")
        if not self._enabled:
            return
        if event not in PROBE_CONTRACT["required_events"]:
            raise SemanticVerticalError("unknown probe event forbidden (fail-closed)")
        if organ_root != EVENT_ROOTS[event]:
            raise SemanticVerticalError("probe event/root binding mismatch (fail-closed)")
        if (
            not isinstance(identity_hash, str)
            or len(identity_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in identity_hash)
        ):
            raise SemanticVerticalError("probe identity hash invalid (fail-closed)")
        assert self._path is not None
        self._sequence += 1
        payload = {
            "schema_id": "kt.prb.semantic_probe_event.v1",
            "probe_contract_hash": PROBE_CONTRACT_HASH,
            "request_id": self._request_id,
            "execution_id": self._execution_id,
            "sequence": self._sequence,
            "previous_event_hash": self._head,
            "event": event,
            "organ_root": organ_root,
            "identity_hash": identity_hash,
        }
        event_hash = _sha256_bytes(_canonical_bytes(payload))
        row = {**payload, "event_hash": event_hash}
        try:
            with self._path.open("ab") as handle:
                handle.write(_canonical_bytes(row) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception as exc:  # noqa: BLE001
            raise SemanticVerticalError("probe sink write failed (fail-closed)") from exc
        self._head = event_hash
        self._events.append(event)

    def finalize(
        self,
        *,
        runtime_roots: Iterable[str],
        artifact_bindings: Dict[str, str],
        mode: str,
        provider_calls_total: int,
    ) -> Dict[str, Any]:
        if self._terminal_attempted:
            raise SemanticVerticalError("probe terminal court is one-shot (fail-closed)")
        self._terminal_attempted = True
        if (self._root / "coverage.json").exists() or (self._root / "run_receipt.json").exists():
            raise SemanticVerticalError("probe terminal artifact collision (fail-closed)")
        if set(artifact_bindings) != REQUIRED_ARTIFACT_BINDINGS:
            raise SemanticVerticalError("terminal artifact binding denominator mismatch (fail-closed)")
        for name, value in artifact_bindings.items():
            if (
                not isinstance(name, str)
                or not name
                or not isinstance(value, str)
                or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)
            ):
                raise SemanticVerticalError("terminal artifact binding invalid (fail-closed)")
        roots = list(runtime_roots)
        if len(roots) != 13 or set(roots) != set(ROOT_CLASSIFICATIONS):
            raise SemanticVerticalError("runtime organ denominator mismatch (fail-closed)")
        if mode != "OFFLINE_PROOF" or type(provider_calls_total) is not int or provider_calls_total != 0:
            raise SemanticVerticalError("offline run receipt cannot bind live provider effects (fail-closed)")
        if artifact_bindings["semantic_request_id"] != self._request_id:
            raise SemanticVerticalError("run receipt request binding mismatch (fail-closed)")
        if artifact_bindings["execution_id"] != self._execution_id:
            raise SemanticVerticalError("run receipt execution binding mismatch (fail-closed)")
        if not self._enabled:
            receipt = {
                "schema_id": "kt.prb.semantic_run_receipt.v1",
                "request_id": self._request_id,
                "execution_id": self._execution_id,
                "proof_status": "FUNCTIONAL_ONLY_NO_PROBE_CLAIM",
                "mode": mode,
                "provider_calls_total": provider_calls_total,
                "artifact_bindings": dict(sorted(artifact_bindings.items())),
                "claim_ceiling": "FUNCTIONAL_ONLY_NO_PROBE_CLAIM",
                "run_receipt_hash": "",
            }
            receipt["run_receipt_hash"] = _sha256_bytes(
                _canonical_bytes({key: value for key, value in receipt.items() if key != "run_receipt_hash"})
            )
            _atomic_write(
                self._root / "run_receipt.json",
                _canonical_bytes(receipt),
                identity=self._execution_id + ".run",
            )
            return receipt
        if self._events != PROBE_CONTRACT["required_events"]:
            raise SemanticVerticalError("probe event denominator/order mismatch (fail-closed)")
        assert self._path is not None
        previous = "GENESIS"
        replayed: list[str] = []
        observed_by_root: Dict[str, list[str]] = {}
        for expected_sequence, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), start=1):
            row = json.loads(line)
            event_hash = row.pop("event_hash", None)
            if row.get("sequence") != expected_sequence or row.get("previous_event_hash") != previous:
                raise SemanticVerticalError("probe ledger chain/order invalid (fail-closed)")
            if event_hash != _sha256_bytes(_canonical_bytes(row)):
                raise SemanticVerticalError("probe ledger hash invalid (fail-closed)")
            event = str(row.get("event"))
            organ_root = str(row.get("organ_root"))
            if (
                row.get("request_id") != self._request_id
                or row.get("execution_id") != self._execution_id
                or row.get("probe_contract_hash") != PROBE_CONTRACT_HASH
                or EVENT_ROOTS.get(event) != organ_root
                or row.get("identity_hash") != artifact_bindings[EVENT_BINDING_KEYS[event]]
            ):
                raise SemanticVerticalError("probe replay binding invalid (fail-closed)")
            previous = event_hash
            replayed.append(event)
            observed_by_root.setdefault(organ_root, []).append(event)
        if replayed != PROBE_CONTRACT["required_events"]:
            raise SemanticVerticalError("probe replay denominator mismatch (fail-closed)")

        observed_roots = set(observed_by_root)
        missing_required = sorted(REQUIRED_CORRELATED_ROOTS - observed_roots)
        unexpected_correlated = sorted(EXPECTED_NO_CORRELATED_EVENT_ROOTS & observed_roots)
        unknown_correlated = sorted(observed_roots - set(ROOT_CLASSIFICATIONS))

        coverage = {
            "schema_id": "kt.prb.semantic_coverage.v1",
            "probe_contract_hash": PROBE_CONTRACT_HASH,
            "request_id": self._request_id,
            "execution_id": self._execution_id,
            "ledger_head": previous,
            "event_count": len(replayed),
            "root_denominator": 13,
            "roots": [
                {
                    "root_id": root,
                    "classification": ROOT_CLASSIFICATIONS[root],
                    "correlated_events": observed_by_root.get(root, []),
                }
                for root in sorted(ROOT_CLASSIFICATIONS)
            ],
            "applicability": {
                "required": [
                    "Entry Point",
                    "Spine",
                    "Schemas / Contracts",
                    "Thermodynamics / Budget",
                    "Council Router Engine",
                    "Governance Kernel",
                    "Receipts / Ledger",
                ],
                "expected_no_correlated_event": [
                    "Crucible Engine",
                    "Curriculum Boundary",
                    "Multiverse Engine",
                    "Paradox Engine",
                    "Temporal Engine",
                ],
            },
            "missing_required": missing_required,
            "unexpected_correlated": unexpected_correlated,
            "unknown_correlated": unknown_correlated,
            "observation_ceiling": COVERAGE_OBSERVATION_CEILING,
            "import_presence_is_not_firing": True,
            "claim_ceiling": RUN_CLAIM_CEILING,
            "coverage_hash": "",
        }
        coverage["coverage_hash"] = _sha256_bytes(
            _canonical_bytes({key: value for key, value in coverage.items() if key != "coverage_hash"})
        )
        _atomic_write(
            self._root / "coverage.json",
            _canonical_bytes(coverage),
            identity=self._execution_id + ".coverage",
        )
        if missing_required or unexpected_correlated or unknown_correlated:
            raise SemanticVerticalError("semantic correlated coverage court failed (fail-closed)")

        receipt = {
            "schema_id": "kt.prb.semantic_run_receipt.v1",
            "request_id": self._request_id,
            "execution_id": self._execution_id,
            "proof_status": RUN_PROOF_STATUS,
            "mode": mode,
            "provider_calls_total": provider_calls_total,
            "probe_contract_hash": PROBE_CONTRACT_HASH,
            "ledger_head": previous,
            "event_count": len(replayed),
            "coverage_hash": coverage["coverage_hash"],
            "artifact_bindings": dict(sorted(artifact_bindings.items())),
            "claim_ceiling": RUN_CLAIM_CEILING,
            "run_receipt_hash": "",
        }
        receipt["run_receipt_hash"] = _sha256_bytes(
            _canonical_bytes({key: value for key, value in receipt.items() if key != "run_receipt_hash"})
        )
        _atomic_write(
            self._root / "run_receipt.json",
            _canonical_bytes(receipt),
            identity=self._execution_id + ".run",
        )
        return receipt


def write_semantic_transcript(
    *,
    artifact_root: Path,
    execution_id: str,
    occurrence_hash: str,
    request: Dict[str, Any],
    receipt: Dict[str, Any],
    message: Dict[str, Any],
    admitted: Dict[str, Any],
    raw_response: bytes,
) -> str:
    root = _safe_root(artifact_root)
    request_id = request["request_id"]
    transcript_path = root / "transcript.json"
    if transcript_path.exists():
        raise SemanticVerticalError("semantic transcript collision/reuse (fail-closed)")
    if receipt.get("trace_id") != execution_id or message.get("request_id") != execution_id:
        raise SemanticVerticalError("semantic transcript execution binding mismatch (fail-closed)")
    if admitted.get("request_id") != execution_id:
        raise SemanticVerticalError("admitted meaning execution binding mismatch (fail-closed)")
    transcript: Dict[str, Any] = {
        "schema_id": "kt.prb.semantic_transcript.v1",
        "request_id": request_id,
        "execution_id": execution_id,
        "occurrence_hash": occurrence_hash,
        "subject_hash": request["subject_hash"],
        "request": request,
        "raw_response_b64": base64.b64encode(raw_response).decode("ascii"),
        "raw_response_hash": _sha256_bytes(raw_response),
        "raw_response_bytes": len(raw_response),
        "provider_receipt": receipt,
        "typed_message": message,
        "admitted_meaning": admitted,
        "output_identities": {
            "raw": _sha256_bytes(raw_response),
            "preserved": _sha256_bytes(raw_response),
            "delivered": message["message_hash"],
            "scored": admitted["meaning_hash"],
            "consumed": admitted["decision_hash"],
            "claimed": "PENDING_EFFECT_AND_ROLLBACK",
        },
        "training_authority": "NONE_QUARANTINED_CANDIDATE_ONLY",
        "transcript_hash": "",
    }
    transcript["transcript_hash"] = _sha256_bytes(
        _canonical_bytes({key: value for key, value in transcript.items() if key != "transcript_hash"})
    )
    _atomic_write(transcript_path, _canonical_bytes(transcript), identity=execution_id + ".transcript")
    return str(transcript["transcript_hash"])


def write_semantic_result_evidence(
    *,
    artifact_root: Path,
    request_id: str,
    execution_id: str,
    occurrence_hash: str,
    plan_hash: str,
    transcript_hash: str,
    raw_response_hash: str,
    message_hash: str,
    meaning_hash: str,
    decision_hash: str,
    effect: Dict[str, Any],
) -> str:
    root = _safe_root(artifact_root)
    path = root / "result.json"
    result: Dict[str, Any] = {
        "schema_id": "kt.prb.semantic_result_evidence.v1",
        "request_id": request_id,
        "execution_id": execution_id,
        "occurrence_hash": occurrence_hash,
        "plan_hash": plan_hash,
        "transcript_hash": transcript_hash,
        "raw_response_hash": raw_response_hash,
        "message_hash": message_hash,
        "meaning_hash": meaning_hash,
        "decision_hash": decision_hash,
        "effect_id": effect["effect_id"],
        "effect_receipt_hash": effect["receipt_hash"],
        "rollback_receipt_hash": effect["rollback_receipt_hash"],
        "effect_journal_hash": effect["journal_hash"],
        "pre_state_hash": effect["pre_state_hash"],
        "post_state_hash": effect["post_state_hash"],
        "restored_state_hash": effect["restored_state_hash"],
        "rollback_status": effect["rollback_status"],
        "proof_status": RESULT_PROOF_STATUS,
        "training_authority": "NONE",
        "result_hash": "",
    }
    result["result_hash"] = _sha256_bytes(
        _canonical_bytes({key: value for key, value in result.items() if key != "result_hash"})
    )
    if path.exists():
        raise SemanticVerticalError("semantic result evidence collision/reuse (fail-closed)")
    _atomic_write(path, _canonical_bytes(result), identity=execution_id + ".result")
    return str(result["result_hash"])


def write_terminal_evidence(
    *,
    artifact_root: Path,
    request_id: str,
    execution_id: str,
    occurrence_hash: str,
    primary_bindings: Dict[str, str],
    routing_record: Dict[str, Any],
    adapter_invocation: Dict[str, Any],
    governance_record: Dict[str, Any],
) -> str:
    root = _safe_root(artifact_root)
    path = root / "terminal_evidence.json"
    if path.exists():
        raise SemanticVerticalError("terminal evidence collision/reuse (fail-closed)")
    for value in primary_bindings.values():
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise SemanticVerticalError("terminal primary binding invalid (fail-closed)")
    terminal: Dict[str, Any] = {
        "schema_id": "kt.prb.semantic_terminal_evidence.v1",
        "request_id": request_id,
        "execution_id": execution_id,
        "occurrence_hash": occurrence_hash,
        "primary_bindings": dict(sorted(primary_bindings.items())),
        "routing_record": routing_record,
        "adapter_invocation": adapter_invocation,
        "governance_record": governance_record,
        "semantic_truth_ceiling": TERMINAL_SEMANTIC_TRUTH_CEILING,
        "durability_ceiling": TERMINAL_DURABILITY_CEILING,
        "filesystem_ceiling": TERMINAL_FILESYSTEM_CEILING,
        "terminal_evidence_hash": "",
    }
    terminal["terminal_evidence_hash"] = _sha256_bytes(
        _canonical_bytes({key: value for key, value in terminal.items() if key != "terminal_evidence_hash"})
    )
    _atomic_write(path, _canonical_bytes(terminal), identity=execution_id + ".terminal")
    return str(terminal["terminal_evidence_hash"])


def _strict_json_loads(text: str, *, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> Dict[str, object]:
        value: Dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise SemanticVerticalError(f"duplicate {label} JSON key (fail-closed)")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise SemanticVerticalError(f"non-finite {label} JSON constant {value} (fail-closed)")

    try:
        return json.loads(text, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except SemanticVerticalError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError(f"{label} JSON parse failed (fail-closed)") from exc


def _strict_artifact_json(path: Path) -> Dict[str, Any]:
    try:
        _assert_no_symlink_path(path)
        if path.stat().st_size > MAX_EVIDENCE_REPLAY_BYTES:
            raise SemanticVerticalError("semantic artifact exceeds verifier ceiling (fail-closed)")
        text = path.read_text(encoding="utf-8")
        payload = _strict_json_loads(text, label="artifact")
    except SemanticVerticalError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("semantic artifact parse failed (fail-closed)") from exc
    if not isinstance(payload, dict):
        raise SemanticVerticalError("semantic artifact must be object (fail-closed)")
    return payload


def _verify_self_hash(path: Path, *, hash_field: str) -> Dict[str, Any]:
    payload = _strict_artifact_json(path)
    expected = payload.get(hash_field)
    actual = _sha256_bytes(_canonical_bytes({key: value for key, value in payload.items() if key != hash_field}))
    if expected != actual:
        raise SemanticVerticalError(f"semantic artifact {hash_field} mismatch (fail-closed)")
    return payload


def _require_exact_keys(payload: Dict[str, Any], expected: set[str], *, label: str) -> None:
    if set(payload) != expected:
        raise SemanticVerticalError(f"{label} key denominator mismatch (fail-closed)")


def _require_hex64(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise SemanticVerticalError(f"{label} must be 64 lowercase hex (fail-closed)")
    return value


def verify_semantic_run(*, run_artifact_root: Path, expected_run_receipt_hash: str) -> Dict[str, Any]:
    """Verify one artifact-local offline chain against current source and an external digest.

    Repository head/tree and the truth of the detached subject remain authority-wrapper
    obligations; this verifier proves the frozen causal plumbing and claim ceilings only.
    """

    expected_hash = _require_hex64(expected_run_receipt_hash, label="expected run receipt hash")

    if not run_artifact_root.is_absolute():
        raise SemanticVerticalError("semantic verifier run root must be absolute (fail-closed)")
    _assert_no_symlink_path(run_artifact_root)
    try:
        run_root = run_artifact_root.resolve(strict=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("semantic verifier run root missing (fail-closed)") from exc
    semantic_root = run_root / "semantic_vertical"
    _assert_no_symlink_path(semantic_root)
    if not semantic_root.is_dir():
        raise SemanticVerticalError("semantic verifier evidence root missing (fail-closed)")

    run_receipt = _verify_self_hash(semantic_root / "run_receipt.json", hash_field="run_receipt_hash")
    _require_exact_keys(
        run_receipt,
        {
            "schema_id",
            "request_id",
            "execution_id",
            "proof_status",
            "mode",
            "provider_calls_total",
            "probe_contract_hash",
            "ledger_head",
            "event_count",
            "coverage_hash",
            "artifact_bindings",
            "claim_ceiling",
            "run_receipt_hash",
        },
        label="run receipt",
    )
    if (
        run_receipt.get("schema_id") != "kt.prb.semantic_run_receipt.v1"
        or run_receipt.get("run_receipt_hash") != expected_hash
        or run_receipt.get("proof_status") != RUN_PROOF_STATUS
        or run_receipt.get("mode") != "OFFLINE_PROOF"
        or type(run_receipt.get("provider_calls_total")) is not int
        or run_receipt.get("provider_calls_total") != 0
        or type(run_receipt.get("event_count")) is not int
        or run_receipt.get("probe_contract_hash") != PROBE_CONTRACT_HASH
        or run_receipt.get("claim_ceiling") != RUN_CLAIM_CEILING
    ):
        raise SemanticVerticalError("semantic run authority/status/ceiling mismatch (fail-closed)")
    bindings = run_receipt.get("artifact_bindings")
    if not isinstance(bindings, dict) or set(bindings) != REQUIRED_ARTIFACT_BINDINGS:
        raise SemanticVerticalError("semantic run binding denominator mismatch (fail-closed)")
    request_id = run_receipt.get("request_id")
    execution_id = run_receipt.get("execution_id")
    _require_hex64(request_id, label="semantic request id")
    _require_hex64(execution_id, label="semantic execution id")
    if bindings.get("semantic_request_id") != request_id or bindings.get("execution_id") != execution_id:
        raise SemanticVerticalError("semantic run identity mismatch (fail-closed)")

    terminal = _verify_self_hash(semantic_root / "terminal_evidence.json", hash_field="terminal_evidence_hash")
    coverage = _verify_self_hash(semantic_root / "coverage.json", hash_field="coverage_hash")
    transcript = _verify_self_hash(semantic_root / "transcript.json", hash_field="transcript_hash")
    result = _verify_self_hash(semantic_root / "result.json", hash_field="result_hash")
    _require_exact_keys(
        terminal,
        {
            "schema_id",
            "request_id",
            "execution_id",
            "occurrence_hash",
            "primary_bindings",
            "routing_record",
            "adapter_invocation",
            "governance_record",
            "semantic_truth_ceiling",
            "durability_ceiling",
            "filesystem_ceiling",
            "terminal_evidence_hash",
        },
        label="terminal evidence",
    )
    _require_exact_keys(
        coverage,
        {
            "schema_id",
            "probe_contract_hash",
            "request_id",
            "execution_id",
            "ledger_head",
            "event_count",
            "root_denominator",
            "roots",
            "applicability",
            "missing_required",
            "unexpected_correlated",
            "unknown_correlated",
            "observation_ceiling",
            "import_presence_is_not_firing",
            "claim_ceiling",
            "coverage_hash",
        },
        label="coverage",
    )
    _require_exact_keys(
        transcript,
        {
            "schema_id",
            "request_id",
            "execution_id",
            "occurrence_hash",
            "subject_hash",
            "request",
            "raw_response_b64",
            "raw_response_hash",
            "raw_response_bytes",
            "provider_receipt",
            "typed_message",
            "admitted_meaning",
            "output_identities",
            "training_authority",
            "transcript_hash",
        },
        label="transcript",
    )
    _require_exact_keys(
        result,
        {
            "schema_id",
            "request_id",
            "execution_id",
            "occurrence_hash",
            "plan_hash",
            "transcript_hash",
            "raw_response_hash",
            "message_hash",
            "meaning_hash",
            "decision_hash",
            "effect_id",
            "effect_receipt_hash",
            "rollback_receipt_hash",
            "effect_journal_hash",
            "pre_state_hash",
            "post_state_hash",
            "restored_state_hash",
            "rollback_status",
            "proof_status",
            "training_authority",
            "result_hash",
        },
        label="result evidence",
    )
    if (
        terminal.get("schema_id") != "kt.prb.semantic_terminal_evidence.v1"
        or terminal.get("request_id") != request_id
        or terminal.get("execution_id") != execution_id
        or terminal.get("semantic_truth_ceiling") != TERMINAL_SEMANTIC_TRUTH_CEILING
        or terminal.get("durability_ceiling") != TERMINAL_DURABILITY_CEILING
        or terminal.get("filesystem_ceiling") != TERMINAL_FILESYSTEM_CEILING
        or coverage.get("schema_id") != "kt.prb.semantic_coverage.v1"
        or coverage.get("request_id") != request_id
        or coverage.get("execution_id") != execution_id
        or coverage.get("probe_contract_hash") != PROBE_CONTRACT_HASH
        or coverage.get("observation_ceiling") != COVERAGE_OBSERVATION_CEILING
        or coverage.get("claim_ceiling") != RUN_CLAIM_CEILING
        or coverage.get("import_presence_is_not_firing") is not True
        or type(coverage.get("event_count")) is not int
        or type(coverage.get("root_denominator")) is not int
        or transcript.get("schema_id") != "kt.prb.semantic_transcript.v1"
        or transcript.get("request_id") != request_id
        or transcript.get("execution_id") != execution_id
        or transcript.get("training_authority") != "NONE_QUARANTINED_CANDIDATE_ONLY"
        or result.get("schema_id") != "kt.prb.semantic_result_evidence.v1"
        or result.get("request_id") != request_id
        or result.get("execution_id") != execution_id
        or result.get("proof_status") != RESULT_PROOF_STATUS
        or result.get("training_authority") != "NONE"
        or result.get("rollback_status") != "RESTORED"
    ):
        raise SemanticVerticalError("terminal artifact status/ceiling mismatch (fail-closed)")
    if terminal["terminal_evidence_hash"] != bindings["terminal_evidence_hash"]:
        raise SemanticVerticalError("terminal evidence binding mismatch (fail-closed)")
    if coverage["coverage_hash"] != run_receipt.get("coverage_hash"):
        raise SemanticVerticalError("coverage/run receipt binding mismatch (fail-closed)")
    if transcript["transcript_hash"] != bindings["transcript_hash"]:
        raise SemanticVerticalError("transcript binding mismatch (fail-closed)")
    if result["result_hash"] != bindings["result_hash"]:
        raise SemanticVerticalError("result binding mismatch (fail-closed)")

    request = transcript.get("request")
    if not isinstance(request, dict) or request.get("request_id") != request_id:
        raise SemanticVerticalError("transcript request binding missing (fail-closed)")
    from core.runtime_registry import load_runtime_registry  # noqa: PLC0415
    from core.spine import _runtime_registry_hash  # noqa: PLC0415
    from council.semantic_router import SemanticCouncilRouter  # noqa: PLC0415
    from schemas.semantic_vertical_schemas import SemanticCouncilRequestSchema  # noqa: PLC0415

    try:
        request_schema = SemanticCouncilRequestSchema.from_dict(request)
        registry = load_runtime_registry()
        registry_hash = _runtime_registry_hash(registry)
        replayed_plan = SemanticCouncilRouter.plan(request=request_schema, runtime_registry=registry)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("request/registry/plan replay failed (fail-closed)") from exc
    if (
        request.get("probe_enabled") is not True
        or request.get("mode") != "OFFLINE_PROOF"
        or request.get("runtime_registry_hash") != registry_hash
        or registry_hash != bindings["runtime_registry_hash"]
        or replayed_plan.plan_hash != bindings["plan_hash"]
        or replayed_plan.manifest_hash != bindings["manifest_hash"]
        or replayed_plan.prompt_hash != bindings["prompt_hash"]
    ):
        raise SemanticVerticalError("request/registry/plan binding mismatch (fail-closed)")
    if _sha256_bytes(_canonical_bytes(request.get("subject"))) != request.get("subject_hash"):
        raise SemanticVerticalError("transcript subject hash mismatch (fail-closed)")
    if request.get("subject_hash") != bindings["subject_hash"]:
        raise SemanticVerticalError("terminal subject binding mismatch (fail-closed)")
    expected_entry_attestation = _sha256_bytes(
        _canonical_bytes(
            {
                "schema_id": "kt.prb.canonical_entry_attestation.v1",
                "entry": "kt.entrypoint.invoke",
                "context_hash": bindings["context_hash"],
                "execution_id": execution_id,
            }
        )
    )
    expected_occurrence = _sha256_bytes(
        _canonical_bytes(
            {
                "schema_id": "kt.prb.semantic_occurrence.v1",
                "entry_attestation_hash": expected_entry_attestation,
                "context_hash": bindings["context_hash"],
                "semantic_request_id": request_id,
                "execution_id": execution_id,
            }
        )
    )
    if (
        expected_entry_attestation != bindings["entry_attestation_hash"]
        or expected_occurrence != bindings["occurrence_hash"]
        or transcript.get("occurrence_hash") != expected_occurrence
        or terminal.get("occurrence_hash") != expected_occurrence
        or result.get("occurrence_hash") != expected_occurrence
    ):
        raise SemanticVerticalError("canonical entry/occurrence replay mismatch (fail-closed)")
    try:
        raw_response = base64.b64decode(transcript["raw_response_b64"], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("transcript raw response encoding invalid (fail-closed)") from exc
    if (
        len(raw_response) != transcript.get("raw_response_bytes")
        or _sha256_bytes(raw_response) != transcript.get("raw_response_hash")
        or transcript.get("raw_response_hash") != bindings["raw_response_hash"]
    ):
        raise SemanticVerticalError("transcript raw response identity mismatch (fail-closed)")

    provider_receipt = transcript.get("provider_receipt")
    typed_message = transcript.get("typed_message")
    admitted = transcript.get("admitted_meaning")
    if not all(isinstance(value, dict) for value in (provider_receipt, typed_message, admitted)):
        raise SemanticVerticalError("transcript compound evidence missing (fail-closed)")
    receipt_payload = {
        key: value for key, value in provider_receipt.items() if key not in {"receipt_id", "receipt_hash"}
    }
    provider_receipt_hash = _sha256_bytes(_canonical_bytes(receipt_payload))
    if (
        provider_receipt.get("receipt_id") != provider_receipt_hash
        or provider_receipt.get("receipt_hash") != provider_receipt_hash
        or provider_receipt_hash != bindings["provider_receipt_hash"]
    ):
        raise SemanticVerticalError("provider receipt replay mismatch (fail-closed)")
    from council.providers.provider_schemas import ProviderCallReceipt  # noqa: PLC0415
    from council.providers.semantic_response import (  # noqa: PLC0415
        admit_typed_message,
        typed_message_from_provider_response,
    )
    from council.semantic_router import _prompt_for_request, _verify_compound_result  # noqa: PLC0415

    try:
        receipt_schema = ProviderCallReceipt.from_dict(provider_receipt)
        replayed_message_schema = typed_message_from_provider_response(
            raw=raw_response,
            expected_model=request["model"],
            provider_id=request["provider_id"],
            request_id=execution_id,
        )
        replayed_message = replayed_message_schema.to_dict()
        replayed_admitted_schema = admit_typed_message(
            message=replayed_message_schema,
            expected_subject_hash=request["subject_hash"],
            expected_nonce=request["nonce"],
        )
        replayed_admitted = replayed_admitted_schema.to_dict()
        _verify_compound_result(
            request=request,
            execution_id=execution_id,
            receipt=receipt_schema,
            message=replayed_message_schema,
            raw_response=raw_response,
            offline=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("raw/typed/admitted compound replay failed (fail-closed)") from exc
    if replayed_message != typed_message or replayed_admitted != admitted:
        raise SemanticVerticalError("raw/typed/admitted artifact splice detected (fail-closed)")
    timing = provider_receipt.get("timing")
    transport = provider_receipt.get("transport")
    provider_attestation = provider_receipt.get("provider_attestation")
    provider_payload = provider_receipt.get("payload")
    if not all(isinstance(value, dict) for value in (timing, transport, provider_attestation, provider_payload)):
        raise SemanticVerticalError("offline provider compound fields missing (fail-closed)")
    _require_exact_keys(timing, {"t_start_ms", "t_end_ms", "latency_ms"}, label="provider timing")
    _require_exact_keys(
        transport,
        {"host", "http_status", "tls_cert_sha256", "remote_ip_hash"},
        label="provider transport",
    )
    _require_exact_keys(
        provider_attestation,
        {"request_id", "request_id_hash", "response_id_hash"},
        label="provider attestation",
    )
    _require_exact_keys(
        provider_payload,
        {"response_bytes_sha256", "response_bytes_len", "prompt_sha256", "content_sha256", "message_hash"},
        label="provider payload",
    )
    if (
        provider_receipt.get("lane") != "OFFLINE_PROOF"
        or provider_receipt.get("endpoint") != "chat.completions"
        or provider_receipt.get("key_index") != 0
        or provider_receipt.get("key_count") != 1
        or transport.get("host") != "offline.fixture"
        or transport.get("http_status") != 200
        or transport.get("tls_cert_sha256") != _sha256_bytes(b"offline-proof-fixture")
        or transport.get("remote_ip_hash") is not None
        or provider_attestation.get("request_id") is not None
        or provider_attestation.get("request_id_hash") is not None
        or timing.get("t_end_ms", -1) < timing.get("t_start_ms", 0)
        or timing.get("latency_ms") != timing.get("t_end_ms") - timing.get("t_start_ms")
    ):
        raise SemanticVerticalError("provider receipt is not the frozen offline transport (fail-closed)")
    if (
        typed_message.get("request_id") != execution_id
        or admitted.get("request_id") != execution_id
        or typed_message.get("raw_response_hash") != bindings["raw_response_hash"]
        or typed_message.get("message_hash") != bindings["message_hash"]
        or admitted.get("meaning_hash") != bindings["meaning_hash"]
        or admitted.get("decision_hash") != bindings["decision_hash"]
    ):
        raise SemanticVerticalError("typed/admitted identity mismatch (fail-closed)")
    prompt_hash = _sha256_bytes(_prompt_for_request(request).encode("utf-8"))
    if (
        prompt_hash != bindings["prompt_hash"]
        or provider_receipt.get("payload", {}).get("prompt_sha256") != "sha256:" + prompt_hash
    ):
        raise SemanticVerticalError("prompt grounding replay mismatch (fail-closed)")
    expected_output_identities = {
        "raw": bindings["raw_response_hash"],
        "preserved": bindings["raw_response_hash"],
        "delivered": bindings["message_hash"],
        "scored": bindings["meaning_hash"],
        "consumed": bindings["decision_hash"],
        "claimed": "PENDING_EFFECT_AND_ROLLBACK",
    }
    if transcript.get("output_identities") != expected_output_identities:
        raise SemanticVerticalError("transcript output identity partition mismatch (fail-closed)")

    effect_id = bindings["effect_id"]
    effect_receipt = _verify_self_hash(
        semantic_root / "effect_receipts" / f"{effect_id}.json",
        hash_field="receipt_hash",
    )
    rollback_receipt = _verify_self_hash(
        semantic_root / "rollback_receipts" / f"{effect_id}.json",
        hash_field="rollback_receipt_hash",
    )
    journal = _verify_self_hash(
        semantic_root / f"effect_journal.{effect_id}.json",
        hash_field="journal_hash",
    )
    _require_exact_keys(
        effect_receipt,
        {
            "schema_id",
            "consumer_id",
            "semantic_request_id",
            "execution_id",
            "meaning_hash",
            "decision_hash",
            "effect_id",
            "effect_status",
            "semantic_effects_applied",
            "pre_state_hash",
            "post_state_hash",
            "restored_state_hash",
            "rollback_status",
            "rollback_receipt_hash",
            "target_id",
            "durability_ceiling",
            "receipt_hash",
        },
        label="effect receipt",
    )
    _require_exact_keys(
        rollback_receipt,
        {
            "schema_id",
            "semantic_request_id",
            "execution_id",
            "effect_id",
            "pre_state_hash",
            "post_state_hash",
            "restored_state_hash",
            "rollback_status",
            "restored_journal_hash",
            "rollback_receipt_hash",
        },
        label="rollback receipt",
    )
    _require_exact_keys(
        journal,
        {
            "schema_id",
            "execution_id",
            "semantic_request_id",
            "effect_id",
            "phase",
            "pre_state_hash",
            "post_state_hash",
            "restored_state_hash",
            "rollback_receipt_hash",
            "effect_receipt_hash",
            "journal_hash",
        },
        label="effect journal",
    )
    from memory.semantic_effect import CONSUMER_ID  # noqa: PLC0415

    expected_effect_id = _sha256_bytes(
        _canonical_bytes(
            {
                "consumer_id": CONSUMER_ID,
                "semantic_request_id": request_id,
                "decision_hash": admitted["decision_hash"],
                "target_id": "semantic_vertical/advisory_state.json",
            }
        )
    )
    expected_state = {
        "schema_id": "kt.semantic_advisory_state.v1",
        "consumer_id": CONSUMER_ID,
        "semantic_request_id": request_id,
        "subject_hash": admitted["subject_hash"],
        "decision": admitted["decision"],
        "reason_code": admitted["reason_code"],
        "decision_hash": admitted["decision_hash"],
        "meaning_hash": admitted["meaning_hash"],
        "effect_id": expected_effect_id,
    }
    expected_pre_state_hash = _sha256_bytes(
        _canonical_bytes({"present": False, "bytes_sha256": "0" * 64})
    )
    expected_post_state_hash = _sha256_bytes(
        _canonical_bytes(
            {
                "present": True,
                "bytes_sha256": _sha256_bytes(_canonical_bytes(expected_state)),
            }
        )
    )
    advisory_state_path = semantic_root / "advisory_state.json"
    _assert_no_symlink_path(advisory_state_path)
    if advisory_state_path.exists() or is_link_or_reparse_point(advisory_state_path):
        raise SemanticVerticalError("semantic state remains applied after claimed rollback (fail-closed)")
    if (
        effect_id != expected_effect_id
        or effect_receipt.get("schema_id") != "kt.semantic_effect_receipt.v1"
        or effect_receipt.get("consumer_id") != CONSUMER_ID
        or effect_receipt.get("semantic_request_id") != request_id
        or effect_receipt.get("execution_id") != execution_id
        or effect_receipt.get("meaning_hash") != admitted["meaning_hash"]
        or effect_receipt.get("decision_hash") != admitted["decision_hash"]
        or effect_receipt.get("effect_id") != expected_effect_id
        or effect_receipt.get("effect_status") != EFFECT_STATUS
        or type(effect_receipt.get("semantic_effects_applied")) is not int
        or effect_receipt.get("semantic_effects_applied") != 1
        or effect_receipt.get("pre_state_hash") != expected_pre_state_hash
        or effect_receipt.get("post_state_hash") != expected_post_state_hash
        or effect_receipt.get("restored_state_hash") != expected_pre_state_hash
        or effect_receipt.get("target_id") != "semantic_vertical/advisory_state.json"
        or effect_receipt.get("durability_ceiling") != EFFECT_DURABILITY_CEILING
        or effect_receipt.get("receipt_hash") != bindings["effect_receipt_hash"]
        or rollback_receipt.get("rollback_receipt_hash") != bindings["rollback_receipt_hash"]
        or rollback_receipt.get("schema_id") != "kt.semantic_rollback_receipt.v1"
        or rollback_receipt.get("semantic_request_id") != request_id
        or rollback_receipt.get("execution_id") != execution_id
        or rollback_receipt.get("effect_id") != expected_effect_id
        or rollback_receipt.get("pre_state_hash") != expected_pre_state_hash
        or rollback_receipt.get("post_state_hash") != expected_post_state_hash
        or rollback_receipt.get("restored_state_hash") != expected_pre_state_hash
        or rollback_receipt.get("rollback_status") != "RESTORED"
        or effect_receipt.get("rollback_receipt_hash") != rollback_receipt.get("rollback_receipt_hash")
        or journal.get("schema_id") != "kt.semantic_effect_journal.v1"
        or journal.get("execution_id") != execution_id
        or journal.get("semantic_request_id") != request_id
        or journal.get("effect_id") != expected_effect_id
        or journal.get("journal_hash") != bindings["effect_journal_hash"]
        or journal.get("phase") != "COMMITTED"
        or journal.get("pre_state_hash") != expected_pre_state_hash
        or journal.get("post_state_hash") != expected_post_state_hash
        or journal.get("restored_state_hash") != expected_pre_state_hash
        or journal.get("effect_receipt_hash") != effect_receipt.get("receipt_hash")
        or journal.get("rollback_receipt_hash") != rollback_receipt.get("rollback_receipt_hash")
        or effect_receipt.get("post_state_hash") != bindings["effect_post_state_hash"]
        or effect_receipt.get("restored_state_hash") != bindings["effect_restored_state_hash"]
        or effect_receipt.get("rollback_status") != "RESTORED"
    ):
        raise SemanticVerticalError("effect/rollback replay mismatch (fail-closed)")

    if (
        result.get("execution_id") != execution_id
        or result.get("occurrence_hash") != bindings["occurrence_hash"]
        or result.get("plan_hash") != bindings["plan_hash"]
        or result.get("transcript_hash") != bindings["transcript_hash"]
        or result.get("raw_response_hash") != bindings["raw_response_hash"]
        or result.get("message_hash") != bindings["message_hash"]
        or result.get("meaning_hash") != bindings["meaning_hash"]
        or result.get("decision_hash") != bindings["decision_hash"]
        or result.get("effect_id") != expected_effect_id
        or result.get("effect_receipt_hash") != bindings["effect_receipt_hash"]
        or result.get("rollback_receipt_hash") != bindings["rollback_receipt_hash"]
        or result.get("effect_journal_hash") != bindings["effect_journal_hash"]
        or result.get("pre_state_hash") != expected_pre_state_hash
        or result.get("post_state_hash") != expected_post_state_hash
        or result.get("restored_state_hash") != expected_pre_state_hash
    ):
        raise SemanticVerticalError("result evidence replay mismatch (fail-closed)")

    primary_bindings = terminal.get("primary_bindings")
    if not isinstance(primary_bindings, dict) or primary_bindings != {
        key: value for key, value in bindings.items() if key != "terminal_evidence_hash"
    }:
        raise SemanticVerticalError("terminal primary binding set mismatch (fail-closed)")
    routing_record = terminal.get("routing_record")
    invocation_record = terminal.get("adapter_invocation")
    governance_record = terminal.get("governance_record")
    if not all(isinstance(value, dict) for value in (routing_record, invocation_record, governance_record)):
        raise SemanticVerticalError("terminal linked records missing (fail-closed)")
    routing_hash = _sha256_bytes(
        _canonical_bytes({key: value for key, value in routing_record.items() if key not in {"created_at", "routing_record_id"}})
    )
    invocation_hash = _sha256_bytes(
        _canonical_bytes({key: value for key, value in invocation_record.items() if key not in {"created_at", "invocation_id"}})
    )
    from governance.events import (  # noqa: PLC0415
        build_inputs_envelope,
        build_outputs_envelope,
        compute_envelope_hash,
    )
    from schemas.schema_registry import validate_object_with_binding  # noqa: PLC0415
    from schemas.state_vault_schema import (  # noqa: PLC0415
        compute_event_hash,
        compute_payload_hash,
        validate_state_vault_record,
    )
    from versioning.constitution_registry import get_constitution_version_hash  # noqa: PLC0415

    try:
        validate_object_with_binding(routing_record)
        validate_object_with_binding(invocation_record)
        validate_state_vault_record(governance_record)
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("terminal linked record schema invalid (fail-closed)") from exc
    expected_candidates = [
        {
            "adapter_id": request["adapter_id"],
            "adapter_version": replayed_plan.manifest.version,
            "capabilities": ["offline_semantic_proof", "one_attempt", "strict_admission"],
            "estimated_risk": "MEDIUM",
        }
    ]
    expected_governor_verdict = {
        "policy": "PRB_SEMANTIC_OFFLINE_PREFLIGHT",
        "verdict": "ALLOW",
        "risk_score": 0.5,
        "verdict_hash": bindings["plan_hash"],
    }
    expected_inputs_hash = compute_envelope_hash(
        build_inputs_envelope(
            policy_id="p.v2.council.semantic.admission",
            policy_version_hash=admitted["parser_hash"],
            subject_hash=request["subject_hash"],
            context_hash=admitted["message_hash"],
            rule_id="r.v2.council.semantic.admission.v1",
        )
    )
    expected_outputs_hash = compute_envelope_hash(
        build_outputs_envelope(decision="ALLOW", obligations_hash=result["result_hash"])
    )
    governance_payload_fields = {
        key: governance_record[key]
        for key in ("inputs_hash", "outputs_hash", "energy_cost", "energy_source", "crisis_mode")
        if key in governance_record
    }
    expected_governance_payload_hash = compute_payload_hash(governance_payload_fields)
    expected_governance_event_hash = compute_event_hash(
        payload_hash=expected_governance_payload_hash,
        event_type=str(governance_record.get("event_type")),
        organ_id=str(governance_record.get("organ_id")),
        parent_hash=str(governance_record.get("parent_hash")),
        schema_version_hash=str(governance_record.get("schema_version_hash")),
        constitution_version_hash=str(governance_record.get("constitution_version_hash")),
    )
    expected_governance_receipt_id = _sha256_bytes(
        _canonical_bytes(
            {
                "created_at": governance_record.get("created_at"),
                "event_type": governance_record.get("event_type"),
                "organ_id": governance_record.get("organ_id"),
                "parent_hash": governance_record.get("parent_hash"),
                "constitution_version_hash": governance_record.get("constitution_version_hash"),
            }
        )
    )
    if (
        routing_hash != bindings["routing_record_hash"]
        or routing_record.get("routing_record_id") != routing_hash
        or routing_record.get("runtime_registry_hash") != bindings["runtime_registry_hash"]
        or routing_record.get("spine_run_hash") != bindings["occurrence_hash"]
        or routing_record.get("task_context_hash") != bindings["context_hash"]
        or routing_record.get("task_context_ref") != f"vault://context/{bindings['context_hash']}"
        or routing_record.get("request_hash") != request_id
        or routing_record.get("plan_hash") != bindings["plan_hash"]
        or routing_record.get("candidates") != expected_candidates
        or routing_record.get("chosen_adapter")
        != {"adapter_id": request["adapter_id"], "adapter_version": replayed_plan.manifest.version}
        or routing_record.get("router_reason") != "council.semantic.v1"
        or type(routing_record.get("router_confidence")) is not float
        or routing_record.get("router_confidence") != 1.0
        or routing_record.get("governor_verdict") != expected_governor_verdict
        or routing_record.get("parent_routing_record") is not None
        or routing_record.get("status") != "OK"
        or invocation_hash != bindings["adapter_invocation_id"]
        or invocation_record.get("invocation_id") != invocation_hash
        or invocation_record.get("routing_record_hash") != routing_hash
        or invocation_record.get("adapter_id") != request["adapter_id"]
        or invocation_record.get("adapter_version") != replayed_plan.manifest.version
        or invocation_record.get("task_context_hash") != bindings["context_hash"]
        or invocation_record.get("input_hash") != bindings["occurrence_hash"]
        or invocation_record.get("output_hash") != bindings["message_hash"]
        or invocation_record.get("governor_verdict_hash") != bindings["plan_hash"]
        or invocation_record.get("evaluator_verdict") != "PASS"
        or type(invocation_record.get("duration_ms")) is not int
        or invocation_record.get("duration_ms") != provider_receipt.get("timing", {}).get("latency_ms")
        or any(type(value) is not int for value in invocation_record.get("token_usage", {}).values())
        or invocation_record.get("token_usage")
        != {
            "prompt": typed_message["usage"]["prompt_tokens"],
            "completion": typed_message["usage"]["completion_tokens"],
            "total": typed_message["usage"]["total_tokens"],
        }
        or invocation_record.get("status") != "OK"
        or governance_record.get("event_hash") != bindings["governance_event_hash"]
        or type(governance_record.get("seq")) is not int
        or governance_record.get("event_type") != "GOV_POLICY_APPLY"
        or governance_record.get("organ_id") != "Governance"
        or governance_record.get("constitution_version_hash") != get_constitution_version_hash()
        or governance_record.get("inputs_hash") != expected_inputs_hash
        or governance_record.get("outputs_hash") != expected_outputs_hash
        or governance_record.get("payload_hash") != expected_governance_payload_hash
        or governance_record.get("event_hash") != expected_governance_event_hash
        or governance_record.get("receipt_id") != expected_governance_receipt_id
    ):
        raise SemanticVerticalError("routing/invocation/governance linkage mismatch (fail-closed)")

    ledger_path = semantic_root / "probe_ledger.jsonl"
    try:
        _assert_no_symlink_path(ledger_path)
        if ledger_path.stat().st_size > MAX_EVIDENCE_REPLAY_BYTES:
            raise SemanticVerticalError("probe ledger exceeds verifier ceiling (fail-closed)")
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except SemanticVerticalError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SemanticVerticalError("probe ledger replay failed (fail-closed)") from exc
    previous = "GENESIS"
    replayed_events: list[str] = []
    observed_by_root: Dict[str, list[str]] = {}
    for sequence, line in enumerate(lines, start=1):
        row = _strict_json_loads(line, label="probe ledger row")
        if not isinstance(row, dict):
            raise SemanticVerticalError("probe ledger row must be object (fail-closed)")
        _require_exact_keys(
            row,
            {
                "schema_id",
                "probe_contract_hash",
                "request_id",
                "execution_id",
                "sequence",
                "previous_event_hash",
                "event",
                "organ_root",
                "identity_hash",
                "event_hash",
            },
            label="probe ledger row",
        )
        event_hash = row.pop("event_hash", None)
        event = row.get("event")
        if event not in EVENT_ROOTS or event not in EVENT_BINDING_KEYS:
            raise SemanticVerticalError("unknown probe ledger event (fail-closed)")
        if (
            row.get("schema_id") != "kt.prb.semantic_probe_event.v1"
            or row.get("probe_contract_hash") != PROBE_CONTRACT_HASH
            or row.get("request_id") != request_id
            or type(row.get("sequence")) is not int
            or row.get("sequence") != sequence
            or row.get("previous_event_hash") != previous
            or row.get("execution_id") != execution_id
            or EVENT_ROOTS.get(event) != row.get("organ_root")
            or row.get("identity_hash") != bindings[EVENT_BINDING_KEYS[event]]
            or event_hash != _sha256_bytes(_canonical_bytes(row))
        ):
            raise SemanticVerticalError("probe ledger terminal replay mismatch (fail-closed)")
        previous = event_hash
        replayed_events.append(str(event))
        observed_by_root.setdefault(str(row["organ_root"]), []).append(str(event))
    observed_roots = set(observed_by_root)
    expected_missing = sorted(REQUIRED_CORRELATED_ROOTS - observed_roots)
    expected_unexpected = sorted(EXPECTED_NO_CORRELATED_EVENT_ROOTS & observed_roots)
    expected_unknown = sorted(observed_roots - set(ROOT_CLASSIFICATIONS))
    expected_roots = [
        {
            "root_id": root,
            "classification": ROOT_CLASSIFICATIONS[root],
            "correlated_events": observed_by_root.get(root, []),
        }
        for root in sorted(ROOT_CLASSIFICATIONS)
    ]
    expected_applicability = {
        "required": [
            "Entry Point",
            "Spine",
            "Schemas / Contracts",
            "Thermodynamics / Budget",
            "Council Router Engine",
            "Governance Kernel",
            "Receipts / Ledger",
        ],
        "expected_no_correlated_event": [
            "Crucible Engine",
            "Curriculum Boundary",
            "Multiverse Engine",
            "Paradox Engine",
            "Temporal Engine",
        ],
    }
    if (
        replayed_events != PROBE_CONTRACT["required_events"]
        or previous != run_receipt.get("ledger_head")
        or len(lines) != run_receipt.get("event_count")
        or coverage.get("ledger_head") != previous
        or coverage.get("event_count") != len(lines)
        or coverage.get("root_denominator") != 13
        or coverage.get("roots") != expected_roots
        or coverage.get("applicability") != expected_applicability
        or coverage.get("missing_required") != expected_missing
        or coverage.get("unexpected_correlated") != expected_unexpected
        or coverage.get("unknown_correlated") != expected_unknown
        or expected_missing
        or expected_unexpected
        or expected_unknown
    ):
        raise SemanticVerticalError("probe coverage closure mismatch (fail-closed)")
    return run_receipt


__all__ = [
    "PROBE_CONTRACT_HASH",
    "SemanticProbeRecorder",
    "write_semantic_result_evidence",
    "write_semantic_transcript",
    "write_terminal_evidence",
    "verify_semantic_run",
]
