from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


class CrucibleSchemaError(ValueError):
    pass


KERNEL_V2_SOVEREIGN = "V2_SOVEREIGN"
KERNEL_V1_ARCHIVAL = "V1_ARCHIVAL"
KERNEL_COVERAGE_BASELINE = "KERNEL_COVERAGE_BASELINE"
KERNEL_GOVERNANCE_BASELINE = "KERNEL_GOVERNANCE_BASELINE"
KERNEL_TARGETS_ALLOWED: Set[str] = {
    KERNEL_V2_SOVEREIGN,
    KERNEL_V1_ARCHIVAL,
    KERNEL_COVERAGE_BASELINE,
    KERNEL_GOVERNANCE_BASELINE,
}

INPUT_MODE_RAW = "RAW_INPUT_STRING"
INPUT_MODE_STRUCTURED = "STRUCTURED_PROMPT_JSON"
INPUT_MODES_ALLOWED: Set[str] = {INPUT_MODE_RAW, INPUT_MODE_STRUCTURED}

REDACTION_ALLOW_RAW = "ALLOW_RAW_IN_CRUCIBLE"
REDACTION_HASH_ONLY = "HASH_ONLY_CRUCIBLE"
REDACTION_POLICIES_ALLOWED: Set[str] = {REDACTION_ALLOW_RAW, REDACTION_HASH_ONLY}

OUTCOME_PASS = "PASS"
OUTCOME_REFUSE = "REFUSE"
OUTCOME_INFEASIBLE = "INFEASIBLE"
OUTCOME_FAIL = "FAIL"
OUTCOMES_ALLOWED: Set[str] = {OUTCOME_PASS, OUTCOME_REFUSE, OUTCOME_INFEASIBLE, OUTCOME_FAIL}

REPLAY_REQUIRED_PASS = "REQUIRED_PASS"
REPLAY_REQUIRED_FAIL = "REQUIRED_FAIL"
REPLAY_NOT_APPLICABLE = "NOT_APPLICABLE"
REPLAY_MODES_ALLOWED: Set[str] = {REPLAY_REQUIRED_PASS, REPLAY_REQUIRED_FAIL, REPLAY_NOT_APPLICABLE}

THERMO_WITHIN = "WITHIN_BUDGET"
THERMO_OVER = "OVER_BUDGET_HALT"
THERMO_NOT_ASSERTED = "BUDGET_NOT_ASSERTED"
THERMO_BUDGET_VERDICTS_ALLOWED: Set[str] = {THERMO_WITHIN, THERMO_OVER, THERMO_NOT_ASSERTED}


_CRUCIBLE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(obj: Any) -> str:
    return sha256_text(_canonical_json(obj))


def _require_dict(obj: Any, *, name: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise CrucibleSchemaError(f"{name} must be an object (fail-closed)")
    return obj


def _require_list(obj: Any, *, name: str) -> List[Any]:
    if not isinstance(obj, list):
        raise CrucibleSchemaError(f"{name} must be a list (fail-closed)")
    return obj


def _require_str(obj: Any, *, name: str, min_len: int = 0, max_len: int = 10_000) -> str:
    if not isinstance(obj, str):
        raise CrucibleSchemaError(f"{name} must be a string (fail-closed)")
    if len(obj) < min_len or len(obj) > max_len:
        raise CrucibleSchemaError(f"{name} length must be {min_len}..{max_len} (fail-closed)")
    return obj


def _require_int(obj: Any, *, name: str, lo: int, hi: int) -> int:
    if not isinstance(obj, int) or isinstance(obj, bool):
        raise CrucibleSchemaError(f"{name} must be an integer (fail-closed)")
    if obj < lo or obj > hi:
        raise CrucibleSchemaError(f"{name} must be in range {lo}..{hi} (fail-closed)")
    return obj


def _require_bool(obj: Any, *, name: str) -> bool:
    if not isinstance(obj, bool):
        raise CrucibleSchemaError(f"{name} must be a boolean (fail-closed)")
    return obj


def _reject_unknown_keys(payload: Mapping[str, Any], *, allowed: Set[str], name: str) -> None:
    extra = set(payload.keys()) - allowed
    if extra:
        raise CrucibleSchemaError(f"{name} has unknown keys (fail-closed): {sorted(extra)}")


def _require_keys(payload: Mapping[str, Any], *, required: Set[str], name: str) -> None:
    missing = required - set(payload.keys())
    if missing:
        raise CrucibleSchemaError(f"{name} missing required keys (fail-closed): {sorted(missing)}")


def _validate_hex64(value: str, *, name: str) -> None:
    if not _HEX64_RE.match(value):
        raise CrucibleSchemaError(f"{name} must be 64 lowercase hex chars (fail-closed)")


def _validate_enum(value: str, *, allowed: Set[str], name: str) -> None:
    if value not in allowed:
        raise CrucibleSchemaError(f"{name} must be one of {sorted(allowed)} (fail-closed)")


def _validate_str_list(
    values: Sequence[Any],
    *,
    name: str,
    min_items: int,
    max_items: int,
    item_min_len: int,
    item_max_len: int,
) -> List[str]:
    items = _require_list(values, name=name)
    if len(items) < min_items or len(items) > max_items:
        raise CrucibleSchemaError(f"{name} must have {min_items}..{max_items} items (fail-closed)")
    out: List[str] = []
    for i, raw in enumerate(items):
        out.append(_require_str(raw, name=f"{name}[{i}]", min_len=item_min_len, max_len=item_max_len))
    return out


@dataclass(frozen=True)
class CrucibleInput:
    mode: str
    prompt: str
    content_hash: Optional[str]
    redaction_policy: str

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleInput":
        payload = _require_dict(data, name="input")
        allowed = {"mode", "prompt", "content_hash", "redaction_policy"}
        required = {"mode", "prompt"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="input")
        _require_keys(payload, required=set(required), name="input")

        mode = _require_str(payload.get("mode"), name="input.mode", min_len=1, max_len=64)
        _validate_enum(mode, allowed=INPUT_MODES_ALLOWED, name="input.mode")

        redaction_policy = payload.get("redaction_policy", REDACTION_ALLOW_RAW)
        redaction_policy = _require_str(redaction_policy, name="input.redaction_policy", min_len=1, max_len=64)
        _validate_enum(redaction_policy, allowed=REDACTION_POLICIES_ALLOWED, name="input.redaction_policy")

        prompt = _require_str(payload.get("prompt"), name="input.prompt", min_len=0, max_len=32_768)

        content_hash = payload.get("content_hash")
        if content_hash is not None:
            content_hash = _require_str(content_hash, name="input.content_hash", min_len=64, max_len=64).lower()
            _validate_hex64(content_hash, name="input.content_hash")

        if redaction_policy == REDACTION_HASH_ONLY and prompt:
            raise CrucibleSchemaError("input.prompt must be empty when redaction_policy=HASH_ONLY_CRUCIBLE (fail-closed)")
        if redaction_policy == REDACTION_HASH_ONLY and not content_hash:
            raise CrucibleSchemaError("input.content_hash required when redaction_policy=HASH_ONLY_CRUCIBLE (fail-closed)")

        return CrucibleInput(mode=mode, prompt=prompt, content_hash=content_hash, redaction_policy=redaction_policy)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"mode": self.mode, "prompt": self.prompt, "redaction_policy": self.redaction_policy}
        if self.content_hash is not None:
            out["content_hash"] = self.content_hash
        return out


@dataclass(frozen=True)
class CrucibleBudgets:
    time_ms: int
    stdout_max_bytes: int
    stderr_max_bytes: int
    runner_memory_max_mb: int
    kernel_timeout_kill_ms: int
    token_cap: int
    step_cap: int
    branch_cap: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleBudgets":
        payload = _require_dict(data, name="budgets")
        allowed = {
            "time_ms",
            "stdout_max_bytes",
            "stderr_max_bytes",
            "runner_memory_max_mb",
            "kernel_timeout_kill_ms",
            "token_cap",
            "step_cap",
            "branch_cap",
        }
        _reject_unknown_keys(payload, allowed=set(allowed), name="budgets")

        time_ms = _require_int(payload.get("time_ms", 30_000), name="budgets.time_ms", lo=50, hi=300_000)
        stdout_max_bytes = _require_int(
            payload.get("stdout_max_bytes", 262_144), name="budgets.stdout_max_bytes", lo=256, hi=1_048_576
        )
        stderr_max_bytes = _require_int(
            payload.get("stderr_max_bytes", 262_144), name="budgets.stderr_max_bytes", lo=0, hi=1_048_576
        )
        runner_memory_max_mb = _require_int(
            payload.get("runner_memory_max_mb", 1024), name="budgets.runner_memory_max_mb", lo=32, hi=4096
        )
        kernel_timeout_kill_ms = _require_int(
            payload.get("kernel_timeout_kill_ms", time_ms + 500),
            name="budgets.kernel_timeout_kill_ms",
            lo=50,
            hi=300_000,
        )
        if kernel_timeout_kill_ms < time_ms:
            raise CrucibleSchemaError("budgets.kernel_timeout_kill_ms must be >= budgets.time_ms (fail-closed)")

        token_cap = _require_int(payload.get("token_cap", 0), name="budgets.token_cap", lo=0, hi=200_000)
        step_cap = _require_int(payload.get("step_cap", 0), name="budgets.step_cap", lo=0, hi=100_000)
        branch_cap = _require_int(payload.get("branch_cap", 0), name="budgets.branch_cap", lo=0, hi=100_000)

        return CrucibleBudgets(
            time_ms=time_ms,
            stdout_max_bytes=stdout_max_bytes,
            stderr_max_bytes=stderr_max_bytes,
            runner_memory_max_mb=runner_memory_max_mb,
            kernel_timeout_kill_ms=kernel_timeout_kill_ms,
            token_cap=token_cap,
            step_cap=step_cap,
            branch_cap=branch_cap,
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class OutputContract:
    must_be_json: bool
    required_keys: Tuple[str, ...]
    forbidden_substrings: Tuple[str, ...]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "OutputContract":
        payload = _require_dict(data, name="expect.output_contract")
        allowed = {"must_be_json", "required_keys", "forbidden_substrings"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="expect.output_contract")

        must_be_json = payload.get("must_be_json", True)
        must_be_json = _require_bool(must_be_json, name="expect.output_contract.must_be_json")

        required_keys = payload.get("required_keys", [])
        required_keys_list = _validate_str_list(
            required_keys,
            name="expect.output_contract.required_keys",
            min_items=0,
            max_items=16,
            item_min_len=1,
            item_max_len=64,
        )

        forbidden_substrings = payload.get("forbidden_substrings", [])
        forbidden_list = _validate_str_list(
            forbidden_substrings,
            name="expect.output_contract.forbidden_substrings",
            min_items=0,
            max_items=32,
            item_min_len=1,
            item_max_len=128,
        )

        return OutputContract(must_be_json=must_be_json, required_keys=tuple(required_keys_list), forbidden_substrings=tuple(forbidden_list))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "must_be_json": self.must_be_json,
            "required_keys": list(self.required_keys),
            "forbidden_substrings": list(self.forbidden_substrings),
        }


@dataclass(frozen=True)
class GovernanceExpectations:
    required_event_types: Tuple[str, ...]
    forbidden_event_types: Tuple[str, ...]
    event_count_min: int
    event_count_max: int

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "GovernanceExpectations":
        payload = _require_dict(data, name="expect.governance_expectations")
        allowed = {"required_event_types", "forbidden_event_types", "event_count_min", "event_count_max"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="expect.governance_expectations")

        required_types = _validate_str_list(
            payload.get("required_event_types", []),
            name="expect.governance_expectations.required_event_types",
            min_items=0,
            max_items=16,
            item_min_len=1,
            item_max_len=64,
        )
        forbidden_types = _validate_str_list(
            payload.get("forbidden_event_types", []),
            name="expect.governance_expectations.forbidden_event_types",
            min_items=0,
            max_items=16,
            item_min_len=1,
            item_max_len=64,
        )

        event_count_min = _require_int(payload.get("event_count_min", 0), name="expect.governance_expectations.event_count_min", lo=0, hi=1000)
        event_count_max = _require_int(payload.get("event_count_max", 0), name="expect.governance_expectations.event_count_max", lo=0, hi=1000)
        if event_count_max < event_count_min:
            raise CrucibleSchemaError("expect.governance_expectations.event_count_max must be >= event_count_min (fail-closed)")

        return GovernanceExpectations(
            required_event_types=tuple(required_types),
            forbidden_event_types=tuple(forbidden_types),
            event_count_min=event_count_min,
            event_count_max=event_count_max,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required_event_types": list(self.required_event_types),
            "forbidden_event_types": list(self.forbidden_event_types),
            "event_count_min": self.event_count_min,
            "event_count_max": self.event_count_max,
        }


@dataclass(frozen=True)
class ThermoExpectations:
    must_enforce_budget: bool
    expected_budget_verdict: str

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "ThermoExpectations":
        payload = _require_dict(data, name="expect.thermo_expectations")
        allowed = {"must_enforce_budget", "expected_budget_verdict"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="expect.thermo_expectations")

        must_enforce_budget = payload.get("must_enforce_budget", False)
        must_enforce_budget = _require_bool(must_enforce_budget, name="expect.thermo_expectations.must_enforce_budget")

        expected_budget_verdict = payload.get("expected_budget_verdict", THERMO_NOT_ASSERTED)
        expected_budget_verdict = _require_str(expected_budget_verdict, name="expect.thermo_expectations.expected_budget_verdict", min_len=1, max_len=64)
        _validate_enum(expected_budget_verdict, allowed=THERMO_BUDGET_VERDICTS_ALLOWED, name="expect.thermo_expectations.expected_budget_verdict")

        return ThermoExpectations(must_enforce_budget=must_enforce_budget, expected_budget_verdict=expected_budget_verdict)

    def to_dict(self) -> Dict[str, Any]:
        return {"must_enforce_budget": self.must_enforce_budget, "expected_budget_verdict": self.expected_budget_verdict}


@dataclass(frozen=True)
class CrucibleExpect:
    expected_outcome: str
    output_contract: OutputContract
    replay_verification: str
    governance_expectations: GovernanceExpectations
    thermo_expectations: ThermoExpectations
    expected_refusal_code: Optional[str] = None
    expected_status_code: Optional[str] = None
    expected_infeasibility_token: Optional[str] = None

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleExpect":
        payload = _require_dict(data, name="expect")
        allowed = {
            "expected_outcome",
            "output_contract",
            "replay_verification",
            "governance_expectations",
            "thermo_expectations",
            "expected_refusal_code",
            "expected_status_code",
            "expected_infeasibility_token",
        }
        required = {"expected_outcome", "output_contract", "replay_verification", "governance_expectations", "thermo_expectations"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="expect")
        _require_keys(payload, required=set(required), name="expect")

        expected_outcome = _require_str(payload.get("expected_outcome"), name="expect.expected_outcome", min_len=1, max_len=16)
        _validate_enum(expected_outcome, allowed=OUTCOMES_ALLOWED, name="expect.expected_outcome")

        replay_verification = _require_str(payload.get("replay_verification"), name="expect.replay_verification", min_len=1, max_len=32)
        _validate_enum(replay_verification, allowed=REPLAY_MODES_ALLOWED, name="expect.replay_verification")

        output_contract = OutputContract.from_dict(_require_dict(payload.get("output_contract"), name="expect.output_contract"))
        governance_expectations = GovernanceExpectations.from_dict(_require_dict(payload.get("governance_expectations"), name="expect.governance_expectations"))
        thermo_expectations = ThermoExpectations.from_dict(_require_dict(payload.get("thermo_expectations"), name="expect.thermo_expectations"))

        expected_refusal_code = payload.get("expected_refusal_code")
        if expected_refusal_code is not None:
            expected_refusal_code = _require_str(expected_refusal_code, name="expect.expected_refusal_code", min_len=0, max_len=64)

        expected_status_code = payload.get("expected_status_code")
        if expected_status_code is not None:
            expected_status_code = _require_str(expected_status_code, name="expect.expected_status_code", min_len=0, max_len=64)

        expected_infeasibility_token = payload.get("expected_infeasibility_token")
        if expected_infeasibility_token is not None:
            expected_infeasibility_token = _require_str(expected_infeasibility_token, name="expect.expected_infeasibility_token", min_len=0, max_len=64)

        return CrucibleExpect(
            expected_outcome=expected_outcome,
            output_contract=output_contract,
            replay_verification=replay_verification,
            governance_expectations=governance_expectations,
            thermo_expectations=thermo_expectations,
            expected_refusal_code=expected_refusal_code,
            expected_status_code=expected_status_code,
            expected_infeasibility_token=expected_infeasibility_token,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "expected_outcome": self.expected_outcome,
            "output_contract": self.output_contract.to_dict(),
            "replay_verification": self.replay_verification,
            "governance_expectations": self.governance_expectations.to_dict(),
            "thermo_expectations": self.thermo_expectations.to_dict(),
        }
        if self.expected_refusal_code is not None:
            out["expected_refusal_code"] = self.expected_refusal_code
        if self.expected_status_code is not None:
            out["expected_status_code"] = self.expected_status_code
        if self.expected_infeasibility_token is not None:
            out["expected_infeasibility_token"] = self.expected_infeasibility_token
        return out


@dataclass(frozen=True)
class CrucibleVariant:
    input_prompt: Optional[str] = None
    budgets_override: Optional[CrucibleBudgets] = None
    expect_override: Optional[CrucibleExpect] = None

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleVariant":
        payload = _require_dict(data, name="variant")
        allowed = {"input", "budgets", "expect"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="variant")

        input_prompt: Optional[str] = None
        if "input" in payload:
            inp = _require_dict(payload.get("input"), name="variant.input")
            _reject_unknown_keys(inp, allowed={"prompt"}, name="variant.input")
            if "prompt" in inp:
                input_prompt = _require_str(inp.get("prompt"), name="variant.input.prompt", min_len=0, max_len=32_768)

        budgets_override: Optional[CrucibleBudgets] = None
        if "budgets" in payload:
            budgets_override = CrucibleBudgets.from_dict(_require_dict(payload.get("budgets"), name="variant.budgets"))

        expect_override: Optional[CrucibleExpect] = None
        if "expect" in payload:
            expect_override = CrucibleExpect.from_dict(_require_dict(payload.get("expect"), name="variant.expect"))

        return CrucibleVariant(input_prompt=input_prompt, budgets_override=budgets_override, expect_override=expect_override)


@dataclass(frozen=True)
class CrucibleProvenance:
    source: str
    version_pin: str
    references: Tuple[str, ...]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleProvenance":
        payload = _require_dict(data, name="provenance")
        allowed = {"source", "version_pin", "references"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="provenance")

        source = _require_str(payload.get("source", ""), name="provenance.source", min_len=0, max_len=256)
        version_pin = _require_str(payload.get("version_pin", ""), name="provenance.version_pin", min_len=0, max_len=128)
        refs = _validate_str_list(
            payload.get("references", []),
            name="provenance.references",
            min_items=0,
            max_items=16,
            item_min_len=0,
            item_max_len=256,
        )
        return CrucibleProvenance(source=source, version_pin=version_pin, references=tuple(refs))

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "version_pin": self.version_pin, "references": list(self.references)}


@dataclass(frozen=True)
class CrucibleTags:
    domains: Tuple[str, ...]
    subdomains: Tuple[str, ...]
    microdomains: Tuple[str, ...]
    ventures: Tuple[str, ...]
    reasoning_modes: Tuple[str, ...]
    modalities: Tuple[str, ...]
    tools: Tuple[str, ...]
    paradox_classes: Tuple[str, ...]

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleTags":
        payload = _require_dict(data, name="tags")
        allowed = {
            "domains",
            "subdomains",
            "microdomains",
            "ventures",
            "reasoning_modes",
            "modalities",
            "tools",
            "paradox_classes",
        }
        _reject_unknown_keys(payload, allowed=set(allowed), name="tags")
        _require_keys(payload, required=set(allowed), name="tags")

        domains = _validate_str_list(payload.get("domains", []), name="tags.domains", min_items=0, max_items=32, item_min_len=1, item_max_len=64)
        subdomains = _validate_str_list(payload.get("subdomains", []), name="tags.subdomains", min_items=0, max_items=64, item_min_len=1, item_max_len=64)
        microdomains = _validate_str_list(payload.get("microdomains", []), name="tags.microdomains", min_items=0, max_items=128, item_min_len=1, item_max_len=64)
        ventures = _validate_str_list(payload.get("ventures", []), name="tags.ventures", min_items=0, max_items=32, item_min_len=1, item_max_len=64)
        reasoning_modes = _validate_str_list(payload.get("reasoning_modes", []), name="tags.reasoning_modes", min_items=0, max_items=32, item_min_len=1, item_max_len=64)
        modalities = _validate_str_list(payload.get("modalities", []), name="tags.modalities", min_items=0, max_items=32, item_min_len=1, item_max_len=64)
        tools = _validate_str_list(payload.get("tools", []), name="tags.tools", min_items=0, max_items=32, item_min_len=1, item_max_len=64)
        paradox_classes = _validate_str_list(payload.get("paradox_classes", []), name="tags.paradox_classes", min_items=0, max_items=32, item_min_len=1, item_max_len=64)

        return CrucibleTags(
            domains=tuple(domains),
            subdomains=tuple(subdomains),
            microdomains=tuple(microdomains),
            ventures=tuple(ventures),
            reasoning_modes=tuple(reasoning_modes),
            modalities=tuple(modalities),
            tools=tuple(tools),
            paradox_classes=tuple(paradox_classes),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": list(self.domains),
            "subdomains": list(self.subdomains),
            "microdomains": list(self.microdomains),
            "ventures": list(self.ventures),
            "reasoning_modes": list(self.reasoning_modes),
            "modalities": list(self.modalities),
            "tools": list(self.tools),
            "paradox_classes": list(self.paradox_classes),
        }


@dataclass(frozen=True)
class CrucibleSpec:
    schema: str
    schema_version: int
    crucible_id: str
    title: str
    domain: str
    kernel_targets: Tuple[str, ...]
    input: CrucibleInput
    budgets: CrucibleBudgets
    expect: CrucibleExpect
    tags: CrucibleTags
    description: str = ""
    notes: str = ""
    provenance: Optional[CrucibleProvenance] = None
    variants: Tuple[CrucibleVariant, ...] = ()

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "CrucibleSpec":
        payload = _require_dict(data, name="CrucibleSpec")
        allowed = {
            "schema",
            "schema_version",
            "crucible_id",
            "title",
            "domain",
            "kernel_targets",
            "input",
            "budgets",
            "expect",
            "tags",
            "description",
            "notes",
            "provenance",
            "variants",
        }
        required = {"schema", "schema_version", "crucible_id", "title", "domain", "kernel_targets", "input", "budgets", "expect", "tags"}
        _reject_unknown_keys(payload, allowed=set(allowed), name="CrucibleSpec")
        _require_keys(payload, required=set(required), name="CrucibleSpec")

        schema = _require_str(payload.get("schema"), name="schema", min_len=1, max_len=64)
        if schema != "kt.crucible.spec":
            raise CrucibleSchemaError("schema must equal 'kt.crucible.spec' (fail-closed)")

        schema_version = _require_int(payload.get("schema_version"), name="schema_version", lo=1, hi=1)

        crucible_id = _require_str(payload.get("crucible_id"), name="crucible_id", min_len=1, max_len=80)
        if not _CRUCIBLE_ID_RE.match(crucible_id):
            raise CrucibleSchemaError("crucible_id contains illegal characters (fail-closed)")

        title = _require_str(payload.get("title"), name="title", min_len=1, max_len=160)
        domain = _require_str(payload.get("domain"), name="domain", min_len=1, max_len=64)

        kernel_targets_raw = _validate_str_list(payload.get("kernel_targets"), name="kernel_targets", min_items=1, max_items=2, item_min_len=1, item_max_len=32)
        kernel_targets: List[str] = []
        for t in kernel_targets_raw:
            _validate_enum(t, allowed=KERNEL_TARGETS_ALLOWED, name="kernel_targets")
            if t not in kernel_targets:
                kernel_targets.append(t)
        if KERNEL_V2_SOVEREIGN not in kernel_targets:
            raise CrucibleSchemaError("kernel_targets must include V2_SOVEREIGN (fail-closed)")

        tags = CrucibleTags.from_dict(payload.get("tags"))
        description = _require_str(payload.get("description", ""), name="description", min_len=0, max_len=2000)
        notes = _require_str(payload.get("notes", ""), name="notes", min_len=0, max_len=4000)

        inp = CrucibleInput.from_dict(_require_dict(payload.get("input"), name="input"))
        if inp.content_hash is not None and inp.prompt:
            actual = sha256_text(inp.prompt)
            if actual != inp.content_hash:
                raise CrucibleSchemaError("input.content_hash does not match sha256(prompt) (fail-closed)")

        budgets = CrucibleBudgets.from_dict(_require_dict(payload.get("budgets"), name="budgets"))
        expect = CrucibleExpect.from_dict(_require_dict(payload.get("expect"), name="expect"))

        provenance = None
        if "provenance" in payload and payload.get("provenance") is not None:
            provenance = CrucibleProvenance.from_dict(_require_dict(payload.get("provenance"), name="provenance"))

        variants: Tuple[CrucibleVariant, ...] = ()
        if "variants" in payload and payload.get("variants") is not None:
            raw_variants = _require_list(payload.get("variants"), name="variants")
            if len(raw_variants) > 32:
                raise CrucibleSchemaError("variants may have at most 32 items (fail-closed)")
            variants_list: List[CrucibleVariant] = []
            for idx, item in enumerate(raw_variants):
                variants_list.append(CrucibleVariant.from_dict(_require_dict(item, name=f"variants[{idx}]")))
            variants = tuple(variants_list)

        if variants and inp.content_hash is not None:
            for v in variants:
                if v.input_prompt is not None and v.input_prompt != inp.prompt:
                    raise CrucibleSchemaError("variants cannot override input.prompt when input.content_hash is set (fail-closed)")

        return CrucibleSpec(
            schema=schema,
            schema_version=schema_version,
            crucible_id=crucible_id,
            title=title,
            domain=domain,
            kernel_targets=tuple(kernel_targets),
            input=inp,
            budgets=budgets,
            expect=expect,
            tags=tags,
            description=description,
            notes=notes,
            provenance=provenance,
            variants=variants,
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "crucible_id": self.crucible_id,
            "title": self.title,
            "domain": self.domain,
            "kernel_targets": list(self.kernel_targets),
            "input": self.input.to_dict(),
            "budgets": self.budgets.to_dict(),
            "expect": self.expect.to_dict(),
            "tags": self.tags.to_dict(),
        }
        if self.description:
            out["description"] = self.description
        if self.notes:
            out["notes"] = self.notes
        if self.provenance is not None:
            out["provenance"] = self.provenance.to_dict()
        if self.variants:
            out["variants"] = [
                {
                    **({"input": {"prompt": v.input_prompt}} if v.input_prompt is not None else {}),
                    **({"budgets": v.budgets_override.to_dict()} if v.budgets_override is not None else {}),
                    **({"expect": v.expect_override.to_dict()} if v.expect_override is not None else {}),
                }
                for v in self.variants
            ]
        return out


def crucible_spec_hash(spec: CrucibleSpec) -> str:
    return sha256_json(spec.to_dict())


def budgets_hash(budgets: CrucibleBudgets) -> str:
    return sha256_json(budgets.to_dict())


def run_id(*, kernel_target: str, crucible_spec_hash_hex: str, prompt_hash_hex: str, seed: int, budgets_hash_hex: str) -> str:
    _validate_enum(kernel_target, allowed=KERNEL_TARGETS_ALLOWED, name="kernel_target")
    _validate_hex64(crucible_spec_hash_hex, name="crucible_spec_hash")
    _validate_hex64(prompt_hash_hex, name="prompt_hash")
    _validate_hex64(budgets_hash_hex, name="budgets_hash")
    return sha256_text(f"{kernel_target}|{crucible_spec_hash_hex}|{prompt_hash_hex}|{seed}|{budgets_hash_hex}")
