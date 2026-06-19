from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum


class GeneratorTerminationSource(str, Enum):
    CUSTOM_STOP_CRITERION = "CUSTOM_STOP_CRITERION"
    EOS_TOKEN = "EOS_TOKEN"
    MAX_NEW_TOKENS = "MAX_NEW_TOKENS"
    MODEL_EXCEPTION = "MODEL_EXCEPTION"
    EXTERNAL_ABORT = "EXTERNAL_ABORT"
    UNKNOWN = "UNKNOWN"


class SemanticBoundaryType(str, Enum):
    FINAL_LINE_CLOSE = "FINAL_LINE_CLOSE"
    SECOND_MARKER_CLOSE = "SECOND_MARKER_CLOSE"
    SAFE_EOS_CLOSURE = "SAFE_EOS_CLOSURE"
    NO_VALID_BOUNDARY = "NO_VALID_BOUNDARY"
    MALFORMED_FINAL = "MALFORMED_FINAL"


@dataclass(frozen=True)
class BoundaryDecision:
    should_stop: bool
    generator_termination_source: GeneratorTerminationSource
    semantic_boundary_type: SemanticBoundaryType
    visible_text: str
    boundary_char_index: int | None
    boundary_token_index_floor: int | None
    boundary_token_index_ceil: int | None
    trigger_token_start_index: int | None
    trigger_char_offset_within_token_if_any: int | None = None
    correction_present: bool = False
    protective_abort: bool = False

    def to_json(self) -> dict:
        payload = asdict(self)
        payload["generator_termination_source"] = self.generator_termination_source.value
        payload["semantic_boundary_type"] = self.semantic_boundary_type.value
        return payload


@dataclass
class StopGrammarV34RuntimeFSM:
    """Generated-token-only STOP detector with immutable first boundary.

    V4 keeps the M0 first accepted boundary fixed even if later text contains a
    different parse. EOS facts are explicit inputs, not inferred from arbitrary
    EOS tokens appearing earlier in the stream.
    """

    marker: str = "FINAL_ANSWER:"
    monitor_only: bool = False
    suffix_limit: int = 512
    text: str = ""
    detector_calls: int = 0
    detector_cpu_ns_total: int = 0
    tokens_examined: int = 0
    characters_examined: int = 0
    full_sequence_rescan_count: int = 0
    first_boundary_decision: BoundaryDecision | None = None
    last_detector_decision: BoundaryDecision | None = None
    state_transitions: list[str] = field(default_factory=list)

    def _source(self, *, ended_on_eos: bool, ended_on_max_new_tokens: bool) -> GeneratorTerminationSource:
        if ended_on_max_new_tokens:
            return GeneratorTerminationSource.MAX_NEW_TOKENS
        if ended_on_eos:
            return GeneratorTerminationSource.EOS_TOKEN
        return GeneratorTerminationSource.UNKNOWN

    def _record(self, decision: BoundaryDecision) -> BoundaryDecision:
        if self.first_boundary_decision is None and decision.semantic_boundary_type != SemanticBoundaryType.NO_VALID_BOUNDARY:
            self.first_boundary_decision = decision
        self.last_detector_decision = decision
        if self.monitor_only and decision.should_stop:
            return BoundaryDecision(
                False,
                decision.generator_termination_source,
                decision.semantic_boundary_type,
                decision.visible_text,
                decision.boundary_char_index,
                decision.boundary_token_index_floor,
                decision.boundary_token_index_ceil,
                decision.trigger_token_start_index,
                decision.trigger_char_offset_within_token_if_any,
                decision.correction_present,
                decision.protective_abort,
            )
        return decision

    def feed(
        self,
        piece: str,
        *,
        token_start_index: int,
        token_end_index: int,
        ended_on_eos: bool = False,
        ended_on_max_new_tokens: bool = False,
    ) -> BoundaryDecision:
        start = time.perf_counter_ns()
        self.detector_calls += 1
        self.tokens_examined += max(0, token_end_index - token_start_index)
        self.text += piece
        scan_start = max(0, len(self.text) - self.suffix_limit)
        scan = self.text[scan_start:]
        self.characters_examined += len(scan)
        source = self._source(ended_on_eos=ended_on_eos, ended_on_max_new_tokens=ended_on_max_new_tokens)

        marker_match = re.search(r"(?m)^[ \t]*" + re.escape(self.marker), scan)
        if marker_match is None:
            decision = BoundaryDecision(False, source, SemanticBoundaryType.NO_VALID_BOUNDARY, self.text, None, None, None, None)
            self.last_detector_decision = decision
            self.state_transitions.append("SEARCH_MARKER")
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return decision

        marker_end = scan_start + marker_match.end()
        tail = self.text[marker_end:]
        payload_start = re.search(r"\S", tail)
        if payload_start is None:
            decision = BoundaryDecision(False, source, SemanticBoundaryType.MALFORMED_FINAL, self.text, None, None, None, None, protective_abort=True)
            self.last_detector_decision = decision
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return decision

        answer_start = marker_end + payload_start.start()
        rest = self.text[answer_start:]
        newline = re.search(r"\r\n|\n|\r", rest)
        second_marker = rest.find(self.marker)
        correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong|wait)\b", rest, re.I))

        if second_marker >= 0 and (newline is None or second_marker < newline.start()):
            visible_end = answer_start + second_marker
            if rest[:second_marker].strip() and not correction:
                decision = BoundaryDecision(
                    True,
                    GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                    SemanticBoundaryType.SECOND_MARKER_CLOSE,
                    self.text[:visible_end].rstrip(),
                    visible_end,
                    token_start_index,
                    token_end_index,
                    token_start_index,
                    0,
                    False,
                )
                self.detector_cpu_ns_total += time.perf_counter_ns() - start
                return self._record(decision)

        if newline is not None:
            visible_end = answer_start + newline.end()
            decision = BoundaryDecision(
                True,
                GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                SemanticBoundaryType.FINAL_LINE_CLOSE,
                self.text[:visible_end],
                visible_end,
                token_start_index,
                token_end_index,
                None,
                None,
                correction,
            )
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return self._record(decision)

        if ended_on_eos and not ended_on_max_new_tokens:
            decision = BoundaryDecision(
                True,
                GeneratorTerminationSource.EOS_TOKEN,
                SemanticBoundaryType.SAFE_EOS_CLOSURE,
                self.text.rstrip(),
                len(self.text),
                token_start_index,
                token_end_index,
                None,
                None,
                correction,
            )
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return self._record(decision)

        decision = BoundaryDecision(False, source, SemanticBoundaryType.NO_VALID_BOUNDARY, self.text, None, None, None, None, correction)
        self.last_detector_decision = decision
        self.state_transitions.append("WAIT_BOUNDARY")
        self.detector_cpu_ns_total += time.perf_counter_ns() - start
        return decision

    def telemetry(self) -> dict:
        return {
            "detector_calls": self.detector_calls,
            "detector_cpu_ns_total": self.detector_cpu_ns_total,
            "detector_cpu_ns_per_generated_token": self.detector_cpu_ns_total / max(self.tokens_examined, 1),
            "characters_examined": self.characters_examined,
            "tokens_examined": self.tokens_examined,
            "full_sequence_rescan_count": self.full_sequence_rescan_count,
            "first_boundary_decision": self.first_boundary_decision.to_json() if self.first_boundary_decision else None,
            "last_detector_decision": self.last_detector_decision.to_json() if self.last_detector_decision else None,
            "state_transitions": self.state_transitions,
        }
