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
    boundary_generated_token_index_exclusive: int | None
    trigger_token_start_index: int | None
    correction_present: bool = False
    protective_abort: bool = False

    def to_json(self) -> dict:
        data = asdict(self)
        data["generator_termination_source"] = self.generator_termination_source.value
        data["semantic_boundary_type"] = self.semantic_boundary_type.value
        return data


@dataclass
class StopGrammarV33RuntimeFSM:
    """Incremental generated-only STOP300 V3 detector.

    M0 monitor mode continues decoding after a first boundary. The first lawful
    accepted boundary is immutable and remains the comparison surface for the
    independent court.
    """

    marker: str = "FINAL_ANSWER:"
    monitor_only: bool = False
    suffix_limit: int = 512
    text: str = ""
    detector_calls: int = 0
    detector_cpu_ns_total: int = 0
    characters_examined: int = 0
    tokens_examined: int = 0
    full_sequence_rescan_count: int = 0
    incremental_decode_count: int = 0
    first_boundary_decision: BoundaryDecision | None = None
    last_detector_decision: BoundaryDecision | None = None
    candidate_boundaries: int = 0
    rejected_boundaries: int = 0
    state_transitions: list[str] = field(default_factory=list)

    def _default(self, source: GeneratorTerminationSource) -> BoundaryDecision:
        return BoundaryDecision(False, source, SemanticBoundaryType.NO_VALID_BOUNDARY, self.text, None, None)

    def _accept(self, decision: BoundaryDecision) -> BoundaryDecision:
        if self.first_boundary_decision is None and decision.semantic_boundary_type != SemanticBoundaryType.NO_VALID_BOUNDARY:
            self.first_boundary_decision = decision
        self.last_detector_decision = decision
        if self.monitor_only:
            return BoundaryDecision(
                False,
                decision.generator_termination_source,
                decision.semantic_boundary_type,
                decision.visible_text,
                decision.boundary_generated_token_index_exclusive,
                decision.trigger_token_start_index,
                correction_present=decision.correction_present,
                protective_abort=decision.protective_abort,
            )
        return decision

    def feed(
        self,
        piece: str,
        *,
        token_start_index: int,
        token_end_index: int,
        eos: bool = False,
        max_new_tokens: bool = False,
    ) -> BoundaryDecision:
        start = time.perf_counter_ns()
        self.detector_calls += 1
        self.incremental_decode_count += 1
        self.tokens_examined += max(0, token_end_index - token_start_index)
        self.text += piece
        scan_start = max(0, len(self.text) - self.suffix_limit)
        scan = self.text[scan_start:]
        self.characters_examined += len(scan)
        source = GeneratorTerminationSource.MAX_NEW_TOKENS if max_new_tokens else (
            GeneratorTerminationSource.EOS_TOKEN if eos else GeneratorTerminationSource.UNKNOWN
        )

        marker_match = re.search(r"(?m)^[ \t]*" + re.escape(self.marker), scan)
        if marker_match is None:
            decision = self._default(source)
            self.last_detector_decision = decision
            self.state_transitions.append("SEARCH_MARKER")
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return decision

        self.candidate_boundaries += 1
        marker_start = scan_start + marker_match.start()
        marker_end = scan_start + marker_match.end()
        tail = self.text[marker_end:]
        payload_start = re.search(r"\S", tail)
        if payload_start is None:
            self.rejected_boundaries += 1
            decision = BoundaryDecision(False, source, SemanticBoundaryType.MALFORMED_FINAL, self.text, None, None, protective_abort=True)
            self.last_detector_decision = decision
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return decision

        answer_start = marker_end + payload_start.start()
        rest = self.text[answer_start:]
        newline = re.search(r"\r\n|\n|\r", rest)
        second_marker = rest.find(self.marker)
        correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong|wait)\b", rest, re.I))

        if second_marker >= 0 and (newline is None or second_marker < newline.start()):
            first_payload = rest[:second_marker].strip()
            if first_payload and not correction:
                # The second marker may have required one or more trigger tokens;
                # those tokens count as physical work but are excluded from
                # authoritative preserved output by slicing before this callback.
                decision = BoundaryDecision(
                    True,
                    GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                    SemanticBoundaryType.SECOND_MARKER_CLOSE,
                    self.text[: answer_start + second_marker].rstrip(),
                    token_start_index,
                    token_start_index,
                    correction_present=False,
                )
                self.detector_cpu_ns_total += time.perf_counter_ns() - start
                return self._accept(decision)
            self.rejected_boundaries += 1

        if newline is not None:
            decision = BoundaryDecision(
                True,
                GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                SemanticBoundaryType.FINAL_LINE_CLOSE,
                self.text[: answer_start + newline.end()],
                token_end_index,
                None,
                correction_present=correction,
            )
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return self._accept(decision)

        if eos and not max_new_tokens:
            decision = BoundaryDecision(
                True,
                GeneratorTerminationSource.EOS_TOKEN,
                SemanticBoundaryType.SAFE_EOS_CLOSURE,
                self.text.rstrip(),
                token_end_index,
                None,
                correction_present=correction,
            )
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return self._accept(decision)

        decision = self._default(source)
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
            "incremental_decode_count": self.incremental_decode_count,
            "first_boundary_decision": self.first_boundary_decision.to_json() if self.first_boundary_decision else None,
            "last_detector_decision": self.last_detector_decision.to_json() if self.last_detector_decision else None,
            "candidate_boundaries": self.candidate_boundaries,
            "rejected_boundaries": self.rejected_boundaries,
            "state_transitions": self.state_transitions,
        }
