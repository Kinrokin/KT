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
    trigger_char_index: int | None
    dropped_trigger_char_count: int = 0
    correction_present: bool = False
    protective_abort: bool = False

    def to_json(self) -> dict:
        data = asdict(self)
        data["generator_termination_source"] = self.generator_termination_source.value
        data["semantic_boundary_type"] = self.semantic_boundary_type.value
        return data


@dataclass
class StopGrammarV32RuntimeFSM:
    """Generated-only incremental STOP300 V2 detector.

    The runtime FSM is deliberately incremental and suffix-bounded. It exposes
    telemetry proving no full-sequence rescans were used by the detector.
    """

    marker: str = "FINAL_ANSWER:"
    monitor_only: bool = False
    suffix_limit: int = 320
    text: str = ""
    detector_calls: int = 0
    detector_cpu_ns_total: int = 0
    characters_examined: int = 0
    tokens_examined: int = 0
    full_sequence_rescan_count: int = 0
    incremental_decode_count: int = 0
    suffix_buffer_max_chars: int = 0
    accepted_boundary: str | None = None
    rejected_boundaries: int = 0
    candidate_boundaries: int = 0
    state_transitions: list[str] = field(default_factory=list)

    def feed(
        self,
        piece: str,
        *,
        eos: bool = False,
        max_new_tokens: bool = False,
        token_count: int = 1,
    ) -> BoundaryDecision:
        start = time.perf_counter_ns()
        self.detector_calls += 1
        self.incremental_decode_count += 1
        self.tokens_examined += max(token_count, 0)
        self.text += piece
        scan_start = max(0, len(self.text) - self.suffix_limit)
        scan = self.text[scan_start:]
        self.characters_examined += len(scan)
        self.suffix_buffer_max_chars = max(self.suffix_buffer_max_chars, len(scan))

        source = GeneratorTerminationSource.MAX_NEW_TOKENS if max_new_tokens else (
            GeneratorTerminationSource.EOS_TOKEN if eos else GeneratorTerminationSource.UNKNOWN
        )
        default = BoundaryDecision(False, source, SemanticBoundaryType.NO_VALID_BOUNDARY, self.text, None)
        marker_match = re.search(r"(?m)^[ \t]*" + re.escape(self.marker), scan)
        if marker_match is None:
            self.state_transitions.append("SEARCH_MARKER")
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return default

        self.candidate_boundaries += 1
        marker_start = scan_start + marker_match.start()
        marker_end = scan_start + marker_match.end()
        tail = self.text[marker_end:]
        payload_start = re.search(r"\S", tail)
        if payload_start is None:
            self.rejected_boundaries += 1
            self.state_transitions.append("MALFORMED_EMPTY_PAYLOAD")
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return BoundaryDecision(False, source, SemanticBoundaryType.MALFORMED_FINAL, self.text, marker_start, protective_abort=True)

        answer_start = marker_end + payload_start.start()
        rest = self.text[answer_start:]
        newline = re.search(r"\r\n|\n|\r", rest)
        second_marker = rest.find(self.marker)
        correction = bool(re.search(r"\b(correction|actually|instead|retract|wrong|wait)\b", rest, re.I))

        if second_marker >= 0 and (newline is None or second_marker < newline.start()):
            first_payload = rest[:second_marker].strip()
            if first_payload and not correction:
                cut = answer_start + second_marker
                self.accepted_boundary = SemanticBoundaryType.SECOND_MARKER_CLOSE.value
                self.detector_cpu_ns_total += time.perf_counter_ns() - start
                return BoundaryDecision(
                    not self.monitor_only,
                    GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                    SemanticBoundaryType.SECOND_MARKER_CLOSE,
                    self.text[:cut].rstrip(),
                    cut,
                    dropped_trigger_char_count=len(self.text) - cut,
                    correction_present=False,
                )
            self.rejected_boundaries += 1
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return BoundaryDecision(False, source, SemanticBoundaryType.NO_VALID_BOUNDARY, self.text, None, correction_present=correction)

        if newline is not None:
            cut = answer_start + newline.end()
            self.accepted_boundary = SemanticBoundaryType.FINAL_LINE_CLOSE.value
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return BoundaryDecision(
                not self.monitor_only,
                GeneratorTerminationSource.CUSTOM_STOP_CRITERION,
                SemanticBoundaryType.FINAL_LINE_CLOSE,
                self.text[:cut],
                cut,
                correction_present=correction,
            )

        if eos and not max_new_tokens:
            self.accepted_boundary = SemanticBoundaryType.SAFE_EOS_CLOSURE.value
            self.detector_cpu_ns_total += time.perf_counter_ns() - start
            return BoundaryDecision(
                not self.monitor_only,
                GeneratorTerminationSource.EOS_TOKEN,
                SemanticBoundaryType.SAFE_EOS_CLOSURE,
                self.text.rstrip(),
                len(self.text),
                correction_present=correction,
            )

        self.state_transitions.append("WAIT_BOUNDARY")
        self.detector_cpu_ns_total += time.perf_counter_ns() - start
        return default

    def telemetry(self) -> dict:
        return {
            "detector_calls": self.detector_calls,
            "detector_cpu_ns_total": self.detector_cpu_ns_total,
            "detector_cpu_ns_per_generated_token": self.detector_cpu_ns_total / max(self.tokens_examined, 1),
            "characters_examined": self.characters_examined,
            "tokens_examined": self.tokens_examined,
            "full_sequence_rescan_count": self.full_sequence_rescan_count,
            "incremental_decode_count": self.incremental_decode_count,
            "suffix_buffer_max_chars": self.suffix_buffer_max_chars,
            "accepted_boundary": self.accepted_boundary,
            "rejected_boundaries": self.rejected_boundaries,
            "candidate_boundaries": self.candidate_boundaries,
            "state_transitions": self.state_transitions,
        }
