from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from dream_schemas import DreamCandidateSchema, DreamSpecSchema, sha256_text


@dataclass(frozen=True)
class GeneratedDream:
    dream_spec_hash: str
    hypothesis_hash: str
    candidates: List[DreamCandidateSchema]


def generate_candidates(spec: DreamSpecSchema) -> GeneratedDream:
    dream_spec_hash = spec.spec_hash()
    hypothesis_hash = sha256_text(spec.hypothesis)
    candidates = [
        DreamCandidateSchema.build(
            dream_spec_hash=dream_spec_hash,
            index=i,
            hypothesis_hash=hypothesis_hash,
            kernel_target=spec.kernel_target,
        )
        for i in range(spec.candidate_bounds.max_candidates)
    ]
    candidates = sorted(candidates, key=lambda c: c.candidate_id)
    return GeneratedDream(dream_spec_hash=dream_spec_hash, hypothesis_hash=hypothesis_hash, candidates=candidates)


def prompt_for_candidate(*, spec: DreamSpecSchema, candidate: DreamCandidateSchema) -> str:
    # Prompts are treated as inputs, not durable evidence. They may be concrete.
    # Do not include any kernel outputs or prior run artifacts here.
    prompt = (
        "Return JSON with keys: status, head_hash, record_count, thermodynamics.\n"
        f"Dream: {spec.dream_id}\n"
        f"Candidate: {candidate.candidate_id}\n"
        f"Hypothesis: {spec.hypothesis}\n"
    )
    if len(prompt) > spec.candidate_bounds.max_prompt_chars:
        # Fail-closed on oversize prompts.
        raise ValueError("prompt exceeds max_prompt_chars (fail-closed)")
    return prompt

