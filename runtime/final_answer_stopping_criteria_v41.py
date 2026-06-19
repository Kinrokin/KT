from __future__ import annotations

from typing import Any

from runtime.stop_fsm_v34 import StopGrammarV34RuntimeFSM

try:
    import torch
    from transformers import StoppingCriteria
except Exception:  # pragma: no cover - exercised in packet smoke paths without deps
    torch = None

    class StoppingCriteria:  # type: ignore[no-redef]
        pass


class KTFinalAnswerStoppingCriteria(StoppingCriteria):
    """Generated-token-only STOP300 V4.1 online stopping criterion.

    V4 fed the detector after full generation. V4.1 lets Transformers call the
    detector during generation and returns True only for the S1 terminating arm.
    M0 uses the same FSM online, but monitor_only prevents physical termination.
    """

    def __init__(
        self,
        *,
        tokenizer: Any,
        prompt_token_count: int,
        monitor_only: bool,
        fsm: StopGrammarV34RuntimeFSM | None = None,
    ) -> None:
        self.tokenizer = tokenizer
        self.prompt_token_count = int(prompt_token_count)
        self.monitor_only = bool(monitor_only)
        self.fsm = fsm or StopGrammarV34RuntimeFSM(monitor_only=self.monitor_only)
        self.processed_generated_tokens = 0

    @property
    def telemetry(self) -> dict[str, Any]:
        return self.fsm.telemetry()

    @property
    def first_boundary_decision(self):
        return self.fsm.first_boundary_decision

    def _decode_piece(self, token_id: int) -> str:
        return self.tokenizer.decode([int(token_id)], skip_special_tokens=False)

    def consume_new_token_ids(self, token_ids: list[int]) -> bool:
        should_stop = False
        for token_id in token_ids:
            index = self.processed_generated_tokens
            decision = self.fsm.feed(
                self._decode_piece(token_id),
                token_start_index=index,
                token_end_index=index + 1,
            )
            self.processed_generated_tokens += 1
            if decision.should_stop and not self.monitor_only:
                should_stop = True
                break
        return should_stop

    def __call__(self, input_ids, scores, **kwargs):  # type: ignore[override]
        batch = int(input_ids.shape[0])
        if batch != 1:
            raise RuntimeError("KT_STOP300_BATCH_SIZE_ONE_REQUIRED")
        start = self.prompt_token_count + self.processed_generated_tokens
        generated = input_ids[0, start:].tolist()
        stop = self.consume_new_token_ids([int(token_id) for token_id in generated])
        if torch is None:
            return [stop]
        return torch.full((batch,), stop, dtype=torch.bool, device=input_ids.device)
