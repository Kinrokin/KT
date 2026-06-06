from __future__ import annotations

from memory.fademem_decay_controller import FadeMemDecayController


def test_memory_decay_retains_relevant_frequently_accessed_items_longer() -> None:
    controller = FadeMemDecayController()
    weak = controller.retention(age=20, semantic_relevance=0.0, access_count=0)
    strong = controller.retention(age=20, semantic_relevance=1.0, access_count=5)

    assert strong > weak


def test_memory_decay_never_overrides_live_repo_truth() -> None:
    controller = FadeMemDecayController()

    assert controller.decay_rate(0.0, 0, "live_repo_truth") == 0.0
    assert controller.retention(100000, authority_class="live_repo_truth") == 1.0
    assert controller.should_decay(100000, authority_class="live_repo_truth") is False
