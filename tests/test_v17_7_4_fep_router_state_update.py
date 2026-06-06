from __future__ import annotations

from models.fep_router import FEPShadowRouter


def test_fep_router_updates_leaky_state_and_remains_shadow_only() -> None:
    router = FEPShadowRouter(beta=0.5)
    first = router.update_state({"math_shift": 1.0})
    second = router.update_state({"math_shift": 1.0})

    assert first["math_shift"] == 0.5
    assert second["math_shift"] == 0.75
    assert router.runtime_authority is False
    assert router.promotion_authority is False


def test_precision_gating_rewards_low_variance_routes() -> None:
    router = FEPShadowRouter()
    for value in [0.1, 0.1, 0.1]:
        router.observe_error("stable", value)
    for value in [0.1, 0.9, 0.2]:
        router.observe_error("noisy", value)

    scores = router.route_scores({"stable": 1.0, "noisy": 1.0})

    assert router.precision("stable") > router.precision("noisy")
    assert scores["stable"] > scores["noisy"]
