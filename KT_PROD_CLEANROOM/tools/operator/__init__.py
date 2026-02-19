"""
Operator-facing tooling (post-V1 productization).

These tools are clients of existing KT primitives and must not mutate
repo-tracked state during execution. All evidence is written WORM under
KT_PROD_CLEANROOM/exports/_runs/.
"""

