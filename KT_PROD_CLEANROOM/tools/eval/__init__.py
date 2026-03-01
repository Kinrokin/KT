"""
EPIC_17: suite pack evaluation tooling (deterministic, offline, artifact-first).

This package contains only evaluation logic and report generation. It must not:
  - mutate runtime/spine surfaces
  - perform network I/O
  - depend on wall-clock entropy for hashed surfaces
"""

