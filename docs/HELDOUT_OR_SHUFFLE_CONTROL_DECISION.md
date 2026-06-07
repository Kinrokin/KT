# Held-Out Or Shuffle Control Decision

This lane resolves the EPC branch after final-answer extraction v2 was quarantined. If a true non-overlapping held-out source is bound, it may generate a held-out generalization packet. Otherwise it generates a row-order shuffle/leakage/negative-control packet over the existing byte-locked 50-row control.

Shuffle-control evidence must never be labeled as held-out generalization.
