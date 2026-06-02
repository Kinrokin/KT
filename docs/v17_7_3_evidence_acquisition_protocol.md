# V17.7.3 Evidence Acquisition Protocol

V17.7.3 converts V17.7.2 active-learning evidence into targeted boundary-row acquisition. The 260-row policy-search surface is exhausted; no policy optimization is authorized on it.

Rows are selected by expected information gain, then split into search, calibration, validation, and final holdout. Final holdout is quarantined for later promotion courts only.
