# WS22 Bounty Scope

Scope: verifier-only public verification for the sealed detached verifier package and bounded critical artifact set.

In scope
- Detached verifier replay using the published package, replay bundle, and recipe
- Detached-vs-repo-local parity on the sealed bounded subject set
- Hidden trust-input or repo-local dependency discovery
- Claim-boundary breaches that widen beyond the verifier-only public horizon

Explicit kill conditions
- `DETACHED_REPLAY_FAILS_WITH_DECLARED_INPUTS`
- `DETACHED_VS_REPO_LOCAL_PARITY_BREAK`
- `HIDDEN_REPO_LOCAL_OR_TRUST_INPUT_DEPENDENCY`
- `CLAIM_BOUNDARY_BREACH`

Out of scope
- Tournament readiness claims
- H1 activation claims
- Production deployment claims
- Economic or commercial entitlement claims
- Platform-governance upgrades

Submission package
- Reproduction steps
- Environment metadata
- Evidence refs and transcripts
- Claimed kill-condition id

Bounty boundary
- This bootstrap defines challenge classes and triage scope only.
- It does not promise cash compensation, commercial terms, or broader public-horizon upgrades.
- WS22 bootstraps an external challenge and bounty process only for the verifier-only public verification horizon. It does not widen public-horizon claims, does not treat the absence of submissions as proof of absence, and does not upgrade tournament, H1, production, economic, publication-readiness, or platform-governance claims.
