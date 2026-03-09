# Subsystem Scorecard

| Subsystem | Closure Grade | Capability Grade | Strengths | Weaknesses | Blockers | Promotion Readiness |
| --- | --- | --- | --- | --- | --- | --- |
| canonical runtime | `B+` | `A-` | explicit entrypoint and spine, bounded runtime roots, runtime suite passed at current head | tracked posture around runtime is stale, clean-clone proof not rerun at current head | truth surfaces still pinned to older commits | freeze code, then re-ratify evidence |
| operator plane | `B` | `A-` | rich CLI, WORM run discipline, explicit certification lanes | large control surface, promotion evidence not current at tracked layer | truth-sync gap between live runs and tracked receipts | needs re-ratification |
| evidence plane | `C+` | `B+` | broad test coverage and truth matrix passed at `46173df31a9242c2e8f4bd7a1494b3466d1a89b9` | tracked evidence bundle is stale, validator still validates the older four-zone worldview | clean-clone smoke skipped in the fresh run | repair and rerun |
| delivery/security | `B` | `B+` | delivery tooling, redaction rules, secret-scan lane, release gates | latest delivery posture is not freshly sealed against current head | no current clean-clone replay proof in this audit cycle | ratify after clean-clone evidence |
| truth engine / posture | `C` | `B` | posture contract is explicit, fresh truth-engine run derived the correct downgraded state | tracked receipts conflict with fresh evidence, truth model omits generated/quarantine zones | `truth_engine.py` still assumes external validation indexes can be relativized into the repo | repair, then ratify |
| lab / adaptive stack | `C` | `B+` | large experimentation surface, growth and training infrastructure, policy-c work exists | too much adjacent material sits near canonical surfaces, authority split is partial | no fully codified promotion contract from lab to canonical | lab only |
| router / lobes | `C` | `B` | router demos and tests exist, runtime registry still models router organ | evidence base is narrow and stays outside canonical readiness | no ratified path from demo routing to canonical promotion | lab only |
| commercial / docs | `C` | `B` | broad documentation and packaging surface | docs mix explanation, policy, and history; some audit docs are historical only | authority smear makes docs easy to misread as truth | keep separate, re-ratify only policy docs |
| archive / legacy contamination | `D` | `C` | history is preserved and recoverable | archive material sits at repo root and near active surfaces, easy to confuse with current truth | no hard top-level cordon for root historical artifacts | archive only, quarantine misleading roots |
| repo hygiene / release discipline | `C-` | `B` | CI workflows, gates, repo canon, branch protection receipts | local branch is ahead of remote, ignored residue is massive, `.env.secret` exists locally | not clean-clone equivalent, no no-residue target | repair before any green claim |

## Summary Reading

- closure is strongest in the canonical runtime and weakest where truth surfaces, residue, and archive material smear system boundaries
- capability is strongest in the operator and runtime stacks; the repo can do more than it can presently certify
- the main deficit is not missing machinery; it is authority drift between live evidence, tracked receipts, and mixed repository zones
