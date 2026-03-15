---- MODULE kt_core_invariants ----
EXTENDS Naturals, Sequences

(*
WS23 bounded formal model for the release-critical core invariants.
Sealed subject anchor: b4789a544954066ee6c225bc9cfa3fddb51c12ee
Current compiled head: 474a14f9d404e70524e60526d8fa427ae5948b94
Observed closed state: {"active_truth_source_is_ledger": true, "authority_rank": 2, "current_head_authority_claimed": false, "h1_allowed": false, "head_claim_evidence_only": true, "head_equals_subject": false, "main_pointer_doc_only": true, "main_runtime_doc_only": true, "main_state_doc_only": true, "previous_authority_rank": 1, "published_head_authority_claimed": true}
*)

VARIABLES authorityRank, previousAuthorityRank, headEqualsSubject,
          currentHeadAuthorityClaimed, headClaimEvidenceOnly,
          activeTruthSourceIsLedger, mainPointerDocOnly,
          mainStateDocOnly, mainRuntimeDocOnly,
          publishedHeadAuthorityClaimed, h1Allowed

Init ==
  /\ authorityRank = 1
  /\ previousAuthorityRank = 1
  /\ headEqualsSubject = TRUE
  /\ currentHeadAuthorityClaimed = TRUE
  /\ headClaimEvidenceOnly = FALSE
  /\ activeTruthSourceIsLedger = TRUE
  /\ mainPointerDocOnly = TRUE
  /\ mainStateDocOnly = TRUE
  /\ mainRuntimeDocOnly = TRUE
  /\ publishedHeadAuthorityClaimed = TRUE
  /\ h1Allowed = FALSE

AdvanceCurrentHeadEvidence ==
  /\ authorityRank >= 1
  /\ authorityRank' = authorityRank
  /\ previousAuthorityRank' = authorityRank
  /\ headEqualsSubject' = FALSE
  /\ currentHeadAuthorityClaimed' = FALSE
  /\ headClaimEvidenceOnly' = TRUE
  /\ h1Allowed' = FALSE
  /\ UNCHANGED <<activeTruthSourceIsLedger, mainPointerDocOnly, mainStateDocOnly,
                  mainRuntimeDocOnly, publishedHeadAuthorityClaimed>>

AlignCurrentHeadToSubject ==
  /\ authorityRank >= 1
  /\ authorityRank' = authorityRank
  /\ previousAuthorityRank' = authorityRank
  /\ headEqualsSubject' = TRUE
  /\ currentHeadAuthorityClaimed' = TRUE
  /\ headClaimEvidenceOnly' = FALSE
  /\ h1Allowed' = FALSE
  /\ UNCHANGED <<activeTruthSourceIsLedger, mainPointerDocOnly, mainStateDocOnly,
                  mainRuntimeDocOnly, publishedHeadAuthorityClaimed>>

SealAuthorityClosure ==
  /\ authorityRank \in {1, 2}
  /\ authorityRank' = 2
  /\ previousAuthorityRank' = authorityRank
  /\ h1Allowed' = FALSE
  /\ UNCHANGED <<headEqualsSubject, currentHeadAuthorityClaimed, headClaimEvidenceOnly,
                  activeTruthSourceIsLedger, mainPointerDocOnly, mainStateDocOnly,
                  mainRuntimeDocOnly, publishedHeadAuthorityClaimed>>

NoOp ==
  /\ authorityRank' = authorityRank
  /\ previousAuthorityRank' = authorityRank
  /\ h1Allowed' = FALSE
  /\ UNCHANGED <<headEqualsSubject, currentHeadAuthorityClaimed, headClaimEvidenceOnly,
                  activeTruthSourceIsLedger, mainPointerDocOnly, mainStateDocOnly,
                  mainRuntimeDocOnly, publishedHeadAuthorityClaimed>>

Next ==
  \/ AdvanceCurrentHeadEvidence
  \/ AlignCurrentHeadToSubject
  \/ SealAuthorityClosure
  \/ NoOp

SubjectEvidenceCurrentHeadAntiOverread ==
  headEqualsSubject \/ (~currentHeadAuthorityClaimed /\ headClaimEvidenceOnly)

DocumentaryMirrorNonAuthority ==
  activeTruthSourceIsLedger /\ mainPointerDocOnly /\ mainStateDocOnly /\ mainRuntimeDocOnly

AuthorityClosureMonotonicity ==
  authorityRank >= previousAuthorityRank /\ ~h1Allowed

TypeInvariant ==
  /\ authorityRank \in {1, 2}
  /\ previousAuthorityRank \in {1, 2}
  /\ headEqualsSubject \in BOOLEAN
  /\ currentHeadAuthorityClaimed \in BOOLEAN
  /\ headClaimEvidenceOnly \in BOOLEAN
  /\ activeTruthSourceIsLedger \in BOOLEAN
  /\ mainPointerDocOnly \in BOOLEAN
  /\ mainStateDocOnly \in BOOLEAN
  /\ mainRuntimeDocOnly \in BOOLEAN
  /\ publishedHeadAuthorityClaimed \in BOOLEAN
  /\ h1Allowed \in BOOLEAN

====
