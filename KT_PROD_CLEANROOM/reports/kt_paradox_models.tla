---- MODULE KTParadoxMetabolism ----
EXTENDS Naturals

CONSTANT MaxHoldDays

VARIABLES state, ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth

States == {"IDLE", "SIGNALLED", "HOLD", "ESCALATED", "FAIL_CLOSED", "RESOLVED"}

Init ==
  /\ state = "IDLE"
  /\ ttlDaysRemaining = MaxHoldDays
  /\ governanceBypassAttempted = FALSE
  /\ flattenedToTrivial = FALSE
  /\ deltaGenerated = FALSE
  /\ deltaTracked = TRUE
  /\ contradictionLoopDepth = 0

Signal ==
  /\ state = "IDLE"
  /\ state' = "SIGNALLED"
  /\ contradictionLoopDepth' = contradictionLoopDepth + 1
  /\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked>>

EnterHold ==
  /\ state = "SIGNALLED"
  /\ state' = "HOLD"
  /\ ttlDaysRemaining' \in 1..MaxHoldDays
  /\ UNCHANGED <<governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Tick ==
  /\ state = "HOLD"
  /\ ttlDaysRemaining > 1
  /\ ttlDaysRemaining' = ttlDaysRemaining - 1
  /\ UNCHANGED <<state, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Escalate ==
  /\ state = "HOLD"
  /\ ttlDaysRemaining = 1
  /\ state' = "ESCALATED"
  /\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

FailClosed ==
  /\ governanceBypassAttempted \/ flattenedToTrivial
  /\ state' = "FAIL_CLOSED"
  /\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Resolve ==
  /\ state \in {"SIGNALLED", "HOLD", "ESCALATED"}
  /\ ~governanceBypassAttempted
  /\ ~flattenedToTrivial
  /\ deltaTracked
  /\ state' = "RESOLVED"
  /\ UNCHANGED <<ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

Next == Signal \/ EnterHold \/ Tick \/ Escalate \/ FailClosed \/ Resolve

NoInfiniteContradictionLoop == contradictionLoopDepth <= 1
NoIndefiniteHoldWithoutTTL == state = "HOLD" => ttlDaysRemaining \in 1..MaxHoldDays
NoGovernanceBypassUnderParadoxLoad == governanceBypassAttempted => state = "FAIL_CLOSED"
NoSilentFlatteningToTrivialAnswers == flattenedToTrivial => state = "FAIL_CLOSED"
NoUntrackedDeltaGenerationDuringResolution == deltaGenerated => deltaTracked

Spec == Init /\ [][Next]_<<state, ttlDaysRemaining, governanceBypassAttempted, flattenedToTrivial, deltaGenerated, deltaTracked, contradictionLoopDepth>>

====
