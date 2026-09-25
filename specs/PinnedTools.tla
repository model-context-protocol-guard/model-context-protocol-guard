---- MODULE PinnedTools ----
EXTENDS Naturals, TLC

CONSTANTS Tools, Hashes, Null, MaxCalls
VARIABLES approved, current, forwardedBad, parentMax, childMax

Init ==
    /\ approved = [t \in Tools |-> Null]
    /\ current \in [Tools -> Hashes]
    /\ forwardedBad = FALSE
    /\ parentMax = MaxCalls
    /\ childMax \in 0..MaxCalls

Approve(t, h) ==
    /\ t \in Tools
    /\ h \in Hashes
    /\ approved' = [approved EXCEPT ![t] = h]
    /\ UNCHANGED <<current, forwardedBad, parentMax, childMax>>

Change(t, h) ==
    /\ t \in Tools
    /\ h \in Hashes
    /\ current' = [current EXCEPT ![t] = h]
    /\ UNCHANGED <<approved, forwardedBad, parentMax, childMax>>

Forward(t) ==
    /\ t \in Tools
    /\ approved[t] = current[t]
    /\ approved[t] # Null
    /\ forwardedBad' = forwardedBad
    /\ UNCHANGED <<approved, current, parentMax, childMax>>

BlockChanged(t) ==
    /\ t \in Tools
    /\ approved[t] # current[t]
    /\ forwardedBad' = forwardedBad
    /\ UNCHANGED <<approved, current, parentMax, childMax>>

Attenuate(n) ==
    /\ n \in 0..childMax
    /\ childMax' = n
    /\ UNCHANGED <<approved, current, forwardedBad, parentMax>>

Next ==
    \/ \E t \in Tools, h \in Hashes: Approve(t, h)
    \/ \E t \in Tools, h \in Hashes: Change(t, h)
    \/ \E t \in Tools: Forward(t)
    \/ \E t \in Tools: BlockChanged(t)
    \/ \E n \in 0..MaxCalls: Attenuate(n)

Safe == /\ forwardedBad = FALSE /\ childMax <= parentMax
Spec == Init /\ [][Next]_<<approved, current, forwardedBad, parentMax, childMax>>
====
