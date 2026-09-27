---- MODULE PinnedTools ----
EXTENDS Naturals, TLC

CONSTANTS Tools, Hashes, Null, MaxCalls
VARIABLES approved, current, forwardedBad, parentMax, childMax, calls, blocked

Init ==
    /\ approved = [t \in Tools |-> Null]
    /\ current \in [Tools -> Hashes]
    /\ forwardedBad = FALSE
    /\ parentMax = MaxCalls
    /\ childMax \in 0..MaxCalls
    /\ calls = [t \in Tools |-> 0]
    /\ blocked = [t \in Tools |-> 0]

Approve(t, h) ==
    /\ t \in Tools
    /\ h \in Hashes
    /\ approved' = [approved EXCEPT ![t] = h]
    /\ UNCHANGED <<current, forwardedBad, parentMax, childMax, calls, blocked>>

Change(t, h) ==
    /\ t \in Tools
    /\ h \in Hashes
    /\ current' = [current EXCEPT ![t] = h]
    /\ UNCHANGED <<approved, forwardedBad, parentMax, childMax, calls, blocked>>

Forward(t) ==
    /\ t \in Tools
    /\ approved[t] = current[t]
    /\ approved[t] # Null
    /\ calls[t] < childMax
    /\ calls' = [calls EXCEPT ![t] = @ + 1]
    /\ forwardedBad' = forwardedBad
    /\ UNCHANGED <<approved, current, parentMax, childMax, blocked>>

BlockChanged(t) ==
    /\ t \in Tools
    /\ approved[t] # current[t]
    /\ calls[t] < childMax
    /\ calls' = [calls EXCEPT ![t] = @ + 1]
    /\ blocked' = [blocked EXCEPT ![t] = @ + 1]
    /\ forwardedBad' = forwardedBad
    /\ UNCHANGED <<approved, current, parentMax, childMax>>

Attenuate(n) ==
    /\ n \in 0..childMax
    /\ \A t \in Tools: calls[t] <= n
    /\ childMax' = n
    /\ UNCHANGED <<approved, current, forwardedBad, parentMax, calls, blocked>>

Next ==
    \/ \E t \in Tools, h \in Hashes: Approve(t, h)
    \/ \E t \in Tools, h \in Hashes: Change(t, h)
    \/ \E t \in Tools: Forward(t)
    \/ \E t \in Tools: BlockChanged(t)
    \/ \E n \in 0..MaxCalls: Attenuate(n)

Safe == /\ forwardedBad = FALSE /\ childMax <= parentMax
        /\ \A t \in Tools: calls[t] <= childMax
Spec == Init /\ [][Next]_<<approved, current, forwardedBad, parentMax, childMax, calls, blocked>>
====
