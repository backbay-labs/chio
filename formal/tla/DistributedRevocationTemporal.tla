------------------ MODULE DistributedRevocationTemporal ------------------
(***************************************************************************)
(* Conditional liveness for one arbitrary ordered authority pair.         *)
(*                                                                         *)
(* A separate bounded refinement check maps the full distributed temporal  *)
(* relation into this arbitrary-pair state. Transport and evaluation steps *)
(* omitted here either stutter or advance the remote high-water mark.       *)
(*                                                                         *)
(* Apalache 0.50.1 does not encode WF operators or ENABLED in temporal     *)
(* properties. ObserveWeakFair and HealWeakFair expand weak fairness into  *)
(* primitive temporal logic using exact state-derived enabledness. No      *)
(* finite delivery-step or evaluation-count bound is introduced.          *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
    \* @type: Int;
    EpochMax

Epochs == 1..EpochMax

ASSUME EpochMax >= 2

VARIABLES
    \* @type: Int;
    originEpoch,
    \* @type: Int;
    observedEpoch,
    \* @type: Bool;
    partitioned,
    \* @type: Bool;
    cutUsed

vars == <<originEpoch, observedEpoch, partitioned, cutUsed>>

Init ==
    /\ originEpoch = 0
    /\ observedEpoch = 0
    /\ partitioned = FALSE
    /\ cutUsed = FALSE

Revoke ==
    /\ originEpoch < EpochMax
    /\ originEpoch' = originEpoch + 1
    /\ UNCHANGED <<observedEpoch, partitioned, cutUsed>>

Observe(e) ==
    /\ e \in Epochs
    /\ ~partitioned
    /\ e > observedEpoch
    /\ e <= originEpoch
    /\ observedEpoch' = e
    /\ UNCHANGED <<originEpoch, partitioned, cutUsed>>

CutOnce ==
    /\ ~partitioned
    /\ ~cutUsed
    /\ partitioned' = TRUE
    /\ cutUsed' = TRUE
    /\ UNCHANGED <<originEpoch, observedEpoch>>

Heal ==
    /\ partitioned
    /\ partitioned' = FALSE
    /\ UNCHANGED <<originEpoch, observedEpoch, cutUsed>>

Stutter == UNCHANGED vars

Next ==
    \/ Revoke
    \/ \E e \in Epochs : Observe(e)
    \/ CutOnce
    \/ Heal
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

AnyOriginEpochIssued ==
    \E e \in Epochs : originEpoch >= e

AllIssuedEpochsObserved ==
    \A e \in Epochs : originEpoch >= e => observedEpoch >= e

ObserveProgressAction == observedEpoch' > observedEpoch

ObserveEnabled == ~partitioned /\ originEpoch > observedEpoch

HealProgressAction == partitioned /\ ~partitioned'

HealEnabled == partitioned

ObserveWeakFair ==
    \/ <>[](~ObserveEnabled)
    \/ []<><<ObserveProgressAction>>_observedEpoch

HealWeakFair ==
    \/ <>[](~HealEnabled)
    \/ []<><<HealProgressAction>>_partitioned

TemporalFairness ==
    /\ ObserveWeakFair
    /\ HealWeakFair

RevocationEventuallyObservedDistributed ==
    TemporalFairness => (AnyOriginEpochIssued ~> AllIssuedEpochsObserved)

=============================================================================
