-------------- MODULE DistributedRevocationTemporalWitness --------------
(***************************************************************************)
(* Executable non-vacuity witness for the scalar liveness model. The final  *)
(* state has observed an issued epoch and can stutter forever with both     *)
(* weak-fairness enabledness predicates false.                              *)
(***************************************************************************)

EXTENDS DistributedRevocationTemporal

VARIABLES
    \* @type: Int;
    phase

witnessVars == <<originEpoch, observedEpoch, partitioned, cutUsed, phase>>

WitnessInit ==
    /\ Init
    /\ phase = 0

WitnessNext ==
    \/ /\ phase = 0
       /\ Revoke
       /\ phase' = 1
    \/ /\ phase = 1
       /\ Observe(originEpoch)
       /\ phase' = 2
    \/ /\ phase = 2
       /\ Stutter
       /\ UNCHANGED phase

WitnessSpec ==
    /\ WitnessInit
    /\ [][WitnessNext]_witnessVars

FairObservationWitness ==
    \/ phase < 2
    \/ /\ phase = 2
       /\ AnyOriginEpochIssued
       /\ AllIssuedEpochsObserved
       /\ ~ObserveEnabled
       /\ ~HealEnabled

=============================================================================
