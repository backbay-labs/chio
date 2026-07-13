-------------- MODULE DistributedRevocationTemporalRefinement --------------
(***************************************************************************)
(* Bounded refinement from the full distributed temporal relation to one   *)
(* selected ordered authority pair. Unrelated full-model actions map to     *)
(* scalar stuttering; delivery and catch-up map to partial or complete      *)
(* observation advances.                                                   *)
(***************************************************************************)

EXTENDS DistributedRevocation

CONSTANTS
    \* @type: Int;
    SelectedOrigin,
    \* @type: Int;
    SelectedReceiver

ASSUME
    /\ SelectedOrigin \in Authorities
    /\ SelectedReceiver \in Authorities
    /\ SelectedOrigin # SelectedReceiver

Scalar == INSTANCE DistributedRevocationTemporal
    WITH EpochMax <- EpochMax,
         originEpoch <- originEpoch[SelectedOrigin],
         observedEpoch <- hwm[SelectedReceiver][SelectedOrigin],
         partitioned <- ~IsConnected(SelectedReceiver, SelectedOrigin),
         cutUsed <- <<SelectedReceiver, SelectedOrigin>> \in cutUsed

TemporalProjectionRefines == Scalar!Spec

=============================================================================
