-------------- MODULE DropGuardSkipChildBudgetReleaseBroken --------------
(***************************************************************************)
(* The pre-dispatch drop leaves a reserved child budget undisposed.         *)
(* ReservationConservation must reject it.                                 *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
