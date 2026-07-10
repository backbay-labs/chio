--------------- MODULE DropGuardSkipInvocationReversalBroken --------------
(***************************************************************************)
(* The pre-dispatch drop leaves a reserved invocation slot undisposed.      *)
(* ReservationConservation must reject it.                                 *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
