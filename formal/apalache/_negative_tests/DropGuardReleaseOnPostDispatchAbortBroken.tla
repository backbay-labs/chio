------------ MODULE DropGuardReleaseOnPostDispatchAbortBroken -------------
(***************************************************************************)
(* An outcome-unknown post-dispatch path releases admission and monetary   *)
(* state even though side effects cannot be excluded. The retention        *)
(* invariant must reject it.                                               *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
