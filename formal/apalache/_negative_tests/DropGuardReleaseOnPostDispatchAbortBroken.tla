------------ MODULE DropGuardReleaseOnPostDispatchAbortBroken -------------
(***************************************************************************)
(* A post-dispatch drop releases a lease even though side effects cannot be *)
(* excluded. RetainedIffAborted must reject it.                             *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
