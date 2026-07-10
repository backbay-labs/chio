----------- MODULE DropGuardNoRetainOnPostInvocationDenyBroken ------------
(***************************************************************************)
(* A post-invocation denial leaves the admission lease reserved instead of  *)
(* retaining it. RetainedIffAborted must reject it.                         *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
