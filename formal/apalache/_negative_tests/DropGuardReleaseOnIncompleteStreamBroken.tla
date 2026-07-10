------------- MODULE DropGuardReleaseOnIncompleteStreamBroken -------------
(***************************************************************************)
(* An incomplete stream releases a lease after dispatch may have produced  *)
(* side effects. RetainedIffAborted must reject it.                         *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
