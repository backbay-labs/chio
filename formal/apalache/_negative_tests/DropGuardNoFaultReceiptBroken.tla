-------------------- MODULE DropGuardNoFaultReceiptBroken ------------------
(***************************************************************************)
(* A failed pre-dispatch cleanup reaches a terminal state without writing  *)
(* its fault receipt. TerminalReceiptExactlyOne must reject it.             *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
