---------------- MODULE DropGuardDiscardChildBufferBroken ----------------
(***************************************************************************)
(* The post-dispatch drop discards buffered child receipts before writing  *)
(* the parent cancellation receipt. ChildReceiptsFlushed must reject it.   *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
