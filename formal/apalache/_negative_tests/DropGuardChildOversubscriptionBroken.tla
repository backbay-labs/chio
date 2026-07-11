-------------- MODULE DropGuardChildOversubscriptionBroken --------------
(***************************************************************************)
(* Child admission ignores the shared active-share capacity guard.          *)
(* ReservationConservation must reject the resulting sibling oversubscription. *)
(***************************************************************************)

EXTENDS PostAdmissionDropGuard

=============================================================================
