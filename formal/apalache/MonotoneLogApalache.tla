---------------------- MODULE MonotoneLogApalache ----------------------
(***************************************************************************)
(* Apalache-shaped port of RevocationPropagation.tla MonotoneLog.          *)
(* Receipt timestamps must strictly increase for each authority.            *)
(*                                                                          *)
(* Known modeling bound:                                                    *)
(*   `Evaluate` is the only writer of `receipt_log` and increments the      *)
(*   shared `clock` on every step, so monotonicity holds by construction in *)
(*   this bounded port. The `clock < EpochMax` guard caps real activity at  *)
(*   EpochMax - 1 = 3 evaluate steps before only Stutter remains; the       *)
(*   length=6 bound therefore exercises 3 active steps and 3 stutters. The  *)
(*   richer surface (interleaved Revoke/Propagate/Evaluate from the parent  *)
(*   RevocationPropagation.tla MonotoneLog) is checked by the TLC nightly   *)
(*   lane on MCRevocationPropagation.cfg.                                   *)
(***************************************************************************)

EXTENDS Naturals, Sequences, Common

VARIABLES
    \* @type: Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int });
    receipt_log,
    \* @type: Int;
    clock

vars == << receipt_log, clock >>

DomainsOK ==
    /\ DOMAIN receipt_log = Authorities
    /\ clock \in Ticks

Init ==
    /\ receipt_log = [a \in Authorities |-> << >>]
    /\ clock = 1

Evaluate(a, c) ==
    /\ a \in Authorities
    /\ c \in CapSet
    /\ clock < EpochMax
    /\ receipt_log' = [receipt_log EXCEPT ![a] =
          Append(@, [cap |-> c,
                     verdict |-> "allow",
                     t |-> clock,
                     seen_epoch |-> 0])]
    /\ clock' = clock + 1

Stutter ==
    UNCHANGED vars

Next ==
    \/ \E a \in Authorities, c \in CapSet : Evaluate(a, c)
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

MonotoneLogApalache ==
    \A a \in Authorities :
        \A i, j \in 1..Len(receipt_log[a]) :
            i < j => receipt_log[a][i].t < receipt_log[a][j].t

SafetyInv ==
    /\ DomainsOK
    /\ MonotoneLogApalache

=============================================================================
