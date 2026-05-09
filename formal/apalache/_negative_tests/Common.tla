----------------------------- MODULE Common -----------------------------
(***************************************************************************)
(* Shared finite domains for the M06 Apalache kernel-state subset.          *)
(*                                                                          *)
(* The constants are supplied by each MC*.cfg file. The M06 reference       *)
(* bounds are Authorities = 1..3, CapSet = 1..6, and EpochMax = 4.          *)
(***************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    \* @type: Set(Int);
    Authorities,
    \* @type: Set(Int);
    CapSet,
    \* @type: Int;
    EpochMax

ASSUME
    /\ Authorities = 1..3
    /\ CapSet = 1..6
    /\ EpochMax = 4

Epochs == 0..EpochMax
Ticks == 1..EpochMax
CapSet0 == CapSet \cup {0}
Verdicts == {"allow", "deny"}

Receipt == [cap: CapSet, verdict: Verdicts, t: Epochs, seen_epoch: Epochs]

=============================================================================
