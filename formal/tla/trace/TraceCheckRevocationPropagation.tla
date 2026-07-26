-------------------- MODULE TraceCheckRevocationPropagation --------------------
EXTENDS RevocationPropagation, TraceInput

VARIABLES
    \* @type: Int;
    trace_index,
    \* @type: Bool;
    accepted

trace_vars == << vars, trace_index, accepted >>

\* @type: ({ authority: Int, cap: Int, epoch: Int, kind: Str, receipt_time: Int, seen_epoch: Int, sequence: Int, verdict: Str }) => { cap: Int, verdict: Str, t: Int, seen_epoch: Int };
ProjectedReceipt(event) ==
    [ cap        |-> event.cap,
      verdict    |-> event.verdict,
      t          |-> event.receipt_time,
      seen_epoch |-> event.seen_epoch ]

\* @type: ({ authority: Int, cap: Int, epoch: Int, kind: Str, receipt_time: Int, seen_epoch: Int, sequence: Int, verdict: Str }) => Bool;
ObservedRevoke(event) ==
    /\ event.kind = "revoke"
    /\ clock = event.sequence
    /\ Revoke(event.authority, event.cap)
    /\ rev_epoch'[event.authority][event.cap] = event.epoch

\* @type: ({ authority: Int, cap: Int, epoch: Int, kind: Str, receipt_time: Int, seen_epoch: Int, sequence: Int, verdict: Str }) => Bool;
ObservedEvaluate(event) ==
    /\ event.kind = "evaluate"
    /\ clock = event.sequence
    /\ Evaluate(event.authority, event.cap)
    /\ receipt_log'[event.authority][Len(receipt_log'[event.authority])] =
         ProjectedReceipt(event)

\* @type: ({ authority: Int, cap: Int, epoch: Int, kind: Str, receipt_time: Int, seen_epoch: Int, sequence: Int, verdict: Str }) => Bool;
ObservedStep(event) ==
    \/ ObservedRevoke(event)
    \/ ObservedEvaluate(event)

TraceHidden ==
    \/ PropagateAny
    \/ \E a \in ProcSet, c \in CapSet : Attenuate(a, c)

TraceInit ==
    /\ Init
    /\ trace_index = 0
    /\ accepted = FALSE

TraceNext ==
    \/ /\ trace_index < Len(ObservedTrace)
       /\ ObservedStep(ObservedTrace[trace_index + 1])
       /\ trace_index' = trace_index + 1
       /\ accepted' = FALSE
    \/ /\ trace_index < Len(ObservedTrace)
       /\ TraceHidden
       /\ UNCHANGED << trace_index, accepted >>
    \/ /\ trace_index = Len(ObservedTrace)
       /\ ~accepted
       /\ accepted' = TRUE
       /\ UNCHANGED << vars, trace_index >>

TraceNotAccepted == ~accepted

================================================================================
