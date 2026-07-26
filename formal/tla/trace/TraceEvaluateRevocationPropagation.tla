------------------- MODULE TraceEvaluateRevocationPropagation -------------------
EXTENDS RevocationPropagation, TraceEvaluationInput

WitnessAllowReceipt ==
    \E a \in ProcSet :
        /\ Len(receipt_log[a]) > 0
        /\ receipt_log[a][1].verdict = "allow"

WitnessOrderedReceiptPair ==
    \E a \in ProcSet : Len(receipt_log[a]) >= 2

WitnessAttenuatedAdmission ==
    \E a \in ProcSet, c \in CapSet :
        /\ state[a][c] = "attenuated"
        /\ depth[a][c] > 0

WitnessNonzeroRevocationEpoch ==
    \E a \in ProcSet, c \in CapSet : rev_epoch[a][c] > 0

EvaluatedNoAllowAfterRevoke ==
    \A a \in ProcSet :
        \A i \in ReceiptIndexSet :
            i <= Len(receipt_log[a]) =>
                (receipt_log[a][i].verdict = "allow" =>
                    receipt_log[a][i].seen_epoch = 0)

EvaluatedMonotoneLog ==
    \A a \in ProcSet :
        \A i, j \in ReceiptIndexSet :
            /\ i <= Len(receipt_log[a])
            /\ j <= Len(receipt_log[a])
            /\ i < j
            => receipt_log[a][i].t < receipt_log[a][j].t

VARIABLES
    \* @type: Int;
    trace_index,
    \* @type: Bool;
    evaluated,
    \* @type: Bool;
    eval_no_allow_after_revoke,
    \* @type: Bool;
    eval_monotone_log,
    \* @type: Bool;
    eval_attenuation_preserving,
    \* @type: Bool;
    eval_revocation_freshness,
    \* @type: Bool;
    eval_witness_allow_receipt,
    \* @type: Bool;
    eval_witness_ordered_receipt_pair,
    \* @type: Bool;
    eval_witness_attenuated_admission,
    \* @type: Bool;
    eval_witness_nonzero_revocation_epoch

evaluation_vars ==
    << vars,
       trace_index,
       evaluated,
       eval_no_allow_after_revoke,
       eval_monotone_log,
       eval_attenuation_preserving,
       eval_revocation_freshness,
       eval_witness_allow_receipt,
       eval_witness_ordered_receipt_pair,
       eval_witness_attenuated_admission,
       eval_witness_nonzero_revocation_epoch >>

LoadInitialObservedState ==
    /\ state = ObservedStates[1].state
    /\ depth = ObservedStates[1].depth
    /\ rev_epoch = ObservedStates[1].rev_epoch
    /\ receipt_log = ObservedStates[1].receipt_log
    /\ pending = ObservedStates[1].pending
    /\ clock = ObservedStates[1].clock

LoadNextObservedState ==
    /\ state' = ObservedStates[trace_index + 1].state
    /\ depth' = ObservedStates[trace_index + 1].depth
    /\ rev_epoch' = ObservedStates[trace_index + 1].rev_epoch
    /\ receipt_log' = ObservedStates[trace_index + 1].receipt_log
    /\ pending' = ObservedStates[trace_index + 1].pending
    /\ clock' = ObservedStates[trace_index + 1].clock

TraceEvaluationInit ==
    /\ Len(ObservedStates) > 0
    /\ LoadInitialObservedState
    /\ trace_index = 1
    /\ evaluated = TRUE
    /\ eval_no_allow_after_revoke = EvaluatedNoAllowAfterRevoke
    /\ eval_monotone_log = EvaluatedMonotoneLog
    /\ eval_attenuation_preserving = AttenuationPreserving
    /\ eval_revocation_freshness = RevocationFreshness
    /\ eval_witness_allow_receipt = WitnessAllowReceipt
    /\ eval_witness_ordered_receipt_pair = WitnessOrderedReceiptPair
    /\ eval_witness_attenuated_admission = WitnessAttenuatedAdmission
    /\ eval_witness_nonzero_revocation_epoch = WitnessNonzeroRevocationEpoch

TraceEvaluationNext ==
    \/ /\ evaluated
       /\ trace_index < Len(ObservedStates)
       /\ LoadNextObservedState
       /\ trace_index' = trace_index + 1
       /\ evaluated' = FALSE
       /\ UNCHANGED << eval_no_allow_after_revoke,
                       eval_monotone_log,
                       eval_attenuation_preserving,
                       eval_revocation_freshness,
                       eval_witness_allow_receipt,
                       eval_witness_ordered_receipt_pair,
                       eval_witness_attenuated_admission,
                       eval_witness_nonzero_revocation_epoch >>
    \/ /\ ~evaluated
       /\ UNCHANGED << vars, trace_index >>
       /\ evaluated' = TRUE
       /\ eval_no_allow_after_revoke' = EvaluatedNoAllowAfterRevoke
       /\ eval_monotone_log' = EvaluatedMonotoneLog
       /\ eval_attenuation_preserving' = AttenuationPreserving
       /\ eval_revocation_freshness' = RevocationFreshness
       /\ eval_witness_allow_receipt' = WitnessAllowReceipt
       /\ eval_witness_ordered_receipt_pair' = WitnessOrderedReceiptPair
       /\ eval_witness_attenuated_admission' = WitnessAttenuatedAdmission
       /\ eval_witness_nonzero_revocation_epoch' = WitnessNonzeroRevocationEpoch

\* This calibrated export invariant becomes false only at the final input
\* state, forcing Apalache to emit one complete evaluation witness.
TraceEvaluationIncomplete == ~(trace_index = Len(ObservedStates) /\ evaluated)

================================================================================
