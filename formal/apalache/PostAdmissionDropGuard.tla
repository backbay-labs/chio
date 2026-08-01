---------------------- MODULE PostAdmissionDropGuard ----------------------
(***************************************************************************)
(* Bounded lifecycle model for an armed post-admission drop guard.          *)
(*                                                                          *)
(* Action                 Rust implementation                               *)
(* Admit                  evaluate_tool_call_async_with_session_context;   *)
(*                        evaluate_tool_call_with_nested_flow_client_async; *)
(*                        reserve_dispatch_credentials;                    *)
(*                        evaluate_runtime_admission_tracked;               *)
(*                        PostAdmissionDropGuard::new                       *)
(* StartDispatch          ChioKernel::revalidate_immediately_before_dispatch; *)
(*                        PostAdmissionDropGuard::mark_dispatch_started    *)
(* StreamChunk            PostAdmissionDropGuard::child_receipts_mut;      *)
(*                        SessionNestedFlowBridge                          *)
(* CompleteOk             record_buffered_child_receipts;                  *)
(*                        DispatchCredentialReservation::commit;           *)
(*                        PostAdmissionDropGuard::disarm;                  *)
(*                        finalize_tool_output_with_metadata_and_payee_binding; *)
(*                        record_chio_receipt_with_federation               *)
(* DenyPostInvocation     finalize_tool_output_with_metadata_and_payee_binding *)
(* IncompleteStream       finalize_tool_output_with_metadata_and_payee_binding *)
(* ServerErrorPostDispatch ambiguous_dispatch_receipt_metadata;            *)
(*                        retained_admission_receipt_metadata;             *)
(*                        record_chio_receipt_with_mode                     *)
(* DropPreDispatch        PostAdmissionDropGuard::handle_pre_dispatch_drop; *)
(*                        record_pre_dispatch_cleanup_fault_receipt;        *)
(*                        ChioRuntimeAdmissionHook::release_reservations;   *)
(*                        ChioRuntimeAdmissionHook::release_reserved;       *)
(*                        PostAdmissionDropGuard::drop                      *)
(* DropPostDispatch       PostAdmissionDropGuard::drop;                    *)
(*                        DispatchCredentialReservation::commit;           *)
(*                        mark_dispatch_credential_commit_failed;          *)
(*                        flush_buffered_child_receipts_from_drop;          *)
(*                        ambiguous_dispatch_receipt_metadata               *)
(*                                                                          *)
(* The model separates receipt persistence from resource disposition.       *)
(* Admission profiles are budget mutation (none, hold, or slot) x runtime  *)
(* lease x child budget. Hold and slot are mutually exclusive in Rust.      *)
(* Child receipts are appended before the parent terminal receipt. A        *)
(* successful child-store append is assumed by the state transitions. Rust  *)
(* retries only the not-attempted suffix. An outcome-unknown child append is *)
(* removed from the retry buffer and embedded in cancellation metadata. The *)
(* persistence-failure branches are outside ChildReceiptsFlushed.            *)
(*                                                                          *)
(* Parent append acknowledgement is modeled independently from durable      *)
(* presence: not-attempted, outcome-unknown, or committed. An unknown        *)
(* acknowledgement may mean zero or one durable parent receipt. Once an      *)
(* attempt starts, terminal Drop handling does not append a second receipt.  *)
(* TerminalReceiptExactlyOne therefore gives exactly one receipt under a     *)
(* committed acknowledgement and at most one under an unknown outcome.       *)
(* Pre-dispatch cleanup failure retains only the failed resources and       *)
(* emits one fault receipt. A returned output reaches finalization after     *)
(* budget reconciliation, so its hold is committed. A server error or       *)
(* dropped future retains the hold because tool effects cannot be excluded.  *)
(* A credential commit failure after a returned output keeps the guard armed *)
(* and follows DropPostDispatch, with signed cancellation and retention.      *)
(* Payment-adapter authorization is outside this four-resource ledger.       *)
(* Production retains it only for those outcome-unknown paths.               *)
(* The aggregate lease conservatively projects destructive, treaty, and     *)
(* swarm reservation identifiers. A release error or panic is projected as  *)
(* retained or possibly stuck, and the concrete callback is not retried.     *)
(* Exact per-identifier ownership after mutate-then-error is outside this    *)
(* abstraction.                                                             *)
(* Every Err returned after polling any invoke path is outcome-unknown.     *)
(* URL elicitation follows this rule regardless of nested bridge activity.  *)
(* Only a kernel error before polling invoke is pre-dispatch and reversible. *)
(* Cleanup failures range over the 12 valid resource profiles, filtered     *)
(* to subsets of the resources admitted for that invocation. This static    *)
(* domain keeps every independent outcome visible to Apalache 0.50.1.       *)
(*                                                                          *)
(* The initial receipt-sequence encoding expanded every index at every      *)
(* transition under Apalache 0.50.1. This bounded model uses exact per-      *)
(* invocation counters plus a child-before-parent witness instead. The      *)
(* structural gate pins the child update before the parent update.          *)
(* Invocation 1 explores every local admission and cleanup outcome.         *)
(* Invocation 2 uses a fixed maximal non-monetary profile and the            *)
(* dispatch-to-drop path. It covers arbitrary ordering of two independently *)
(* keyed lifecycles plus their shared child-share capacity. Receipt counters *)
(* remain per invocation.                                                    *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

(***************************************************************************)
(* Reservation law (normative text in chio-kernel/src/budget_store.rs):    *)
(* 1. Partition: reserved amount equals committed plus released plus        *)
(*    retained plus outstanding at every reachable state, and outstanding  *)
(*    is nonnegative.                                                       *)
(* 2. Terminal uniqueness: a terminal admission has no outstanding amount  *)
(*    and exactly one terminal classification.                             *)
(* 3. Child splits: admitted sibling shares never exceed the parent share, *)
(*    and every child independently obeys clauses 1 and 2.                 *)
(*                                                                         *)
(* Equivalent checks are maintained in                                     *)
(* chio-kernel-core/src/formal_aeneas.rs,                                   *)
(* chio-kernel/src/kernel/ledger_audit.rs, and                              *)
(* chio-kernel/tests/property_reservation_ledger.rs.                        *)
(***************************************************************************)

CONSTANTS
    \* @type: Set(Int);
    Invocations,
    \* @type: Int;
    ChildMax,
    \* @type: Str;
    Mutation

Resources == {"hold", "slot", "lease", "child"}
BudgetMax == 4
AdmissionProfiles == {
    {},
    {"lease"},
    {"child"},
    {"lease", "child"},
    {"hold"},
    {"slot"},
    {"hold", "lease"},
    {"slot", "lease"},
    {"hold", "child"},
    {"slot", "child"},
    {"hold", "lease", "child"},
    {"slot", "lease", "child"}
}
CleanupFailureProfiles == AdmissionProfiles
AdmissionProfilesFor(i) ==
    IF i = 1
    THEN AdmissionProfiles
    ELSE {{"slot", "lease", "child"}}

Phases == {
    "idle",
    "admitted",
    "dispatch_started",
    "streaming",
    "terminal_ok",
    "terminal_denied",
    "terminal_unwound",
    "terminal_fault"
}
TerminalKinds == {"none", "allow", "deny", "incomplete", "cancel", "fault", "unwound"}
ParentReceiptKinds == {"allow", "deny", "incomplete", "cancel", "fault"}
ParentAppendStates == {"not-attempted", "outcome-unknown", "committed"}
ServerErrorKinds == {"deny", "incomplete", "cancel", "url"}
RecordedServerErrorKinds == ServerErrorKinds \cup {"none"}
Mutations == {
    "none",
    "discard-child-buffer",
    "skip-child-release",
    "skip-slot-release",
    "omit-fault-receipt",
    "release-incomplete-lease",
    "skip-deny-retention",
    "release-post-dispatch-state",
    "skip-child-capacity-guard"
}

ASSUME
    /\ Invocations = 1..2
    /\ ChildMax = 1
    /\ Mutation \in Mutations

VARIABLES
    \* @type: Int -> Str;
    phase,
    \* @type: Int -> (Str -> Str);
    ledger,
    \* @type: Int -> Set(Str);
    admitted_resources,
    \* @type: Int -> Set(Str);
    unwind_failed,
    \* @type: Int -> Int;
    child_buf,
    \* @type: Int -> Int;
    child_total,
    \* @type: Int -> Int;
    child_logged,
    \* @type: Int -> Int;
    parent_receipts,
    \* @type: Int -> Int;
    parent_append_attempts,
    \* @type: Int -> Str;
    parent_append_state,
    \* @type: Int -> Str;
    parent_kind_logged,
    \* @type: Int -> Bool;
    children_before_parent,
    \* @type: Int -> Bool;
    post_dispatch_outcome_unknown,
    \* @type: Int -> Str;
    server_error_kind,
    \* @type: Int -> Bool;
    nested_bridge_active_at_error,
    \* @type: Int -> Str;
    terminal_kind

vars == <<
    phase,
    ledger,
    admitted_resources,
    unwind_failed,
    child_buf,
    child_total,
    child_logged,
    parent_receipts,
    parent_append_attempts,
    parent_append_state,
    parent_kind_logged,
    children_before_parent,
    post_dispatch_outcome_unknown,
    server_error_kind,
    nested_bridge_active_at_error,
    terminal_kind
>>

CleanupFailureSets(i) ==
    IF i = 1
    THEN CleanupFailureProfiles
    ELSE {{}}

ParentAppendOutcomes(i) ==
    IF i = 1
    THEN {"outcome-unknown", "committed"}
    ELSE {"committed"}

ParentPersistenceOutcomes(append_outcome) ==
    IF append_outcome = "committed"
    THEN {TRUE}
    ELSE BOOLEAN

ServerErrorReceiptKind(error_kind) ==
    IF error_kind = "url" THEN "incomplete" ELSE error_kind

IsTerminal(i) == phase[i] \in {
    "terminal_ok",
    "terminal_denied",
    "terminal_unwound",
    "terminal_fault"
}

StatusAmount(i, status) ==
    Cardinality({resource \in admitted_resources[i] : ledger[i][resource] = status})

ReservedAmount(i) == Cardinality(admitted_resources[i])

CountedLedger(i) == [
    outstanding |-> StatusAmount(i, "reserved"),
    committed |-> StatusAmount(i, "committed"),
    released |-> StatusAmount(i, "released"),
    retained |-> StatusAmount(i, "retained")
]

CountedLedgerDomains ==
    \A i \in Invocations :
        /\ ReservedAmount(i) \in 0..BudgetMax
        /\ CountedLedger(i).outstanding \in 0..BudgetMax
        /\ CountedLedger(i).committed \in 0..BudgetMax
        /\ CountedLedger(i).released \in 0..BudgetMax
        /\ CountedLedger(i).retained \in 0..BudgetMax

PartitionAtEveryState ==
    \A i \in Invocations :
        ReservedAmount(i) =
            CountedLedger(i).committed
            + CountedLedger(i).released
            + CountedLedger(i).retained
            + CountedLedger(i).outstanding

ActiveChildShares ==
    Cardinality({i \in Invocations :
        /\ "child" \in admitted_resources[i]
        /\ ledger[i]["child"] \notin {"none", "released"}})

ChildSplitsBounded == ActiveChildShares <= ChildMax

ResolveAll(current, disposition) ==
    [resource \in Resources |->
        IF current[resource] = "reserved"
        THEN disposition
        ELSE current[resource]]

ResolveReturnedOutput(current, kind) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource = "lease"
        THEN
            IF /\ kind = "incomplete"
               /\ Mutation = "release-incomplete-lease"
            THEN "released"
            ELSE IF /\ kind = "deny"
                    /\ Mutation = "skip-deny-retention"
            THEN "reserved"
            ELSE "retained"
        ELSE "committed"]

ResolvePreDispatch(current, failed) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource \in failed
        THEN "retained"
        ELSE IF /\ resource = "child"
                /\ Mutation = "skip-child-release"
        THEN "reserved"
        ELSE IF /\ resource = "slot"
                /\ Mutation = "skip-slot-release"
        THEN "reserved"
        ELSE "released"]

ResolvePostDispatch(current) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource \in {"lease", "hold"}
        THEN
            IF Mutation = "release-post-dispatch-state"
            THEN "released"
            ELSE "retained"
        ELSE "committed"]

DomainsOK ==
    /\ Mutation \in Mutations
    /\ \A i \in Invocations :
        /\ phase[i] \in Phases
        /\ admitted_resources[i] \subseteq Resources
        /\ unwind_failed[i] \subseteq admitted_resources[i]
        /\ child_buf[i] \in 0..ChildMax
        /\ child_total[i] \in 0..ChildMax
        /\ child_buf[i] <= child_total[i]
        /\ child_logged[i] \in 0..ChildMax
        /\ child_logged[i] <= child_total[i]
        /\ parent_receipts[i] \in 0..1
        /\ parent_append_attempts[i] \in 0..1
        /\ parent_append_state[i] \in ParentAppendStates
        /\ parent_kind_logged[i] \in TerminalKinds
        /\ children_before_parent[i] \in BOOLEAN
        /\ post_dispatch_outcome_unknown[i] \in BOOLEAN
        /\ server_error_kind[i] \in RecordedServerErrorKinds
        /\ nested_bridge_active_at_error[i] \in BOOLEAN
        /\ terminal_kind[i] \in TerminalKinds

Init ==
    /\ phase = [i \in Invocations |-> "idle"]
    /\ ledger = [i \in Invocations |-> [resource \in Resources |-> "none"]]
    /\ admitted_resources = [i \in Invocations |-> {}]
    /\ unwind_failed = [i \in Invocations |-> {}]
    /\ child_buf = [i \in Invocations |-> 0]
    /\ child_total = [i \in Invocations |-> 0]
    /\ child_logged = [i \in Invocations |-> 0]
    /\ parent_receipts = [i \in Invocations |-> 0]
    /\ parent_append_attempts = [i \in Invocations |-> 0]
    /\ parent_append_state = [i \in Invocations |-> "not-attempted"]
    /\ parent_kind_logged = [i \in Invocations |-> "none"]
    /\ children_before_parent = [i \in Invocations |-> TRUE]
    /\ post_dispatch_outcome_unknown = [i \in Invocations |-> FALSE]
    /\ server_error_kind = [i \in Invocations |-> "none"]
    /\ nested_bridge_active_at_error = [i \in Invocations |-> FALSE]
    /\ terminal_kind = [i \in Invocations |-> "none"]

Admit(i) ==
    /\ phase[i] = "idle"
    /\ \E resources \in AdmissionProfilesFor(i) :
        /\ IF "child" \in resources
           THEN \/ ActiveChildShares < ChildMax
                \/ Mutation = "skip-child-capacity-guard"
           ELSE TRUE
        /\ phase' = [phase EXCEPT ![i] = "admitted"]
        /\ ledger' = [ledger EXCEPT ![i] =
            [resource \in Resources |->
                IF resource \in resources THEN "reserved" ELSE "none"]]
        /\ admitted_resources' = [admitted_resources EXCEPT ![i] = resources]
        /\ unwind_failed' = [unwind_failed EXCEPT ![i] = {}]
        /\ child_buf' = [child_buf EXCEPT ![i] = 0]
        /\ child_total' = [child_total EXCEPT ![i] = 0]
        /\ child_logged' = [child_logged EXCEPT ![i] = 0]
        /\ parent_receipts' = [parent_receipts EXCEPT ![i] = 0]
        /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = 0]
        /\ parent_append_state' = [parent_append_state EXCEPT ![i] = "not-attempted"]
        /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "none"]
        /\ children_before_parent' = [children_before_parent EXCEPT ![i] = TRUE]
        /\ post_dispatch_outcome_unknown' =
            [post_dispatch_outcome_unknown EXCEPT ![i] = FALSE]
        /\ server_error_kind' = [server_error_kind EXCEPT ![i] = "none"]
        /\ nested_bridge_active_at_error' =
            [nested_bridge_active_at_error EXCEPT ![i] = FALSE]
        /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "none"]

StartDispatch(i) ==
    /\ phase[i] = "admitted"
    /\ phase' = [phase EXCEPT ![i] = "dispatch_started"]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_buf,
                     child_total, child_logged, parent_receipts,
                     parent_append_attempts, parent_append_state,
                     parent_kind_logged, children_before_parent,
                     post_dispatch_outcome_unknown, server_error_kind,
                     nested_bridge_active_at_error, terminal_kind >>

StreamChunk(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ child_buf[i] < ChildMax
    /\ phase' = [phase EXCEPT ![i] = "streaming"]
    /\ child_buf' = [child_buf EXCEPT ![i] = @ + 1]
    /\ child_total' = [child_total EXCEPT ![i] = @ + 1]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_logged,
                     parent_receipts, parent_append_attempts,
                     parent_append_state, parent_kind_logged,
                     children_before_parent, post_dispatch_outcome_unknown,
                     server_error_kind, nested_bridge_active_at_error,
                     terminal_kind >>

CompleteOk(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_ok"]
            /\ ledger' = [ledger EXCEPT ![i] = ResolveAll(@, "committed")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "allow" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "allow"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

DenyPostInvocation(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
            /\ ledger' = [ledger EXCEPT ![i] =
                ResolveReturnedOutput(@, "deny")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "deny" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "deny"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

IncompleteStream(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
            /\ ledger' = [ledger EXCEPT ![i] =
                ResolveReturnedOutput(@, "incomplete")]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "incomplete" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                child_logged[i] + child_buf[i] = child_total[i]]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "incomplete"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             post_dispatch_outcome_unknown, server_error_kind,
                             nested_bridge_active_at_error >>

ServerErrorPostDispatch(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E error_kind \in ServerErrorKinds :
        /\ \E nested_bridge_active \in BOOLEAN :
            /\ \E append_outcome \in ParentAppendOutcomes(i) :
                /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
                    LET receipt_kind == ServerErrorReceiptKind(error_kind)
                    IN
                    /\ phase' = [phase EXCEPT ![i] =
                        IF receipt_kind = "cancel"
                        THEN "terminal_fault"
                        ELSE "terminal_denied"]
                    /\ ledger' = [ledger EXCEPT ![i] = ResolvePostDispatch(@)]
                    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
                    /\ child_logged' =
                        [child_logged EXCEPT ![i] = @ + child_buf[i]]
                    /\ parent_append_attempts' =
                        [parent_append_attempts EXCEPT ![i] = @ + 1]
                    /\ parent_append_state' =
                        [parent_append_state EXCEPT ![i] = append_outcome]
                    /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                        @ + IF append_persisted THEN 1 ELSE 0]
                    /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                        IF append_persisted THEN receipt_kind ELSE "none"]
                    /\ children_before_parent' =
                        [children_before_parent EXCEPT ![i] =
                            child_logged[i] + child_buf[i] = child_total[i]]
                    /\ post_dispatch_outcome_unknown' =
                        [post_dispatch_outcome_unknown EXCEPT ![i] = TRUE]
                    /\ server_error_kind' =
                        [server_error_kind EXCEPT ![i] = error_kind]
                    /\ nested_bridge_active_at_error' =
                        [nested_bridge_active_at_error EXCEPT
                            ![i] = nested_bridge_active]
                    /\ terminal_kind' =
                        [terminal_kind EXCEPT ![i] = receipt_kind]
                    /\ UNCHANGED << admitted_resources, unwind_failed,
                                     child_total >>

DropPreDispatch(i) ==
    /\ i = 1
    /\ phase[i] = "admitted"
    /\ \E failed \in CleanupFailureSets(i) :
        /\ failed \subseteq admitted_resources[i]
        /\ ledger' = [ledger EXCEPT ![i] = ResolvePreDispatch(@, failed)]
        /\ unwind_failed' = [unwind_failed EXCEPT ![i] = failed]
        /\ IF failed = {}
           THEN
                /\ phase' = [phase EXCEPT ![i] = "terminal_unwound"]
                /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "unwound"]
                /\ UNCHANGED << parent_receipts, parent_append_attempts,
                                 parent_append_state, parent_kind_logged >>
           ELSE
                /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
                /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "fault"]
                /\ IF Mutation = "omit-fault-receipt"
                   THEN UNCHANGED << parent_receipts, parent_append_attempts,
                                    parent_append_state, parent_kind_logged >>
                   ELSE
                        /\ parent_append_state[i] = "not-attempted"
                        /\ \E append_outcome \in ParentAppendOutcomes(i) :
                            /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
                                /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
                                /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
                                /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                                    @ + IF append_persisted THEN 1 ELSE 0]
                                /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                                    IF append_persisted THEN "fault" ELSE "none"]
        /\ UNCHANGED << admitted_resources, child_buf, child_total,
                         child_logged, children_before_parent,
                         post_dispatch_outcome_unknown, server_error_kind,
                         nested_bridge_active_at_error >>

DropPostDispatch(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ parent_append_state[i] = "not-attempted"
    /\ \E append_outcome \in ParentAppendOutcomes(i) :
        /\ \E append_persisted \in ParentPersistenceOutcomes(append_outcome) :
            LET flushed_count ==
                    IF Mutation = "discard-child-buffer"
                    THEN child_logged[i]
                    ELSE child_logged[i] + child_buf[i]
            IN
            /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
            /\ ledger' = [ledger EXCEPT ![i] = ResolvePostDispatch(@)]
            /\ child_buf' = [child_buf EXCEPT ![i] = 0]
            /\ child_logged' = [child_logged EXCEPT ![i] = flushed_count]
            /\ parent_append_attempts' = [parent_append_attempts EXCEPT ![i] = @ + 1]
            /\ parent_append_state' = [parent_append_state EXCEPT ![i] = append_outcome]
            /\ parent_receipts' = [parent_receipts EXCEPT ![i] =
                @ + IF append_persisted THEN 1 ELSE 0]
            /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] =
                IF append_persisted THEN "cancel" ELSE "none"]
            /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
                flushed_count = child_total[i]]
            /\ post_dispatch_outcome_unknown' =
                [post_dispatch_outcome_unknown EXCEPT ![i] = TRUE]
            /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "cancel"]
            /\ UNCHANGED << admitted_resources, unwind_failed, child_total,
                             server_error_kind,
                             nested_bridge_active_at_error >>

Next ==
    \/ \E i \in Invocations : Admit(i)
    \/ \E i \in Invocations : StartDispatch(i)
    \/ \E i \in Invocations : StreamChunk(i)
    \/ \E i \in Invocations : CompleteOk(i)
    \/ \E i \in Invocations : DenyPostInvocation(i)
    \/ \E i \in Invocations : IncompleteStream(i)
    \/ \E i \in Invocations : ServerErrorPostDispatch(i)
    \/ \E i \in Invocations : DropPreDispatch(i)
    \/ \E i \in Invocations : DropPostDispatch(i)

Spec ==
    /\ Init
    /\ [][Next]_vars

ReservationConservation ==
    /\ CountedLedgerDomains
    /\ PartitionAtEveryState
    /\ ChildSplitsBounded
    /\ \A i \in Invocations :
        IsTerminal(i) => CountedLedger(i).outstanding = 0

TerminalReceiptExactlyOne ==
    \A i \in Invocations :
        /\ parent_append_state[i] = "not-attempted" =>
            /\ parent_append_attempts[i] = 0
            /\ parent_receipts[i] = 0
            /\ parent_kind_logged[i] = "none"
        /\ parent_append_state[i] = "committed" =>
            /\ parent_append_attempts[i] = 1
            /\ parent_receipts[i] = 1
            /\ parent_kind_logged[i] = terminal_kind[i]
            /\ terminal_kind[i] \in ParentReceiptKinds
        /\ parent_append_state[i] = "outcome-unknown" =>
            /\ parent_append_attempts[i] = 1
            /\ parent_receipts[i] \in 0..1
            /\ parent_kind_logged[i] =
                IF parent_receipts[i] = 1 THEN terminal_kind[i] ELSE "none"
            /\ terminal_kind[i] \in ParentReceiptKinds
        /\ terminal_kind[i] \in {"none", "unwound"} =>
            parent_append_state[i] = "not-attempted"
        /\ terminal_kind[i] \in ParentReceiptKinds =>
            parent_append_state[i] \in {"outcome-unknown", "committed"}

ChildReceiptsFlushed ==
    \A i \in Invocations :
        IsTerminal(i) =>
            /\ child_buf[i] = 0
            /\ child_logged[i] = child_total[i]
            /\ children_before_parent[i]

RetainedIffAborted ==
    \A i \in Invocations :
        /\ ( (ledger[i]["lease"] = "retained") <=>
             ( /\ "lease" \in admitted_resources[i]
               /\ \/ terminal_kind[i] \in {"deny", "incomplete", "cancel"}
                  \/ "lease" \in unwind_failed[i] ) )
        /\ ( (ledger[i]["hold"] = "retained") <=>
             ( /\ "hold" \in admitted_resources[i]
               /\ \/ post_dispatch_outcome_unknown[i]
                  \/ "hold" \in unwind_failed[i] ) )
        /\ (server_error_kind[i] = "url") =>
            /\ post_dispatch_outcome_unknown[i]
            /\ terminal_kind[i] = "incomplete"
            /\ phase[i] = "terminal_denied"

SafetyInv ==
    /\ DomainsOK
    /\ ReservationConservation
    /\ TerminalReceiptExactlyOne
    /\ ChildReceiptsFlushed
    /\ RetainedIffAborted

=============================================================================
