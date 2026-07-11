---------------------- MODULE PostAdmissionDropGuard ----------------------
(***************************************************************************)
(* Bounded lifecycle model for an armed post-admission drop guard.          *)
(*                                                                          *)
(* Action                 Rust implementation                               *)
(* Admit                  kernel_drop_guard.rs:86-109                       *)
(* StartDispatch          kernel_drop_guard.rs:130-132                      *)
(* StreamChunk            kernel_drop_guard.rs:115-117                      *)
(* CompleteOk             kernel_drop_guard.rs:122-136;                     *)
(*                        responses/finalization.rs:54-69                   *)
(* DenyPostInvocation     responses/finalization.rs:36-51                   *)
(* IncompleteStream       responses/finalization.rs:70-85                   *)
(* DropPreDispatch        kernel_drop_guard.rs:180-308,385-392              *)
(* DropPostDispatch       kernel_drop_guard.rs:379-438                      *)
(*                                                                          *)
(* The model separates receipt persistence from resource disposition.       *)
(* Admission profiles are budget mutation (none, hold, or slot) x runtime  *)
(* lease x child budget. Hold and slot are mutually exclusive in Rust.      *)
(* Child receipts are appended before the parent terminal receipt. A        *)
(* pre-dispatch cleanup failure retains only the failed resources and       *)
(* emits one fault receipt. A post-dispatch monetary unwind may fail; that   *)
(* outcome leaves the hold retained while all other terminal resources      *)
(* still reach an explicit disposition.                                    *)
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
Mutations == {
    "none",
    "discard-child-buffer",
    "skip-child-release",
    "skip-slot-release",
    "omit-fault-receipt",
    "release-incomplete-lease",
    "skip-deny-retention",
    "release-post-dispatch-lease",
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
    \* @type: Int -> Str;
    parent_kind_logged,
    \* @type: Int -> Bool;
    children_before_parent,
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
    parent_kind_logged,
    children_before_parent,
    terminal_kind
>>

CleanupFailureSets(i) ==
    IF i = 1
    THEN CleanupFailureProfiles
    ELSE {{}}

MonetaryUnwindOutcomes(i) ==
    IF /\ i = 1
       /\ ledger[i]["hold"] = "reserved"
    THEN BOOLEAN
    ELSE {FALSE}

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

ResolveAbort(current, kind) ==
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

ResolvePostDispatch(current, monetary_unwind_failed) ==
    [resource \in Resources |->
        IF current[resource] # "reserved"
        THEN current[resource]
        ELSE IF resource = "lease"
        THEN
            IF Mutation = "release-post-dispatch-lease"
            THEN "released"
            ELSE "retained"
        ELSE IF resource = "hold"
        THEN
            IF monetary_unwind_failed
            THEN "retained"
            ELSE "released"
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
        /\ parent_kind_logged[i] \in TerminalKinds
        /\ children_before_parent[i] \in BOOLEAN
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
    /\ parent_kind_logged = [i \in Invocations |-> "none"]
    /\ children_before_parent = [i \in Invocations |-> TRUE]
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
        /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "none"]
        /\ children_before_parent' = [children_before_parent EXCEPT ![i] = TRUE]
        /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "none"]

StartDispatch(i) ==
    /\ phase[i] = "admitted"
    /\ phase' = [phase EXCEPT ![i] = "dispatch_started"]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_buf,
                     child_total, child_logged, parent_receipts,
                     parent_kind_logged, children_before_parent,
                     terminal_kind >>

StreamChunk(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ child_buf[i] < ChildMax
    /\ phase' = [phase EXCEPT ![i] = "streaming"]
    /\ child_buf' = [child_buf EXCEPT ![i] = @ + 1]
    /\ child_total' = [child_total EXCEPT ![i] = @ + 1]
    /\ UNCHANGED << ledger, admitted_resources, unwind_failed, child_logged,
                     parent_receipts, parent_kind_logged,
                     children_before_parent, terminal_kind >>

CompleteOk(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ phase' = [phase EXCEPT ![i] = "terminal_ok"]
    /\ ledger' = [ledger EXCEPT ![i] = ResolveAll(@, "committed")]
    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
    /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
    /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
    /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "allow"]
    /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
        child_logged[i] + child_buf[i] = child_total[i]]
    /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "allow"]
    /\ UNCHANGED << admitted_resources, unwind_failed, child_total >>

DenyPostInvocation(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
    /\ ledger' = [ledger EXCEPT ![i] = ResolveAbort(@, "deny")]
    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
    /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
    /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
    /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "deny"]
    /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
        child_logged[i] + child_buf[i] = child_total[i]]
    /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "deny"]
    /\ UNCHANGED << admitted_resources, unwind_failed, child_total >>

IncompleteStream(i) ==
    /\ i = 1
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ phase' = [phase EXCEPT ![i] = "terminal_denied"]
    /\ ledger' = [ledger EXCEPT ![i] = ResolveAbort(@, "incomplete")]
    /\ child_buf' = [child_buf EXCEPT ![i] = 0]
    /\ child_logged' = [child_logged EXCEPT ![i] = @ + child_buf[i]]
    /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
    /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "incomplete"]
    /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
        child_logged[i] + child_buf[i] = child_total[i]]
    /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "incomplete"]
    /\ UNCHANGED << admitted_resources, unwind_failed, child_total >>

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
                /\ UNCHANGED << parent_receipts, parent_kind_logged >>
           ELSE
                /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
                /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "fault"]
                /\ IF Mutation = "omit-fault-receipt"
                   THEN UNCHANGED << parent_receipts, parent_kind_logged >>
                   ELSE
                        /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
                        /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "fault"]
        /\ UNCHANGED << admitted_resources, child_buf, child_total,
                         child_logged, children_before_parent >>

DropPostDispatch(i) ==
    /\ phase[i] \in {"dispatch_started", "streaming"}
    /\ \E monetary_unwind_failed \in MonetaryUnwindOutcomes(i) :
        LET flushed_count ==
                IF Mutation = "discard-child-buffer"
                THEN child_logged[i]
                ELSE child_logged[i] + child_buf[i]
        IN
        /\ phase' = [phase EXCEPT ![i] = "terminal_fault"]
        /\ ledger' = [ledger EXCEPT ![i] =
            ResolvePostDispatch(@, monetary_unwind_failed)]
        /\ child_buf' = [child_buf EXCEPT ![i] = 0]
        /\ child_logged' = [child_logged EXCEPT ![i] = flushed_count]
        /\ parent_receipts' = [parent_receipts EXCEPT ![i] = @ + 1]
        /\ parent_kind_logged' = [parent_kind_logged EXCEPT ![i] = "cancel"]
        /\ children_before_parent' = [children_before_parent EXCEPT ![i] =
            flushed_count = child_total[i]]
        /\ terminal_kind' = [terminal_kind EXCEPT ![i] = "cancel"]
        /\ UNCHANGED << admitted_resources, unwind_failed, child_total >>

Next ==
    \/ \E i \in Invocations : Admit(i)
    \/ \E i \in Invocations : StartDispatch(i)
    \/ \E i \in Invocations : StreamChunk(i)
    \/ \E i \in Invocations : CompleteOk(i)
    \/ \E i \in Invocations : DenyPostInvocation(i)
    \/ \E i \in Invocations : IncompleteStream(i)
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
        /\ terminal_kind[i] = "none" =>
            /\ parent_receipts[i] = 0
            /\ parent_kind_logged[i] = "none"
        /\ terminal_kind[i] = "unwound" =>
            /\ parent_receipts[i] = 0
            /\ parent_kind_logged[i] = "none"
        /\ terminal_kind[i] \in ParentReceiptKinds =>
            /\ parent_receipts[i] = 1
            /\ parent_kind_logged[i] = terminal_kind[i]

ChildReceiptsFlushed ==
    \A i \in Invocations :
        IsTerminal(i) =>
            /\ child_buf[i] = 0
            /\ child_logged[i] = child_total[i]
            /\ children_before_parent[i]

RetainedIffAborted ==
    \A i \in Invocations :
        (ledger[i]["lease"] = "retained") <=>
            ( /\ "lease" \in admitted_resources[i]
              /\ \/ terminal_kind[i] \in {"deny", "incomplete", "cancel"}
                 \/ "lease" \in unwind_failed[i] )

SafetyInv ==
    /\ DomainsOK
    /\ ReservationConservation
    /\ TerminalReceiptExactlyOne
    /\ ChildReceiptsFlushed
    /\ RetainedIffAborted

=============================================================================
