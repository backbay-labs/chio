---------------- MODULE TraceCheckDistributedRevocation ----------------
(***************************************************************************)
(* State predicates evaluated directly over production-emitted ITF traces.  *)
(* The companion validator checks adjacent transitions; Apalache trace       *)
(* evaluation checks these predicates against every concrete trace state.    *)
(***************************************************************************)

EXTENDS Naturals

VARIABLES
    \* @type: Str;
    action,
    \* @type: Int;
    originEpoch,
    \* @type: Int;
    viewEpoch,
    \* @type: Int;
    queueEpoch,
    \* @type: Int;
    channelCount,
    \* @type: Int;
    forgedCount,
    \* @type: Bool;
    partitioned,
    \* @type: Int;
    localTime,
    \* @type: Int;
    viewIssuedAt,
    \* @type: Int;
    freshnessBound,
    \* @type: Bool;
    allowFresh

Actions == {
    "Init",
    "Tick",
    "Revoke",
    "QueueRoot",
    "Send",
    "Duplicate",
    "Lose",
    "Deliver",
    "InjectForged",
    "RejectForged",
    "Cut",
    "Heal",
    "Catchup",
    "EvaluateDeny"
}

RootIssuedAt(e) == 1700000000000 + e

ProjectionDomainOK ==
    /\ action \in Actions
    /\ originEpoch \in Nat
    /\ viewEpoch \in Nat
    /\ queueEpoch \in Nat
    /\ channelCount \in Nat
    /\ forgedCount \in Nat
    /\ partitioned \in BOOLEAN
    /\ localTime \in Nat
    /\ viewIssuedAt \in Nat
    /\ freshnessBound \in Nat
    /\ allowFresh \in BOOLEAN

ProjectionSafety ==
    /\ ProjectionDomainOK
    /\ viewEpoch <= originEpoch
    /\ viewIssuedAt = IF viewEpoch = 0 THEN 0 ELSE RootIssuedAt(viewEpoch)
    /\ allowFresh
    /\ (action = "Deliver") => ~partitioned
    /\ (action = "Catchup") =>
        /\ ~partitioned
        /\ viewEpoch = originEpoch
    /\ (action = "EvaluateDeny") =>
        /\ localTime >= viewIssuedAt
        /\ localTime - viewIssuedAt > freshnessBound

ProjectionData == [
    originEpoch |-> originEpoch,
    viewEpoch |-> viewEpoch,
    queueEpoch |-> queueEpoch,
    channelCount |-> channelCount,
    forgedCount |-> forgedCount,
    partitioned |-> partitioned,
    localTime |-> localTime,
    viewIssuedAt |-> viewIssuedAt,
    freshnessBound |-> freshnessBound,
    allowFresh |-> allowFresh
]

ProjectionStep ==
    CASE action' = "Revoke" ->
        ProjectionData' = [ProjectionData EXCEPT !.originEpoch = @ + 1]
    [] action' = "QueueRoot" ->
        /\ originEpoch > 0
        /\ ProjectionData' = [ProjectionData EXCEPT !.queueEpoch = originEpoch]
    [] action' = "Send" ->
        /\ queueEpoch > 0
        /\ ProjectionData' = [ProjectionData EXCEPT
            !.queueEpoch = 0,
            !.channelCount = @ + 1]
    [] action' = "Duplicate" ->
        /\ channelCount > 0
        /\ ProjectionData' = [ProjectionData EXCEPT !.channelCount = @ + 1]
    [] action' = "Lose" ->
        /\ channelCount > 0
        /\ ProjectionData' = [ProjectionData EXCEPT !.channelCount = @ - 1]
    [] action' = "Deliver" ->
        /\ ~partitioned
        /\ channelCount > 0
        /\ viewEpoch <= viewEpoch'
        /\ viewEpoch' <= originEpoch
        /\ ProjectionData' = [ProjectionData EXCEPT
            !.channelCount = @ - 1,
            !.viewEpoch = viewEpoch',
            !.viewIssuedAt =
                IF viewEpoch' > viewEpoch
                THEN RootIssuedAt(viewEpoch')
                ELSE viewIssuedAt]
    [] action' = "InjectForged" ->
        ProjectionData' = [ProjectionData EXCEPT !.forgedCount = @ + 1]
    [] action' = "RejectForged" ->
        /\ forgedCount > 0
        /\ ProjectionData' = [ProjectionData EXCEPT !.forgedCount = @ - 1]
    [] action' = "Cut" ->
        /\ ~partitioned
        /\ ProjectionData' = [ProjectionData EXCEPT !.partitioned = TRUE]
    [] action' = "Heal" ->
        /\ partitioned
        /\ ProjectionData' = [ProjectionData EXCEPT !.partitioned = FALSE]
    [] action' = "Catchup" ->
        /\ ~partitioned
        /\ originEpoch > viewEpoch
        /\ viewEpoch' = originEpoch
        /\ ProjectionData' = [ProjectionData EXCEPT
            !.viewEpoch = viewEpoch',
            !.viewIssuedAt = RootIssuedAt(viewEpoch')]
    [] action' = "Tick" ->
        ProjectionData' = [ProjectionData EXCEPT !.localTime = @ + 1]
    [] action' = "EvaluateDeny" ->
        /\ localTime >= viewIssuedAt
        /\ localTime - viewIssuedAt > freshnessBound
        /\ ProjectionData' = ProjectionData
    [] OTHER -> FALSE

=============================================================================
