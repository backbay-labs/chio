---------------------- MODULE DistributedRevocation ----------------------
(***************************************************************************)
(* Distributed revocation-root propagation over bilateral peers.           *)
(*                                                                         *)
(* Production action map                                                   *)
(*                                                                         *)
(* QueueRoot        RevocationGossipPushQueue::enqueue_signed_root         *)
(* Send             RevocationGossipPushQueue::flush_batches_at            *)
(* Duplicate, Lose  bilateral transport behavior                           *)
(* RejectForged     RevocationRootGossip::validate_envelope plus pinned    *)
(*                  SignedEpochRoot::verify                                *)
(* Deliver          RevocationView::install_if_newer                       *)
(* Catchup          RevocationCatchupRequest::new, respond_to_catchup,     *)
(*                  RevocationCatchupResponse::validate_response           *)
(* Evaluate         delegation::consult_revocation_view_at                 *)
(*                                                                         *)
(* Valid channels are counting functions. Duplicate increments a count,    *)
(* Lose decrements without delivery, and Deliver may choose any epoch with  *)
(* a positive count, so delivery order is arbitrary. forgedChannel is      *)
(* adversarial input. The unmutated model rejects it before changing a      *)
(* high-water mark.                                                        *)
(* viewAuthentic distinguishes a genuine signed root from a forged root at  *)
(* the same epoch. targetRevokedEpoch separates root advancement from       *)
(* revocation of the evaluated target, so fresh nonzero views may allow an  *)
(* unrelated target.                                                       *)
(*                                                                         *)
(* ChannelCap is a finite model-checking bound on in-flight multiplicity.   *)
(* It is not a production transport replay or duplication bound. Safety     *)
(* permits repeated cuts; only the bounded temporal behavior limits each    *)
(* pair to one cut so its weak-fair heal obligation can converge.           *)
(*                                                                         *)
(* Per-origin matrices are a distributed abstraction. The executable        *)
(* production projection covers one pinned origin and the shipped global    *)
(* RevocationView, not multi-origin view isolation.                         *)
(*                                                                         *)
(* DistributedDomainsOK checks exact domains and relational shape in the     *)
(* concrete initial state. Behavioral safety remains a bounded path check.    *)
(*                                                                         *)
(* StaleEvaluationDenied is the production-grounded freshness property.    *)
(* An evaluation may allow only when its installed root timestamp is not   *)
(* in the future and its age is within FreshnessBound. This mirrors         *)
(* verify_fresh_epoch_root and verify_snapshot_freshness. It does not bound *)
(* raw evaluation count. RejectedRawEvaluationCountBound is deliberately   *)
(* outside SafetyInv; a registered witness demonstrates that arbitrary     *)
(* loss permits more evaluations than any finite count before observation. *)
(*                                                                         *)
(* Eventual observation is conditional on weak fairness for connected      *)
(* direct-origin catch-up and partition healing. Loss, duplication, and     *)
(* reordering remain actions rather than assumptions.                      *)
(*                                                                         *)
(* Handwritten TLA+ is the artifact of record. The repository-pinned        *)
(* Apalache checker consumes it directly, avoiding an additional compiler  *)
(* and package-distribution boundary.                                      *)
(***************************************************************************)

EXTENDS Naturals, Integers, FiniteSets, Sequences

CONSTANTS
    \* @type: Set(Int);
    Authorities,
    \* @type: Int;
    EpochMax,
    \* @type: Int;
    ClockMax,
    \* @type: Int;
    FreshnessBound,
    \* @type: Int;
    EvaluationWitnessBound,
    \* @type: Int;
    PartitionBound,
    \* @type: Int;
    SkewBound,
    \* @type: Int;
    ChannelCap,
    \* @type: Str;
    Mutation

Epochs == 1..EpochMax
ClockDomain == 0..(ClockMax + 1)
EvaluationDomain == 0..(EvaluationWitnessBound + 1)
PartitionDomain == 0..PartitionBound
Mutations == {
    "none",
    "accept-forged",
    "unbounded-skew",
    "cross-partition-catchup",
    "skip-freshness",
    "skip-revocation"
}

ASSUME
    /\ Cardinality(Authorities) >= 2
    /\ EpochMax >= 2
    /\ ClockMax >= 2
    /\ FreshnessBound >= 0
    /\ EvaluationWitnessBound >= 1
    /\ PartitionBound >= 1
    /\ SkewBound >= 0
    /\ ChannelCap >= 2
    /\ Mutation \in Mutations

VARIABLES
    \* @type: Int -> Int;
    now,
    \* @type: Int -> Int;
    originEpoch,
    \* @type: Int -> (Int -> Int);
    epochIssuedAt,
    \* @type: Int -> Int;
    targetRevokedEpoch,
    \* @type: Int -> (Int -> Int);
    hwm,
    \* @type: Int -> (Int -> Int);
    viewIssuedAt,
    \* @type: Int -> (Int -> Bool);
    viewAuthentic,
    \* @type: Int -> (Int -> Int);
    queue,
    \* @type: Int -> (Int -> (Int -> Int));
    channel,
    \* @type: Int -> (Int -> (Int -> Int));
    forgedChannel,
    \* @type: Set(Seq(Int));
    partition,
    \* @type: Int -> (Int -> Int);
    cutHwm,
    \* @type: Int -> (Int -> Int);
    cutIssuedAt,
    \* @type: Int -> (Int -> Int);
    partitionTicks,
    \* @type: Int -> (Int -> Bool);
    allowRevoked,
    \* @type: Int -> (Int -> Bool);
    allowFresh,
    \* @type: Int -> (Int -> Int);
    evalsSinceObservation,
    \* @type: Set(Seq(Int));
    cutUsed

vars == <<
    now,
    originEpoch,
    epochIssuedAt,
    targetRevokedEpoch,
    hwm,
    viewIssuedAt,
    viewAuthentic,
    queue,
    channel,
    forgedChannel,
    partition,
    cutHwm,
    cutIssuedAt,
    partitionTicks,
    allowRevoked,
    allowFresh,
    evalsSinceObservation,
    cutUsed
>>

Max2(x, y) == IF x >= y THEN x ELSE y
Min2(x, y) == IF x <= y THEN x ELSE y

IsConnected(a, b) == <<a, b>> \notin partition

\* @type: (Int -> Int) => Bool;
WithinSkew(clocks) ==
    \A a \in Authorities, b \in Authorities :
        /\ clocks[a] <= clocks[b] + SkewBound
        /\ clocks[b] <= clocks[a] + SkewBound

SnapshotFresh(a, o) ==
    /\ now[a] >= viewIssuedAt[a][o]
    /\ now[a] - viewIssuedAt[a][o] <= FreshnessBound

ZeroMatrix ==
    [a \in Authorities |-> [o \in Authorities |-> 0]]

ZeroEpochTimes ==
    [o \in Authorities |-> [e \in Epochs |-> 0]]

ZeroBoolMatrix ==
    [a \in Authorities |-> [o \in Authorities |-> FALSE]]

TrueBoolMatrix ==
    [a \in Authorities |-> [o \in Authorities |-> TRUE]]

ZeroChannel ==
    [o \in Authorities |->
        [a \in Authorities |->
            [e \in Epochs |-> 0]]]

Init ==
    /\ now = [a \in Authorities |-> 0]
    /\ originEpoch = [o \in Authorities |-> 0]
    /\ epochIssuedAt = ZeroEpochTimes
    /\ targetRevokedEpoch = [o \in Authorities |-> 0]
    /\ hwm = ZeroMatrix
    /\ viewIssuedAt = ZeroMatrix
    /\ viewAuthentic = TrueBoolMatrix
    /\ queue = ZeroMatrix
    /\ channel = ZeroChannel
    /\ forgedChannel = ZeroChannel
    /\ partition = {}
    /\ cutHwm = ZeroMatrix
    /\ cutIssuedAt = ZeroMatrix
    /\ partitionTicks = ZeroMatrix
    /\ allowRevoked = ZeroBoolMatrix
    /\ allowFresh = TrueBoolMatrix
    /\ evalsSinceObservation = ZeroMatrix
    /\ cutUsed = {}

Tick(a) ==
    LET advanced == [now EXCEPT ![a] = @ + 1]
        agedPartitions == [partitionTicks EXCEPT
            ![a] = [b \in Authorities |->
                IF IsConnected(a, b)
                THEN partitionTicks[a][b]
                ELSE partitionTicks[a][b] + 1]]
    IN
        /\ a \in Authorities
        /\ now[a] < ClockMax
        /\ \A b \in Authorities :
            (~IsConnected(a, b)) => partitionTicks[a][b] < PartitionBound
        /\ \/ Mutation = "unbounded-skew"
           \/ WithinSkew(advanced)
        /\ now' = advanced
        /\ partitionTicks' = agedPartitions
        /\ UNCHANGED <<
            originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
            viewAuthentic, queue, channel,
            forgedChannel, partition, cutHwm, cutIssuedAt,
            allowRevoked, allowFresh, evalsSinceObservation, cutUsed
            >>

Revoke(o, revokesTarget) ==
    LET nextEpoch == originEpoch[o] + 1
    IN
        /\ o \in Authorities
        /\ revokesTarget \in BOOLEAN
        /\ originEpoch[o] < EpochMax
        /\ originEpoch' = [originEpoch EXCEPT ![o] = nextEpoch]
        /\ epochIssuedAt' = [epochIssuedAt EXCEPT ![o][nextEpoch] = now[o]]
        /\ targetRevokedEpoch' = [targetRevokedEpoch EXCEPT ![o] =
            IF revokesTarget /\ @ = 0 THEN nextEpoch ELSE @]
        /\ hwm' = [hwm EXCEPT ![o][o] = nextEpoch]
        /\ viewIssuedAt' = [viewIssuedAt EXCEPT ![o][o] = now[o]]
        /\ evalsSinceObservation' = [evalsSinceObservation EXCEPT ![o][o] = 0]
        /\ UNCHANGED <<
            now, viewAuthentic, queue, channel, forgedChannel, partition, cutHwm,
            cutIssuedAt, partitionTicks, allowRevoked, allowFresh, cutUsed
            >>

QueueRoot(o) ==
    /\ o \in Authorities
    /\ originEpoch[o] > 0
    /\ \E a \in Authorities :
        /\ a # o
        /\ queue[o][a] < originEpoch[o]
    /\ queue' = [queue EXCEPT
        ![o] = [a \in Authorities |->
            IF a = o
            THEN 0
            ELSE Max2(queue[o][a], originEpoch[o])]]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
        viewAuthentic, channel,
        forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

Send(o, a) ==
    LET e == queue[o][a]
    IN
        /\ o \in Authorities
        /\ a \in Authorities
        /\ o # a
        /\ e \in Epochs
        /\ channel[o][a][e] < ChannelCap
        /\ queue' = [queue EXCEPT ![o][a] = 0]
        /\ channel' = [channel EXCEPT ![o][a][e] = @ + 1]
        /\ UNCHANGED <<
            now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm,
            viewIssuedAt, viewAuthentic,
            forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
            allowRevoked, allowFresh, evalsSinceObservation, cutUsed
            >>

Duplicate(o, a, e) ==
    /\ o \in Authorities
    /\ a \in Authorities
    /\ o # a
    /\ e \in Epochs
    /\ channel[o][a][e] > 0
    /\ channel[o][a][e] < ChannelCap
    /\ channel' = [channel EXCEPT ![o][a][e] = @ + 1]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
        viewAuthentic, queue,
        forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

Lose(o, a, e) ==
    /\ o \in Authorities
    /\ a \in Authorities
    /\ o # a
    /\ e \in Epochs
    /\ channel[o][a][e] > 0
    /\ channel' = [channel EXCEPT ![o][a][e] = @ - 1]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
        viewAuthentic, queue,
        forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

InjectForged(o, a, e) ==
    /\ o \in Authorities
    /\ a \in Authorities
    /\ o # a
    /\ e \in Epochs
    /\ forgedChannel[o][a][e] < ChannelCap
    /\ forgedChannel' = [forgedChannel EXCEPT ![o][a][e] = @ + 1]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
        viewAuthentic, queue, channel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

RejectForged(o, a, e) ==
    /\ o \in Authorities
    /\ a \in Authorities
    /\ e \in Epochs
    /\ forgedChannel[o][a][e] > 0
    /\ forgedChannel' = [forgedChannel EXCEPT ![o][a][e] = @ - 1]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm, viewIssuedAt,
        viewAuthentic, queue, channel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

AcceptForged(o, a, e) ==
    /\ Mutation = "accept-forged"
    /\ o \in Authorities
    /\ a \in Authorities
    /\ o # a
    /\ e \in Epochs
    /\ IsConnected(a, o)
    /\ forgedChannel[o][a][e] > 0
    /\ e > hwm[a][o]
    /\ forgedChannel' = [forgedChannel EXCEPT ![o][a][e] = @ - 1]
    /\ hwm' = [hwm EXCEPT ![a][o] = Max2(@, e)]
    /\ viewIssuedAt' = [viewIssuedAt EXCEPT ![a][o] = now[a]]
    /\ viewAuthentic' = [viewAuthentic EXCEPT ![a][o] = FALSE]
    /\ evalsSinceObservation' = [evalsSinceObservation EXCEPT ![a][o] = 0]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, queue, channel,
        partition, cutHwm, cutIssuedAt, partitionTicks, allowRevoked,
        allowFresh, cutUsed
        >>

Deliver(o, a, e) ==
    LET installed == Max2(hwm[a][o], e)
        issued == IF e > hwm[a][o] THEN epochIssuedAt[o][e] ELSE viewIssuedAt[a][o]
    IN
        /\ o \in Authorities
        /\ a \in Authorities
        /\ o # a
        /\ e \in Epochs
        /\ IsConnected(a, o)
        /\ channel[o][a][e] > 0
        /\ channel' = [channel EXCEPT ![o][a][e] = @ - 1]
        /\ hwm' = [hwm EXCEPT ![a][o] = installed]
        /\ viewIssuedAt' = [viewIssuedAt EXCEPT ![a][o] = issued]
        /\ evalsSinceObservation' = [evalsSinceObservation EXCEPT ![a][o] =
            IF installed >= originEpoch[o] THEN 0 ELSE @]
        /\ UNCHANGED <<
            now, originEpoch, epochIssuedAt, targetRevokedEpoch, viewAuthentic, queue,
            forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
            allowRevoked, allowFresh, cutUsed
            >>

Catchup(a, b, o) ==
    /\ a \in Authorities
    /\ b \in Authorities
    /\ o \in Authorities
    /\ a # b
    /\ b = o
    /\ \/ IsConnected(a, b)
       \/ Mutation = "cross-partition-catchup"
    /\ hwm[b][o] > hwm[a][o]
    /\ hwm' = [hwm EXCEPT ![a][o] = hwm[b][o]]
    /\ viewIssuedAt' = [viewIssuedAt EXCEPT ![a][o] = viewIssuedAt[b][o]]
    /\ evalsSinceObservation' = [evalsSinceObservation EXCEPT ![a][o] =
        IF hwm[b][o] >= originEpoch[o] THEN 0 ELSE @]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, viewAuthentic,
        queue, channel,
        forgedChannel, partition, cutHwm, cutIssuedAt, partitionTicks,
        allowRevoked, allowFresh, cutUsed
        >>

CutState(a, b) ==
    /\ a \in Authorities
    /\ b \in Authorities
    /\ a # b
    /\ IsConnected(a, b)
    /\ partition' = partition \cup {<<a, b>>, <<b, a>>}
    /\ cutHwm' = [cutHwm EXCEPT
        ![a][b] = hwm[a][b],
        ![b][a] = hwm[b][a]]
    /\ cutIssuedAt' = [cutIssuedAt EXCEPT
        ![a][b] = viewIssuedAt[a][b],
        ![b][a] = viewIssuedAt[b][a]]
    /\ partitionTicks' = [partitionTicks EXCEPT
        ![a][b] = 0,
        ![b][a] = 0]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm,
        viewIssuedAt, viewAuthentic, queue, channel, forgedChannel,
        allowRevoked, allowFresh,
        evalsSinceObservation
        >>

Cut(a, b) ==
    /\ CutState(a, b)
    /\ UNCHANGED cutUsed

CutOnce(a, b) ==
    /\ <<a, b>> \notin cutUsed
    /\ CutState(a, b)
    /\ cutUsed' = cutUsed \cup {<<a, b>>, <<b, a>>}

Heal(a, b) ==
    /\ a \in Authorities
    /\ b \in Authorities
    /\ a # b
    /\ <<a, b>> \in partition
    /\ partition' = partition \ {<<a, b>>, <<b, a>>}
    /\ partitionTicks' = [partitionTicks EXCEPT
        ![a][b] = 0,
        ![b][a] = 0]
    /\ UNCHANGED <<
        now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm,
        viewIssuedAt, viewAuthentic, queue, channel, forgedChannel, cutHwm,
        cutIssuedAt,
        allowRevoked, allowFresh, evalsSinceObservation, cutUsed
        >>

Evaluate(a, o) ==
    LET behind == originEpoch[o] > hwm[a][o]
        fresh == SnapshotFresh(a, o)
        locallyRevoked ==
            /\ targetRevokedEpoch[o] > 0
            /\ hwm[a][o] >= targetRevokedEpoch[o]
        localAllow ==
            /\ \/ ~locallyRevoked
               \/ Mutation = "skip-revocation"
            /\ \/ fresh
               \/ Mutation = "skip-freshness"
    IN
        /\ a \in Authorities
        /\ o \in Authorities
        /\ allowRevoked' = [allowRevoked EXCEPT ![a][o] =
            IF localAllow THEN @ \/ locallyRevoked ELSE @]
        /\ allowFresh' = [allowFresh EXCEPT ![a][o] =
            IF localAllow THEN @ /\ fresh ELSE @]
        /\ evalsSinceObservation' = [evalsSinceObservation EXCEPT ![a][o] =
            IF behind
            THEN Min2(@ + 1, EvaluationWitnessBound + 1)
            ELSE 0]
        /\ UNCHANGED <<
            now, originEpoch, epochIssuedAt, targetRevokedEpoch, hwm,
            viewIssuedAt, viewAuthentic, queue, channel, forgedChannel,
            partition, cutHwm,
            cutIssuedAt, partitionTicks, cutUsed
            >>

\* @type: Set(Seq(Int));
AuthorityPairs == {<<a, b>> : a \in Authorities, b \in Authorities}

DomainsOK ==
    /\ Mutation \in Mutations
    /\ now \in [Authorities -> ClockDomain]
    /\ originEpoch \in [Authorities -> 0..EpochMax]
    /\ epochIssuedAt \in [Authorities -> [Epochs -> ClockDomain]]
    /\ targetRevokedEpoch \in [Authorities -> 0..EpochMax]
    /\ hwm \in [Authorities -> [Authorities -> 0..EpochMax]]
    /\ viewIssuedAt \in [Authorities -> [Authorities -> ClockDomain]]
    /\ viewAuthentic \in [Authorities -> [Authorities -> BOOLEAN]]
    /\ queue \in [Authorities -> [Authorities -> 0..EpochMax]]
    /\ channel \in
        [Authorities -> [Authorities -> [Epochs -> 0..ChannelCap]]]
    /\ forgedChannel \in
        [Authorities -> [Authorities -> [Epochs -> 0..ChannelCap]]]
    /\ partition \in SUBSET AuthorityPairs
    /\ cutHwm \in [Authorities -> [Authorities -> 0..EpochMax]]
    /\ cutIssuedAt \in [Authorities -> [Authorities -> ClockDomain]]
    /\ partitionTicks \in [Authorities -> [Authorities -> PartitionDomain]]
    /\ allowRevoked \in [Authorities -> [Authorities -> BOOLEAN]]
    /\ allowFresh \in [Authorities -> [Authorities -> BOOLEAN]]
    /\ evalsSinceObservation \in
        [Authorities -> [Authorities -> EvaluationDomain]]
    /\ cutUsed \in SUBSET AuthorityPairs

PartitionRelationOK ==
    /\ \A a \in Authorities : <<a, a>> \notin partition
    /\ \A a \in Authorities, b \in Authorities :
        (<<a, b>> \in partition) <=> (<<b, a>> \in partition)

OriginStateOK ==
    \A o \in Authorities :
        /\ hwm[o][o] = originEpoch[o]
        /\ targetRevokedEpoch[o] <= originEpoch[o]
        /\ viewAuthentic[o][o]
        /\ viewIssuedAt[o][o] =
            IF originEpoch[o] = 0
            THEN 0
            ELSE epochIssuedAt[o][originEpoch[o]]

DistributedDomainsOK ==
    /\ DomainsOK
    /\ PartitionRelationOK
    /\ OriginStateOK

ClockSkewBound == WithinSkew(now)

SignerPinnedHighWater ==
    \A a \in Authorities, o \in Authorities :
        /\ hwm[a][o] <= originEpoch[o]
        /\ viewAuthentic[a][o]

NoAllowAfterRevokeDistributed ==
    \A a \in Authorities, o \in Authorities :
        ~allowRevoked[a][o]

StaleEvaluationDenied ==
    \A a \in Authorities, o \in Authorities : allowFresh[a][o]

PartitionSuspendResume ==
    \A a \in Authorities, o \in Authorities :
        /\ (~IsConnected(a, o)) =>
            /\ hwm[a][o] = cutHwm[a][o]
            /\ viewIssuedAt[a][o] = cutIssuedAt[a][o]
            /\ partitionTicks[a][o] <= PartitionBound

BehavioralSafetyInv ==
    /\ ClockSkewBound
    /\ SignerPinnedHighWater
    /\ NoAllowAfterRevokeDistributed
    /\ StaleEvaluationDenied
    /\ PartitionSuspendResume

SafetyInv ==
    BehavioralSafetyInv

ObserveAny ==
    \E a \in Authorities, o \in Authorities :
        /\ a # o
        /\ Catchup(a, o, o)

HealAny ==
    \E a \in Authorities, b \in Authorities : Heal(a, b)

NonCutNext ==
    \/ \E a \in Authorities : Tick(a)
    \/ \E o \in Authorities, revokesTarget \in BOOLEAN : Revoke(o, revokesTarget)
    \/ \E o \in Authorities : QueueRoot(o)
    \/ \E o \in Authorities, a \in Authorities : Send(o, a)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : Duplicate(o, a, e)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : Lose(o, a, e)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : InjectForged(o, a, e)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : RejectForged(o, a, e)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : AcceptForged(o, a, e)
    \/ \E o \in Authorities, a \in Authorities, e \in Epochs : Deliver(o, a, e)
    \/ \E a \in Authorities, b \in Authorities, o \in Authorities : Catchup(a, b, o)
    \/ \E a \in Authorities, b \in Authorities : Heal(a, b)
    \/ \E a \in Authorities, o \in Authorities : Evaluate(a, o)

Next ==
    \/ NonCutNext
    \/ \E a \in Authorities, b \in Authorities : Cut(a, b)

TemporalNext ==
    \/ NonCutNext
    \/ \E a \in Authorities, b \in Authorities : CutOnce(a, b)

Spec ==
    /\ Init
    /\ [][Next]_vars

TemporalSpec ==
    /\ Init
    /\ [][TemporalNext]_vars

RejectedRawEvaluationCountBound ==
    \A a \in Authorities, o \in Authorities :
        evalsSinceObservation[a][o] <= EvaluationWitnessBound

=============================================================================
