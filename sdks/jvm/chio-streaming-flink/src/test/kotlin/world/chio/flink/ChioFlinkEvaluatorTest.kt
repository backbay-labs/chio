package world.chio.flink

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import world.chio.flink.support.FakeChioClient
import world.chio.flink.support.FakeRuntimeContext
import world.chio.sdk.ChioClientLike
import world.chio.sdk.DlqRouter
import world.chio.sdk.SyntheticDenyReceipt
import world.chio.sdk.errors.ChioConnectionError
import world.chio.sdk.errors.ChioError
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Tag("parity")
class ChioFlinkEvaluatorTest {
    private fun configFor(
        client: ChioClientLike,
        onSidecarError: SidecarErrorBehaviour = SidecarErrorBehaviour.RAISE,
        receiptTopic: String? = null,
        maxInFlight: Int = 4,
    ): ChioFlinkConfig<Map<String, Any?>> =
        ChioFlinkConfig
            .builder<Map<String, Any?>>()
            .capabilityId("cap")
            .toolServer("srv")
            .subjectExtractor { e -> e["topic"]?.toString() ?: "topic" }
            .clientFactory { client }
            .dlqRouterFactory { DlqRouter(defaultTopic = "chio-dlq") }
            .onSidecarError(onSidecarError)
            .receiptTopic(receiptTopic)
            .maxInFlight(maxInFlight)
            .build()

    @Test
    fun allowEmitsOnlyMainWhenNoReceiptTopic() {
        val client = FakeChioClient(behaviour = FakeChioClient.Behaviour.Allow)
        val evaluator = ChioFlinkEvaluator(configFor(client))
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        assertTrue(outcome.allowed)
        assertTrue(outcome.acked, "allow path must report acked=true for parity with Python")
        assertNull(outcome.receiptBytes)
        assertNull(outcome.dlqBytes)
        assertNull(outcome.dlqRecord)
    }

    @Test
    fun allowPopulatesReceiptBytesWhenTopicSet() {
        val client = FakeChioClient(behaviour = FakeChioClient.Behaviour.Allow)
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, receiptTopic = "chio-receipts"),
            )
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        assertTrue(outcome.allowed)
        assertNotNull(outcome.receiptBytes)
        assertNull(outcome.dlqBytes)
    }

    @Test
    fun denyEmitsOnlyDlqNoReceipt() {
        val client = FakeChioClient(behaviour = FakeChioClient.Behaviour.Deny())
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, receiptTopic = "chio-receipts"),
            )
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        assertEquals(false, outcome.allowed)
        assertNotNull(outcome.dlqBytes)
        assertNotNull(outcome.dlqRecord)
        assertNull(outcome.receiptBytes)
    }

    @Test
    fun unverifiedAllowReceiptGoesToDlq() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Allow,
                verifyResult = false,
            )
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, receiptTopic = "chio-receipts"),
            )
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        assertEquals(false, outcome.allowed)
        assertNotNull(outcome.dlqBytes)
        assertNull(outcome.receiptBytes)
    }

    @Test
    fun raiseSidecarErrorPropagates() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom")),
            )
        val evaluator = ChioFlinkEvaluator(configFor(client))
        evaluator.bind(FakeRuntimeContext())
        assertThrows<ChioError> {
            evaluator.evaluate(mapOf("topic" to "t"))
        }
    }

    @Test
    fun denyBehaviourSynthesisesMarkerReceiptAndDlq() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom")),
            )
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, onSidecarError = SidecarErrorBehaviour.DENY),
            )
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        assertEquals(false, outcome.allowed)
        assertNotNull(outcome.dlqBytes)
        assertEquals(
            SyntheticDenyReceipt.MARKER,
            outcome.receipt.metadata!!["chio_streaming_synthetic_marker"],
        )
    }

    @Test
    fun metricsRegisteredFlatOnOperatorGroup() {
        val client = FakeChioClient()
        val evaluator = ChioFlinkEvaluator(configFor(client))
        val ctx = FakeRuntimeContext()
        evaluator.bind(ctx)
        evaluator.evaluate(mapOf("topic" to "t"))
        evaluator.evaluate(mapOf("topic" to "t"))
        // Parity with chio_streaming.flink._register_metrics: counters
        // live flat on the operator group, not under a "chio" subgroup.
        val group = ctx.metrics
        assertEquals(2L, group.counterValue("evaluations_total"))
        assertEquals(2L, group.counterValue("allow_total"))
        assertEquals(0L, group.counterValue("deny_total"))
        assertEquals(0L, group.counterValue("sidecar_errors_total"))
        assertNotNull(group.gaugeFor("in_flight"))
        assertTrue(group.subgroups["chio"] == null, "counters should not live under a 'chio' subgroup")
    }

    @Test
    fun denyCountersBumpCorrectly() {
        val client = FakeChioClient(behaviour = FakeChioClient.Behaviour.Deny())
        val evaluator = ChioFlinkEvaluator(configFor(client))
        val ctx = FakeRuntimeContext()
        evaluator.bind(ctx)
        evaluator.evaluate(mapOf("topic" to "t"))
        val group = ctx.metrics
        assertEquals(1L, group.counterValue("evaluations_total"))
        assertEquals(1L, group.counterValue("deny_total"))
    }

    @Test
    fun nonChioRuntimeExceptionPropagatesEvenUnderDeny() {
        // Python's evaluate_with_chio only catches ChioDeniedError and
        // ChioError. Any other RuntimeException (bug in a user extractor,
        // Jackson crash, etc.) bubbles out so Flink restarts the task. The
        // JVM evaluator must not launder it into a synthetic deny.
        val client =
            object : ChioClientLike {
                override fun evaluateToolCall(
                    capabilityId: String,
                    toolServer: String,
                    toolName: String,
                    parameters: Map<String, Any?>,
                ): world.chio.sdk.ChioReceipt = throw IllegalStateException("bug")
            }
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, onSidecarError = SidecarErrorBehaviour.DENY),
            )
        val ctx = FakeRuntimeContext()
        evaluator.bind(ctx)
        assertThrows<IllegalStateException> {
            evaluator.evaluate(mapOf("topic" to "t"))
        }
        // sidecar_errors_total must NOT bump: it's not a sidecar error.
        assertEquals(0L, ctx.metrics.counterValue("sidecar_errors_total"))
    }

    @Test
    fun sidecarErrorCounterIncrementsOnThrow() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom")),
            )
        val evaluator =
            ChioFlinkEvaluator(
                configFor(client, onSidecarError = SidecarErrorBehaviour.DENY),
            )
        val ctx = FakeRuntimeContext()
        evaluator.bind(ctx)
        evaluator.evaluate(mapOf("topic" to "t"))
        val group = ctx.metrics
        assertEquals(1L, group.counterValue("sidecar_errors_total"))
        assertEquals(1L, group.counterValue("deny_total"))
    }

    @Test
    fun requestIdFormatUsesPrefixAndUuidHex() {
        val client = FakeChioClient()
        val evaluator = ChioFlinkEvaluator(configFor(client))
        evaluator.bind(FakeRuntimeContext())
        val outcome = evaluator.evaluate(mapOf("topic" to "t"))
        // prefix + "-" + 32 hex chars (UUID without hyphens).
        val re = Regex("^chio-flink-[0-9a-f]{32}$")
        assertTrue(re.matches(outcome.requestId), "request_id was ${outcome.requestId}")
    }

    @Test
    fun maxInFlightLimitsConcurrency() {
        val gate = CountDownLatch(1)
        val admitted = AtomicInteger(0)
        val blocker =
            object : ChioClientLike {
                override fun evaluateToolCall(
                    capabilityId: String,
                    toolServer: String,
                    toolName: String,
                    parameters: Map<String, Any?>,
                ): world.chio.sdk.ChioReceipt {
                    admitted.incrementAndGet()
                    gate.await(5, TimeUnit.SECONDS)
                    return FakeChioClient().evaluateToolCall(capabilityId, toolServer, toolName, parameters)
                }

                override fun verifyReceipt(receipt: world.chio.sdk.ChioReceipt): Boolean = true
            }
        val evaluator =
            ChioFlinkEvaluator(
                configFor(blocker, maxInFlight = 2),
            )
        evaluator.bind(FakeRuntimeContext())
        val threads =
            (0 until 5).map { idx ->
                Thread {
                    evaluator.evaluate(mapOf("topic" to "t-$idx"))
                }.also {
                    it.isDaemon = true
                    it.start()
                }
            }
        // Let threads contend for the semaphore.
        Thread.sleep(200)
        assertTrue(admitted.get() <= 2, "admitted=${admitted.get()} exceeded maxInFlight")
        gate.countDown()
        threads.forEach { it.join(5000) }
    }
}
