package world.chio.flink

import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.ProcessFunction
import org.apache.flink.util.Collector
import org.apache.flink.util.OutputTag
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
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Tag("parity")
class ChioEvaluateFunctionTest {
    private fun configFor(
        client: ChioClientLike,
        onSidecarError: SidecarErrorBehaviour = SidecarErrorBehaviour.RAISE,
        receiptTopic: String? = null,
    ): ChioFlinkConfig<Map<String, Any?>> =
        ChioFlinkConfig
            .builder<Map<String, Any?>>()
            .capabilityId("cap")
            .toolServer("srv")
            .subjectExtractor { e -> e["topic"]?.toString() ?: "t" }
            .clientFactory { client }
            .dlqRouterFactory { DlqRouter(defaultTopic = "chio-dlq") }
            .onSidecarError(onSidecarError)
            .receiptTopic(receiptTopic)
            .build()

    private fun runOperator(
        config: ChioFlinkConfig<Map<String, Any?>>,
        element: Map<String, Any?>,
    ): OperatorOutputs {
        val fn = ChioEvaluateFunction(config)
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())
        val main = mutableListOf<Map<String, Any?>>()
        val side = mutableMapOf<String, MutableList<ByteArray>>()
        val ctx = fn.newFakeContext(side)
        fn.processElement(element, ctx, ListCollector(main))
        fn.close()
        return OperatorOutputs(main, side)
    }

    /**
     * Reach into AbstractRichFunction.setRuntimeContext to inject our
     * fake. Flink's open() pulls from runtimeContext, which is set by
     * the framework before open() during production use.
     */
    private fun setRuntimeContext(
        fn: ChioEvaluateFunction<*>,
        rc: FakeRuntimeContext,
    ) {
        // Kotlin can call the protected setter via reflection.
        val m =
            fn.javaClass.superclass.superclass
                .getDeclaredMethod("setRuntimeContext", org.apache.flink.api.common.functions.RuntimeContext::class.java)
        m.isAccessible = true
        m.invoke(fn, rc)
    }

    @Test
    fun allowYieldsMainAndReceiptWhenTopicSet() {
        val out =
            runOperator(
                configFor(FakeChioClient(), receiptTopic = "chio-receipts"),
                mapOf("topic" to "t"),
            )
        assertEquals(1, out.main.size)
        assertEquals(1, out.side["chio-receipt"]?.size)
        assertTrue(out.side["chio-dlq"].isNullOrEmpty())
    }

    @Test
    fun allowWithoutTopicYieldsMainOnly() {
        val out =
            runOperator(
                configFor(FakeChioClient()),
                mapOf("topic" to "t"),
            )
        assertEquals(1, out.main.size)
        assertTrue(out.side.isEmpty())
    }

    @Test
    fun denyYieldsDlqOnlyNoReceipt() {
        val out =
            runOperator(
                configFor(
                    FakeChioClient(behaviour = FakeChioClient.Behaviour.Deny()),
                    receiptTopic = "chio-receipts",
                ),
                mapOf("topic" to "t"),
            )
        assertTrue(out.main.isEmpty())
        assertEquals(1, out.side["chio-dlq"]?.size)
        assertTrue(out.side["chio-receipt"].isNullOrEmpty())
    }

    @Test
    fun sidecarErrorRaiseThrows() {
        val config =
            configFor(
                FakeChioClient(behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom"))),
                onSidecarError = SidecarErrorBehaviour.RAISE,
            )
        val fn = ChioEvaluateFunction(config)
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())
        assertThrows<ChioError> {
            val ctx = fn.newFakeContext(mutableMapOf())
            fn.processElement(mapOf("topic" to "t"), ctx, ListCollector(mutableListOf()))
        }
    }

    @Test
    fun sidecarErrorDenySynthesisesReceiptWithMarker() {
        val client =
            FakeChioClient(
                behaviour = FakeChioClient.Behaviour.Throw(ChioConnectionError("boom")),
            )
        val config =
            configFor(
                client,
                onSidecarError = SidecarErrorBehaviour.DENY,
                receiptTopic = "chio-receipts",
            )
        val out = runOperator(config, mapOf("topic" to "t"))
        assertTrue(out.main.isEmpty())
        val dlqBytes = out.side["chio-dlq"]?.single()
        assertTrue(dlqBytes != null)
        val dlqString = String(dlqBytes!!, Charsets.UTF_8)
        assertTrue(dlqString.contains(SyntheticDenyReceipt.MARKER))
    }

    @Test
    fun closeInvokesClientClose() {
        val closedFlag = booleanArrayOf(false)
        val client =
            object : ChioClientLike, AutoCloseable {
                override fun evaluateToolCall(
                    capabilityId: String,
                    toolServer: String,
                    toolName: String,
                    parameters: Map<String, Any?>,
                ): world.chio.sdk.ChioReceipt =
                    FakeChioClient().evaluateToolCall(
                        capabilityId,
                        toolServer,
                        toolName,
                        parameters,
                    )

                override fun close() {
                    closedFlag[0] = true
                }
            }
        val fn = ChioEvaluateFunction(configFor(client))
        setRuntimeContext(fn, FakeRuntimeContext())
        fn.open(EmptyOpenContext())
        fn.close()
        assertTrue(closedFlag[0], "client.close() was not invoked")
    }

    @Test
    fun preservesAllowPathInvariant() {
        val out =
            runOperator(
                configFor(FakeChioClient()),
                mapOf("topic" to "t"),
            )
        assertFalse(out.main.isEmpty())
    }

    private class EmptyOpenContext : OpenContext

    private class ListCollector<T>(
        val out: MutableList<T>,
    ) : Collector<T> {
        override fun collect(record: T) {
            out.add(record)
        }

        override fun close() = Unit
    }

    private class OperatorOutputs(
        val main: MutableList<Map<String, Any?>>,
        val side: MutableMap<String, MutableList<ByteArray>>,
    )
}

// Same inner-class extension trick as ChioVerdictSplitFunctionTest.
private fun <IN> ChioEvaluateFunction<IN>.newFakeContext(
    side: MutableMap<String, MutableList<ByteArray>>,
): ProcessFunction<IN, IN>.Context {
    val outer = this
    return outer.run {
        object : ProcessFunction<IN, IN>.Context() {
            override fun timestamp(): Long? = null

            override fun timerService(): org.apache.flink.streaming.api.TimerService = throw UnsupportedOperationException()

            override fun <X : Any?> output(
                outputTag: OutputTag<X>,
                value: X,
            ) {
                val bytes = value as ByteArray
                side.computeIfAbsent(outputTag.id) { mutableListOf() }.add(bytes)
            }
        }
    }
}
