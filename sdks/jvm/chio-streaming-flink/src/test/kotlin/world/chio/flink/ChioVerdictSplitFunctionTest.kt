package world.chio.flink

import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.ProcessFunction
import org.apache.flink.util.Collector
import org.apache.flink.util.OutputTag
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Tag("parity")
class ChioVerdictSplitFunctionTest {
    @Test
    fun tagNamesAreWireStable() {
        assertEquals("chio-receipt", ChioOutputTags.RECEIPT_TAG_NAME)
        assertEquals("chio-dlq", ChioOutputTags.DLQ_TAG_NAME)
    }

    @Test
    fun mainOutputReceivesElementOnlyOnAllow() {
        val (main, side) = runSplit(EvaluationResult(allowed = true, element = "hello"))
        assertEquals(listOf("hello"), main)
        assertTrue(side.isEmpty())
    }

    @Test
    fun receiptSideOutputReceivesReceiptBytesWhenNonNull() {
        val (_, side) =
            runSplit(
                EvaluationResult(
                    allowed = true,
                    element = "x",
                    receiptBytes = "receipt".toByteArray(),
                ),
            )
        assertEquals(1, side["chio-receipt"]?.size)
        assertEquals("receipt", String(side["chio-receipt"]!!.single(), Charsets.UTF_8))
    }

    @Test
    fun dlqSideOutputReceivesDlqBytesAndNoMainOnDeny() {
        val (main, side) =
            runSplit(
                EvaluationResult(
                    allowed = false,
                    element = "x",
                    dlqBytes = "dlq".toByteArray(),
                ),
            )
        assertTrue(main.isEmpty())
        assertEquals("dlq", String(side["chio-dlq"]!!.single(), Charsets.UTF_8))
    }

    private fun runSplit(input: EvaluationResult<String>): Pair<MutableList<String>, MutableMap<String, MutableList<ByteArray>>> {
        val main = mutableListOf<String>()
        val side = mutableMapOf<String, MutableList<ByteArray>>()
        val fn = ChioVerdictSplitFunction<String>()
        fn.open(EmptyOpenContext())
        val ctx = fn.fakeContext(side)
        fn.processElement(input, ctx, ListCollector(main))
        return main to side
    }

    private class ListCollector<T>(
        val out: MutableList<T>,
    ) : Collector<T> {
        override fun collect(record: T) {
            out.add(record)
        }

        override fun close() = Unit
    }

    private inner class EmptyOpenContext : OpenContext
}

// Extension-style inner class that piggy-backs on the operator's inner type
// binding. Declared top-level so Kotlin can legally extend Context.
private fun <IN> ChioVerdictSplitFunction<IN>.fakeContext(
    side: MutableMap<String, MutableList<ByteArray>>,
): ProcessFunction<EvaluationResult<IN>, IN>.Context {
    val operator = this
    return operator.run {
        object : ProcessFunction<EvaluationResult<IN>, IN>.Context() {
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
