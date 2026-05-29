/**
 * Synchronous Chio ProcessFunction. Mirrors the Python
 * ChioEvaluateFunction.
 *
 * Latency floor equals sidecar RTT times the per-element cost; no
 * pipelining. Use only when the sidecar is co-located and RTT is sub-ms,
 * or the source is low-throughput. Prefer ChioAsyncEvaluateFunction +
 * ChioVerdictSplitFunction otherwise.
 *
 * Emits:
 * - value to main on allow;
 * - receipt bytes to the receipt side output when non-null;
 * - DLQ bytes to the DLQ side output when non-null.
 */
package world.chio.flink

import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.ProcessFunction
import org.apache.flink.util.Collector

class ChioEvaluateFunction<IN>(
    private val config: ChioFlinkConfig<IN>,
) : ProcessFunction<IN, IN>() {
    @Transient
    private var evaluator: ChioFlinkEvaluator<IN>? = null

    @Transient
    private var receiptTag: org.apache.flink.util.OutputTag<ByteArray>? = null

    @Transient
    private var dlqTag: org.apache.flink.util.OutputTag<ByteArray>? = null

    fun config(): ChioFlinkConfig<IN> = config

    override fun open(openContext: OpenContext) {
        super.open(openContext)
        val ev = ChioFlinkEvaluator(config)
        ev.bind(runtimeContext)
        evaluator = ev
        receiptTag = ChioOutputTags.receiptTag()
        dlqTag = ChioOutputTags.dlqTag()
    }

    override fun close() {
        evaluator?.shutdown()
        evaluator = null
        super.close()
    }

    override fun processElement(
        value: IN,
        ctx: ProcessFunction<IN, IN>.Context,
        out: Collector<IN>,
    ) {
        val ev = evaluator ?: error("ChioEvaluateFunction.processElement called before open()")
        val outcome = ev.evaluate(value)
        if (outcome.allowed) {
            out.collect(outcome.element)
        }
        val rBytes = outcome.receiptBytes
        if (rBytes != null) {
            ctx.output(receiptTag!!, rBytes)
        }
        val dBytes = outcome.dlqBytes
        if (dBytes != null) {
            ctx.output(dlqTag!!, dBytes)
        }
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
