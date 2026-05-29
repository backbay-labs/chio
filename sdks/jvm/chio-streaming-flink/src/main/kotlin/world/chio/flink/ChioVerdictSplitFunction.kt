/**
 * ProcessFunction that fans out EvaluationResult from
 * ChioAsyncEvaluateFunction to main / receipt / DLQ side outputs.
 * Mirrors the Python ChioVerdictSplitFunction.
 *
 * Runtime cost is negligible when chained to the async operator (same
 * task thread, no serialisation).
 */
package world.chio.flink

import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.ProcessFunction
import org.apache.flink.util.Collector

class ChioVerdictSplitFunction<IN> : ProcessFunction<EvaluationResult<IN>, IN>() {
    @Transient
    private var receiptTag: org.apache.flink.util.OutputTag<ByteArray>? = null

    @Transient
    private var dlqTag: org.apache.flink.util.OutputTag<ByteArray>? = null

    override fun open(openContext: OpenContext) {
        super.open(openContext)
        receiptTag = ChioOutputTags.receiptTag()
        dlqTag = ChioOutputTags.dlqTag()
    }

    override fun processElement(
        value: EvaluationResult<IN>,
        ctx: ProcessFunction<EvaluationResult<IN>, IN>.Context,
        out: Collector<IN>,
    ) {
        if (value.allowed) {
            out.collect(value.element)
        }
        val rBytes = value.receiptBytes
        if (rBytes != null) {
            ctx.output(receiptTag!!, rBytes)
        }
        val dBytes = value.dlqBytes
        if (dBytes != null) {
            ctx.output(dlqTag!!, dBytes)
        }
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
