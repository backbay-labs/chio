/**
 * Per-element record the async operator emits. Mirrors the Python
 * EvaluationResult.
 *
 * The async operator yields exactly one EvaluationResult per input,
 * which the downstream ChioVerdictSplitFunction fans out to main /
 * receipt / DLQ side outputs.
 */
package world.chio.flink

import java.io.Serializable

data class EvaluationResult<IN>(
    val allowed: Boolean,
    val element: IN,
    val receiptBytes: ByteArray? = null,
    val dlqBytes: ByteArray? = null,
) : Serializable {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EvaluationResult<*>) return false
        if (allowed != other.allowed) return false
        if (element != other.element) return false
        if (receiptBytes == null) {
            if (other.receiptBytes != null) return false
        } else {
            if (other.receiptBytes == null) return false
            if (!receiptBytes.contentEquals(other.receiptBytes)) return false
        }
        if (dlqBytes == null) {
            if (other.dlqBytes != null) return false
        } else {
            if (other.dlqBytes == null) return false
            if (!dlqBytes.contentEquals(other.dlqBytes)) return false
        }
        return true
    }

    override fun hashCode(): Int {
        var h = allowed.hashCode()
        h = 31 * h + (element?.hashCode() ?: 0)
        h = 31 * h + (receiptBytes?.contentHashCode() ?: 0)
        h = 31 * h + (dlqBytes?.contentHashCode() ?: 0)
        return h
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
