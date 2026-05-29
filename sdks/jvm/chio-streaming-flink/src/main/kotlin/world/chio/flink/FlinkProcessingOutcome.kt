/**
 * Full evaluation outcome produced by the sync operator and the shared
 * core. Mirrors the Python FlinkProcessingOutcome.
 */
package world.chio.flink

import world.chio.sdk.ChioReceipt
import world.chio.sdk.DlqRecord
import java.io.Serializable

data class FlinkProcessingOutcome<IN>(
    val allowed: Boolean,
    val receipt: ChioReceipt,
    val requestId: String,
    val element: IN,
    val subtaskIndex: Int? = null,
    val attemptNumber: Int? = null,
    val checkpointId: Long? = null,
    val receiptBytes: ByteArray? = null,
    val dlqBytes: ByteArray? = null,
    val dlqRecord: DlqRecord? = null,
    val acked: Boolean = false,
    val handlerError: Throwable? = null,
) : Serializable {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FlinkProcessingOutcome<*>) return false
        if (allowed != other.allowed) return false
        if (receipt != other.receipt) return false
        if (requestId != other.requestId) return false
        if (element != other.element) return false
        if (subtaskIndex != other.subtaskIndex) return false
        if (attemptNumber != other.attemptNumber) return false
        if (checkpointId != other.checkpointId) return false
        if ((receiptBytes == null) != (other.receiptBytes == null)) return false
        if (receiptBytes != null &&
            other.receiptBytes != null &&
            !receiptBytes.contentEquals(other.receiptBytes)
        ) {
            return false
        }
        if ((dlqBytes == null) != (other.dlqBytes == null)) return false
        if (dlqBytes != null &&
            other.dlqBytes != null &&
            !dlqBytes.contentEquals(other.dlqBytes)
        ) {
            return false
        }
        if (dlqRecord != other.dlqRecord) return false
        if (acked != other.acked) return false
        return true
    }

    override fun hashCode(): Int {
        var h = allowed.hashCode()
        h = 31 * h + receipt.hashCode()
        h = 31 * h + requestId.hashCode()
        h = 31 * h + (element?.hashCode() ?: 0)
        h = 31 * h + (subtaskIndex ?: 0)
        h = 31 * h + (attemptNumber ?: 0)
        h = 31 * h + (receiptBytes?.contentHashCode() ?: 0)
        h = 31 * h + (dlqBytes?.contentHashCode() ?: 0)
        return h
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
