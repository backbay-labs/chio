package world.chio.flink.support

import world.chio.sdk.ChioReceipt
import world.chio.sdk.DlqRecord
import world.chio.sdk.DlqRouter
import java.io.Serializable
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Records every buildRecord call for assertions while still producing
 * wire-canonical DLQ records via the real DlqRouter.
 */
class FakeDlqRouter(
    private val delegate: DlqRouter = DlqRouter(defaultTopic = "chio-dlq"),
) : Serializable {
    @Transient
    val records: MutableList<DlqRecord> = CopyOnWriteArrayList()

    fun asRouter(): DlqRouter = delegate

    fun buildRecord(
        sourceTopic: String,
        requestId: String,
        receipt: ChioReceipt,
    ): DlqRecord {
        val record =
            delegate.buildRecord(
                sourceTopic = sourceTopic,
                requestId = requestId,
                receipt = receipt,
            )
        records.add(record)
        return record
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
