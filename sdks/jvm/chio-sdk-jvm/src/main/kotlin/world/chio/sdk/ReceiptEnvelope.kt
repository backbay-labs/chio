/**
 * Canonical envelope emitted to the receipt side output. Mirrors
 * chio_streaming.receipt.build_envelope and ReceiptEnvelope.
 */
package world.chio.sdk

import world.chio.sdk.errors.ChioValidationError
import java.io.Serializable

data class ReceiptEnvelope(
    val key: ByteArray,
    val value: ByteArray,
    val headers: List<Pair<String, ByteArray>>,
    val requestId: String,
    val receiptId: String,
) : Serializable {
    // data class equals/hashCode on ByteArray would compare identity; override
    // with content equality so tests match Python semantics.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ReceiptEnvelope) return false
        if (!key.contentEquals(other.key)) return false
        if (!value.contentEquals(other.value)) return false
        if (headers.size != other.headers.size) return false
        for (i in headers.indices) {
            if (headers[i].first != other.headers[i].first) return false
            if (!headers[i].second.contentEquals(other.headers[i].second)) return false
        }
        if (requestId != other.requestId) return false
        if (receiptId != other.receiptId) return false
        return true
    }

    override fun hashCode(): Int {
        var result = key.contentHashCode()
        result = 31 * result + value.contentHashCode()
        result = 31 * result + requestId.hashCode()
        result = 31 * result + receiptId.hashCode()
        return result
    }

    companion object {
        private const val serialVersionUID: Long = 1L

        /** Envelope schema version. Bump on any breaking wire change. */
        const val ENVELOPE_VERSION: String = "chio-streaming/v1"

        /** Header carrying the receipt id on produced events. */
        const val RECEIPT_HEADER: String = "X-Chio-Receipt"

        /** Header carrying the verdict ("allow" / "deny"). */
        const val VERDICT_HEADER: String = "X-Chio-Verdict"

        /** Serialise [receipt] into a broker-friendly envelope. */
        @JvmOverloads
        @JvmStatic
        fun build(
            requestId: String,
            receipt: ChioReceipt,
            sourceTopic: String? = null,
            sourcePartition: Int? = null,
            sourceOffset: Long? = null,
            extraMetadata: Map<String, Any?>? = null,
        ): ReceiptEnvelope {
            if (requestId.isEmpty()) {
                throw ChioValidationError("build_envelope requires a non-empty request_id")
            }
            val verdict =
                when {
                    receipt.isAllowed() -> "allow"
                    receipt.isDenied() -> "deny"
                    else -> "none"
                }
            val metadata: Map<String, Any?> = extraMetadata ?: emptyMap()

            val payload =
                linkedMapOf<String, Any?>(
                    "version" to ENVELOPE_VERSION,
                    "request_id" to requestId,
                    "verdict" to verdict,
                    "receipt" to receiptAsMap(receipt),
                )
            if (sourceTopic != null) payload["source_topic"] = sourceTopic
            if (sourcePartition != null) payload["source_partition"] = sourcePartition.toLong()
            if (sourceOffset != null) payload["source_offset"] = sourceOffset
            if (metadata.isNotEmpty()) payload["metadata"] = metadata

            val value = CanonicalJson.writeBytes(payload)
            val headers =
                listOf(
                    RECEIPT_HEADER to receipt.id.toByteArray(Charsets.UTF_8),
                    VERDICT_HEADER to verdict.toByteArray(Charsets.UTF_8),
                )
            return ReceiptEnvelope(
                key = requestId.toByteArray(Charsets.UTF_8),
                value = value,
                headers = headers,
                requestId = requestId,
                receiptId = receipt.id,
            )
        }

        internal fun receiptAsMap(receipt: ChioReceipt): Map<String, Any?> {
            @Suppress("UNCHECKED_CAST")
            return CanonicalJson.MAPPER.convertValue(receipt, Map::class.java) as Map<String, Any?>
        }
    }
}
