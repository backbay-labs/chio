/**
 * Build DLQ records for denied evaluations. Mirrors DLQRouter in
 * chio_streaming/dlq.py.
 *
 * Routing precedence (highest wins):
 * 1. Exact match on topicMap[sourceTopic].
 * 2. defaultTopic fallback.
 * 3. ChioValidationError if neither is configured.
 *
 * Payload invariants (dlq.py):
 * - Input receipt MUST be a deny; otherwise throws ChioValidationError.
 * - Payload version: "chio-streaming/dlq/v1".
 * - Payload keys in fixed order after canonicalisation:
 *   version, request_id, verdict, reason, guard, receipt_id, receipt,
 *   source, metadata?, original_value?.
 * - source.partition / source.offset are null when not supplied, not omitted.
 * - Headers: X-Chio-Receipt, X-Chio-Verdict=deny, X-Chio-Deny-Guard,
 *   X-Chio-Deny-Reason.
 * - key = originalKey ?: requestId.utf8.
 * - original_value encoded as {"utf8": ...} if decodes, else {"hex": ...}.
 */
package world.chio.sdk

import world.chio.sdk.errors.ChioValidationError
import java.io.Serializable
import java.nio.charset.StandardCharsets

class DlqRouter
    @JvmOverloads
    constructor(
        private val defaultTopic: String? = null,
        topicMap: Map<String, String> = emptyMap(),
        private val includeOriginalValue: Boolean = true,
    ) : Serializable {
        private val topicMap: Map<String, String> = LinkedHashMap(topicMap)

        init {
            if (defaultTopic != null && defaultTopic.isEmpty()) {
                throw ChioValidationError("defaultTopic must be a non-empty string or null")
            }
        }

        /** Return the DLQ topic for [sourceTopic]. */
        fun route(sourceTopic: String): String {
            if (sourceTopic.isEmpty()) {
                throw ChioValidationError("route() requires a non-empty source_topic")
            }
            val mapped = topicMap[sourceTopic]
            if (mapped != null) return mapped
            if (!defaultTopic.isNullOrEmpty()) return defaultTopic
            throw ChioValidationError(
                "no DLQ topic configured for source_topic=$sourceTopic and no default_topic is set",
            )
        }

        @JvmOverloads
        fun buildRecord(
            sourceTopic: String,
            sourcePartition: Int? = null,
            sourceOffset: Long? = null,
            originalKey: ByteArray? = null,
            originalValue: ByteArray? = null,
            requestId: String,
            receipt: ChioReceipt,
            extraMetadata: Map<String, Any?>? = null,
        ): DlqRecord {
            if (!receipt.isDenied()) {
                throw ChioValidationError(
                    "DlqRouter.buildRecord called with a non-deny receipt; the DLQ path is reserved for denials",
                )
            }
            val decision =
                receipt.decision
                    ?: throw ChioValidationError(
                        "DlqRouter.buildRecord called with a decisionless receipt; the DLQ path is reserved for denials",
                    )
            val reason = decision.reason ?: "denied by Chio kernel"
            val guard = decision.guard ?: "unknown"

            // LinkedHashMap preserves insertion order. CanonicalJson will
            // re-sort keys alphabetically on serialize; the plan doc
            // references an "insertion order" invariant but the Python
            // output is SORTED by json.dumps(sort_keys=True). Match Python.
            val source =
                linkedMapOf<String, Any?>(
                    "topic" to sourceTopic,
                    "partition" to sourcePartition?.toLong(),
                    "offset" to sourceOffset,
                )
            val payload =
                linkedMapOf<String, Any?>(
                    "version" to DLQ_PAYLOAD_VERSION,
                    "request_id" to requestId,
                    "verdict" to "deny",
                    "reason" to reason,
                    "guard" to guard,
                    "receipt_id" to receipt.id,
                    "receipt" to ReceiptEnvelope.receiptAsMap(receipt),
                    "source" to source,
                )
            val metadata = extraMetadata ?: emptyMap()
            if (metadata.isNotEmpty()) payload["metadata"] = metadata
            if (includeOriginalValue && originalValue != null) {
                payload["original_value"] = encodeOriginalValue(originalValue)
            }

            val headers =
                listOf(
                    ReceiptEnvelope.RECEIPT_HEADER to receipt.id.toByteArray(Charsets.UTF_8),
                    ReceiptEnvelope.VERDICT_HEADER to "deny".toByteArray(Charsets.UTF_8),
                    "X-Chio-Deny-Guard" to guard.toByteArray(Charsets.UTF_8),
                    "X-Chio-Deny-Reason" to reason.toByteArray(Charsets.UTF_8),
                )
            val key = originalKey ?: requestId.toByteArray(Charsets.UTF_8)
            return DlqRecord(
                topic = route(sourceTopic),
                key = key,
                value = CanonicalJson.writeBytes(payload),
                headers = headers,
            )
        }

        /** Return the explicit mapping for [sourceTopic] (null if unset). */
        fun topicFor(sourceTopic: String): String? = topicMap[sourceTopic]

        /** Return the configured fallback DLQ topic (null if unset). */
        fun defaultTopic(): String? = defaultTopic

        companion object {
            private const val serialVersionUID: Long = 1L
            const val DLQ_PAYLOAD_VERSION: String = "chio-streaming/dlq/v1"

            private fun encodeOriginalValue(value: ByteArray): Map<String, Any?> =
                try {
                    val decoded = String(value, StandardCharsets.UTF_8)
                    // Round-trip check: encoding back must match for the bytes
                    // to be "clean" UTF-8. Otherwise fall back to hex.
                    val back = decoded.toByteArray(StandardCharsets.UTF_8)
                    if (back.contentEquals(value)) {
                        mapOf("utf8" to decoded)
                    } else {
                        mapOf("hex" to toHex(value))
                    }
                } catch (_: Exception) {
                    mapOf("hex" to toHex(value))
                }

            private fun toHex(bytes: ByteArray): String {
                val hex = "0123456789abcdef".toCharArray()
                val sb = StringBuilder(bytes.size * 2)
                for (b in bytes) {
                    val v = b.toInt() and 0xFF
                    sb.append(hex[v ushr 4])
                    sb.append(hex[v and 0xF])
                }
                return sb.toString()
            }
        }
    }
