/**
 * Dead-letter-queue wire record. Mirrors DLQRecord in
 * chio_streaming/dlq.py.
 */
package world.chio.sdk

import java.io.Serializable

data class DlqRecord(
    val topic: String,
    val key: ByteArray,
    val value: ByteArray,
    val headers: List<Pair<String, ByteArray>>,
) : Serializable {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DlqRecord) return false
        if (topic != other.topic) return false
        if (!key.contentEquals(other.key)) return false
        if (!value.contentEquals(other.value)) return false
        if (headers.size != other.headers.size) return false
        for (i in headers.indices) {
            if (headers[i].first != other.headers[i].first) return false
            if (!headers[i].second.contentEquals(other.headers[i].second)) return false
        }
        return true
    }

    override fun hashCode(): Int {
        var h = topic.hashCode()
        h = 31 * h + key.contentHashCode()
        h = 31 * h + value.contentHashCode()
        return h
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
