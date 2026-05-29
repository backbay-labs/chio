/**
 * SHA-256 hex helpers. Mirrors chio_streaming.core.hash_body.
 */
package world.chio.sdk

import java.security.MessageDigest

object Hashing {
    private val HEX = "0123456789abcdef".toCharArray()

    @JvmStatic
    fun sha256Hex(input: String): String = sha256Hex(input.toByteArray(Charsets.UTF_8))

    @JvmStatic
    fun sha256Hex(input: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(input)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            val v = b.toInt() and 0xFF
            sb.append(HEX[v ushr 4])
            sb.append(HEX[v and 0xF])
        }
        return sb.toString()
    }

    /** Hex SHA-256 or null for null/empty input. */
    @JvmStatic
    fun hashBody(input: ByteArray?): String? {
        if (input == null || input.isEmpty()) {
            return null
        }
        return sha256Hex(input)
    }
}
