/**
 * Canonical body bytes for the default parameters extractor. Mirrors
 * the Python _canonical_body_bytes.
 */
package world.chio.flink

import world.chio.sdk.CanonicalJson
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

internal object BodyCoercion {
    /**
     * Encoding rules (matching the Python equivalent):
     * 1. ByteArray / ByteBuffer passthrough.
     * 2. String encodes as UTF-8.
     * 3. Map canonical JSON via CanonicalJson.writeBytes.
     * 4. Fallback: element.toString().toByteArray(UTF_8).
     *
     * Null short-circuits to "None" bytes to match Python's
     * ``str(None).encode("utf-8")``; Kotlin's ``null.toString()`` would NPE.
     */
    @JvmStatic
    fun canonicalBodyBytes(element: Any?): ByteArray =
        when (element) {
            null -> "None".toByteArray(StandardCharsets.UTF_8)
            is ByteArray -> element
            is ByteBuffer -> {
                val buf = element.duplicate()
                val out = ByteArray(buf.remaining())
                buf.get(out)
                out
            }
            is String -> element.toByteArray(StandardCharsets.UTF_8)
            is Map<*, *> ->
                try {
                    CanonicalJson.writeBytes(element)
                } catch (_: Exception) {
                    element.toString().toByteArray(StandardCharsets.UTF_8)
                }
            else -> element.toString().toByteArray(StandardCharsets.UTF_8)
        }
}
