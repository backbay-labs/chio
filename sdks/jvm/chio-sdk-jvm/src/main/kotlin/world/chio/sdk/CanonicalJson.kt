/**
 * Canonical JSON serialization for byte-identical output with the
 * Python SDK and Rust kernel. Mirrors chio_sdk.client._canonical_json
 * and chio_streaming.receipt.canonical_json.
 *
 * Guarantees:
 * - Map keys sorted alphabetically (code-point order).
 * - POJO properties sorted alphabetically.
 * - Non-ASCII characters escaped as \uXXXX (lowercase hex, matching
 *   Python's json.dumps(ensure_ascii=True)).
 * - No insignificant whitespace (separators = "," and ":").
 * - Null map values round-trip (serialise as null, not dropped).
 */
package world.chio.sdk

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.json.JsonWriteFeature
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.KotlinModule

object CanonicalJson {
    /**
     * ObjectMapper configured for byte-identical output vs Python's
     * json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True).
     *
     * Jackson's ESCAPE_NON_ASCII emits uppercase \uXXXX hex; Python uses
     * lowercase. See [writeBytes] / [writeString] for the post-processing
     * step that lowercases the hex.
     */
    @JvmStatic
    val MAPPER: ObjectMapper = buildMapper()

    /**
     * Serialize value to canonical JSON bytes. Sorts map keys,
     * alphabetises POJO properties, escapes non-ASCII.
     */
    @JvmStatic
    fun writeBytes(value: Any?): ByteArray {
        val raw = MAPPER.writeValueAsBytes(value)
        return lowercaseUnicodeEscapes(raw)
    }

    /** Same as [writeBytes] but returns a String. Prefer bytes where the consumer hashes. */
    @JvmStatic
    fun writeString(value: Any?): String = String(writeBytes(value), Charsets.UTF_8)

    private fun buildMapper(): ObjectMapper {
        val factory =
            JsonFactory()
                .enable(JsonWriteFeature.ESCAPE_NON_ASCII.mappedFeature())
        val mapper =
            ObjectMapper(factory)
                .registerModule(KotlinModule.Builder().build())
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
                .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true)
                .configure(SerializationFeature.INDENT_OUTPUT, false)
        // Property-level: NON_NULL so POJO null fields are dropped (matches
        // Python Pydantic model_dump(exclude_none=True)). Content-level:
        // ALWAYS so null values inside Map / List containers are preserved
        // (matches Python json.dumps({"a": None}) -> '{"a":null}').
        mapper.setDefaultPropertyInclusion(
            JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.ALWAYS),
        )
        return mapper
    }

    /**
     * Replace each "\uXXXX" escape's hex digits with lowercase, matching
     * Python's json.dumps output byte-for-byte. Scans ASCII-safe bytes
     * because the escape sequence is pure ASCII by definition.
     */
    private fun lowercaseUnicodeEscapes(src: ByteArray): ByteArray {
        val n = src.size
        if (n < 6) return src
        val out = src.copyOf()
        var i = 0
        val dst = out
        val backslash = '\\'.code.toByte()
        val u = 'u'.code.toByte()
        while (i <= n - 6) {
            if (dst[i] == backslash &&
                dst[i + 1] == u &&
                isHex(dst[i + 2]) &&
                isHex(dst[i + 3]) &&
                isHex(dst[i + 4]) &&
                isHex(dst[i + 5])
            ) {
                dst[i + 2] = toLower(dst[i + 2])
                dst[i + 3] = toLower(dst[i + 3])
                dst[i + 4] = toLower(dst[i + 4])
                dst[i + 5] = toLower(dst[i + 5])
                i += 6
            } else {
                i++
            }
        }
        return dst
    }

    private fun isHex(b: Byte): Boolean {
        val c = b.toInt() and 0xFF
        return (c in '0'.code..'9'.code) ||
            (c in 'a'.code..'f'.code) ||
            (c in 'A'.code..'F'.code)
    }

    private fun toLower(b: Byte): Byte {
        val c = b.toInt() and 0xFF
        return if (c in 'A'.code..'F'.code) (c + 32).toByte() else b
    }
}
