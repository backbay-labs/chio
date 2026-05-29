package world.chio.flink

import org.junit.jupiter.api.Test
import world.chio.sdk.CanonicalJson
import world.chio.sdk.Hashing
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DefaultParametersExtractorTest {
    @Test
    fun defaultFieldsMatch() {
        val params =
            DefaultParametersExtractor.extract(
                element = "hello",
                requestId = "req-1",
                subject = "topic",
            )
        assertEquals(setOf("request_id", "subject", "body_length", "body_hash"), params.keys)
        assertEquals("req-1", params["request_id"])
        assertEquals("topic", params["subject"])
        assertEquals(5L, params["body_length"])
        assertNotNull(params["body_hash"])
    }

    @Test
    fun bodyHashMatchesCanonicalSha256ForMap() {
        val element = mapOf("a" to 1, "b" to listOf(1, 2, 3))
        val params = DefaultParametersExtractor.extract(element, "r", "s")
        val expected = Hashing.sha256Hex(CanonicalJson.writeBytes(element))
        assertEquals(expected, params["body_hash"])
        assertEquals(CanonicalJson.writeBytes(element).size.toLong(), params["body_length"])
    }

    @Test
    fun stringFallbackCoercesViaToString() {
        val params =
            DefaultParametersExtractor.extract(
                element = 42,
                requestId = "r",
                subject = "s",
            )
        // str(42) = "42" bytes, hashed.
        val expected = Hashing.sha256Hex("42".toByteArray(Charsets.UTF_8))
        assertEquals(expected, params["body_hash"])
        assertEquals(2L, params["body_length"])
    }

    @Test
    fun byteArrayPassthrough() {
        val bytes = byteArrayOf(0x01, 0x02, 0x03)
        val params = DefaultParametersExtractor.extract(bytes, "r", "s")
        assertEquals(Hashing.sha256Hex(bytes), params["body_hash"])
        assertEquals(3L, params["body_length"])
    }
}
