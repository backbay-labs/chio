package world.chio.flink

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import world.chio.sdk.CanonicalJson
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Tag("parity")
class BodyCoercionTest {
    @Test
    fun nullMatchesPythonStrNoneEncoding() {
        // Python's _canonical_body_bytes falls through to
        // str(None).encode("utf-8"), which is the four-byte payload "None".
        val expected = "None".toByteArray(StandardCharsets.UTF_8)
        val actual = BodyCoercion.canonicalBodyBytes(null)
        assertTrue(expected.contentEquals(actual), "null should encode to bytes 'None', got ${String(actual)}")
    }

    @Test
    fun stringEncodesUtf8() {
        val expected = "hello".toByteArray(StandardCharsets.UTF_8)
        val actual = BodyCoercion.canonicalBodyBytes("hello")
        assertTrue(expected.contentEquals(actual))
    }

    @Test
    fun byteArrayPassesThrough() {
        val bytes = byteArrayOf(0x01, 0x02, 0x03)
        val actual = BodyCoercion.canonicalBodyBytes(bytes)
        assertTrue(bytes.contentEquals(actual))
    }

    @Test
    fun byteBufferCopiesRemainingBytes() {
        val buf = ByteBuffer.wrap(byteArrayOf(0x0A, 0x0B, 0x0C, 0x0D))
        buf.position(1)
        val actual = BodyCoercion.canonicalBodyBytes(buf)
        assertTrue(byteArrayOf(0x0B, 0x0C, 0x0D).contentEquals(actual))
    }

    @Test
    fun mapCanonicalJson() {
        val element = mapOf("b" to 2, "a" to 1)
        val expected = CanonicalJson.writeBytes(element)
        val actual = BodyCoercion.canonicalBodyBytes(element)
        assertTrue(expected.contentEquals(actual))
    }

    @Test
    fun fallbackUsesToString() {
        val actual = BodyCoercion.canonicalBodyBytes(42)
        assertEquals("42", String(actual, StandardCharsets.UTF_8))
    }
}
