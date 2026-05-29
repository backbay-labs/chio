package world.chio.sdk

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class HashingTest {
    @Test
    fun sha256HexEmptyString() {
        // RFC 6234 known vector for the empty input.
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Hashing.sha256Hex(""),
        )
    }

    @Test
    fun sha256HexShortString() {
        // Known vector: "abc"
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Hashing.sha256Hex("abc"),
        )
    }

    @Test
    fun sha256HexBytesMatchesString() {
        val viaStr = Hashing.sha256Hex("hello")
        val viaBytes = Hashing.sha256Hex("hello".toByteArray(Charsets.UTF_8))
        assertEquals(viaStr, viaBytes)
    }

    @Test
    fun hashBodyNullReturnsNull() {
        assertNull(Hashing.hashBody(null))
    }

    @Test
    fun hashBodyEmptyReturnsNull() {
        assertNull(Hashing.hashBody(ByteArray(0)))
    }

    @Test
    fun hashBodyNonEmptyReturnsHex() {
        val bytes = "abc".toByteArray(Charsets.UTF_8)
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Hashing.hashBody(bytes),
        )
    }
}
