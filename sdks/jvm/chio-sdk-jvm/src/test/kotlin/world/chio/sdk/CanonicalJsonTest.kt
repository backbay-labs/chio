package world.chio.sdk

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

@Tag("parity")
class CanonicalJsonTest {
    @Test
    fun matchesPythonVectorMapSorted() {
        // Vector 1 from plan section 3: nested map with unicode.
        // Python: json.dumps({"b":2,"a":{"cafe":"café","xyz":1}},
        //         sort_keys=True, separators=(",",":"), ensure_ascii=True)
        // -> '{"a":{"cafe":"caf\\u00e9","xyz":1},"b":2}'
        val input =
            mapOf(
                "b" to 2,
                "a" to mapOf("cafe" to "café", "xyz" to 1),
            )
        val expected = "{\"a\":{\"cafe\":\"caf\\u00e9\",\"xyz\":1},\"b\":2}"
        assertEquals(expected, CanonicalJson.writeString(input))
        assertEquals(expected, String(CanonicalJson.writeBytes(input), Charsets.UTF_8))
    }

    @Test
    fun matchesPythonVectorUnicodeEscapes() {
        // Vector 2: emoji (surrogate pair), uppercase sorts before lowercase.
        // Python expected: '{"0":"\\ud83d\\udca1","Z":"b","z":"a"}'
        val input =
            mapOf(
                "z" to "a",
                "Z" to "b",
                "0" to "💡",
            )
        val expected = "{\"0\":\"\\ud83d\\udca1\",\"Z\":\"b\",\"z\":\"a\"}"
        assertEquals(expected, CanonicalJson.writeString(input))
    }

    @Test
    fun nullMapValueRoundTrips() {
        // Vector 3: null map values, nested array with mixed types.
        // Python expected: '{"arr":[1,"two",{"k":3}],"flag":true,"null_field":null}'
        val input =
            mapOf<String, Any?>(
                "null_field" to null,
                "arr" to listOf<Any>(1, "two", mapOf("k" to 3L)),
                "flag" to true,
            )
        val expected = "{\"arr\":[1,\"two\",{\"k\":3}],\"flag\":true,\"null_field\":null}"
        assertEquals(expected, CanonicalJson.writeString(input))
    }

    @Test
    fun emptyMapSerialises() {
        assertEquals("{}", CanonicalJson.writeString(emptyMap<String, Any?>()))
    }

    @Test
    fun emptyListSerialises() {
        assertEquals("[]", CanonicalJson.writeString(emptyList<Any?>()))
    }

    @Test
    fun deeplyNestedMapRoundTrips() {
        val input =
            mapOf(
                "a" to
                    mapOf(
                        "b" to
                            mapOf(
                                "c" to listOf(1, 2, mapOf("d" to "e")),
                            ),
                    ),
            )
        val expected = "{\"a\":{\"b\":{\"c\":[1,2,{\"d\":\"e\"}]}}}"
        assertEquals(expected, CanonicalJson.writeString(input))
    }
}
