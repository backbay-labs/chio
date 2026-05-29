package world.chio.sdk

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import world.chio.sdk.errors.ChioValidationError
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Tag("parity")
class DlqRouterTest {
    @Test
    fun payloadVersionPinned() {
        assertEquals("chio-streaming/dlq/v1", DlqRouter.DLQ_PAYLOAD_VERSION)
    }

    @Test
    fun routeHonoursExplicitMappingFirst() {
        val router =
            DlqRouter(
                defaultTopic = "dlq-fallback",
                topicMap = mapOf("orders" to "orders-dlq"),
            )
        assertEquals("orders-dlq", router.route("orders"))
    }

    @Test
    fun routeFallsBackToDefaultWhenMissing() {
        val router = DlqRouter(defaultTopic = "dlq-fallback")
        assertEquals("dlq-fallback", router.route("anything"))
    }

    @Test
    fun routeThrowsWhenNoMapping() {
        val router = DlqRouter()
        assertThrows<ChioValidationError> { router.route("topic") }
    }

    @Test
    fun routeRejectsEmptyTopic() {
        val router = DlqRouter(defaultTopic = "x")
        assertThrows<ChioValidationError> { router.route("") }
    }

    @Test
    fun buildRecordRejectsAllowReceipt() {
        val router = DlqRouter(defaultTopic = "dlq")
        assertThrows<ChioValidationError> {
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildAllowReceipt(),
            )
        }
    }

    @Test
    fun headerOrderPinned() {
        val router = DlqRouter(defaultTopic = "dlq")
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
            )
        val names = record.headers.map { it.first }
        assertEquals(
            listOf("X-Chio-Receipt", "X-Chio-Verdict", "X-Chio-Deny-Guard", "X-Chio-Deny-Reason"),
            names,
        )
        assertEquals("deny", String(record.headers[1].second, Charsets.UTF_8))
        assertEquals("G", String(record.headers[2].second, Charsets.UTF_8))
        assertEquals("blocked", String(record.headers[3].second, Charsets.UTF_8))
    }

    @Test
    fun keyFallsBackToRequestId() {
        val router = DlqRouter(defaultTopic = "dlq")
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req-42",
                receipt = buildDenyReceipt(),
            )
        assertTrue("req-42".toByteArray(Charsets.UTF_8).contentEquals(record.key))
    }

    @Test
    fun keyHonoursOriginalKey() {
        val router = DlqRouter(defaultTopic = "dlq")
        val originalKey = "kafka-key".toByteArray(Charsets.UTF_8)
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
                originalKey = originalKey,
            )
        assertTrue(originalKey.contentEquals(record.key))
    }

    @Test
    fun originalValueEncodingUtf8() {
        val router = DlqRouter(defaultTopic = "dlq")
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
                originalValue = """{"hello":"world"}""".toByteArray(Charsets.UTF_8),
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(record.value)

        @Suppress("UNCHECKED_CAST")
        val ov = parsed["original_value"] as Map<String, Any?>
        assertTrue(ov.containsKey("utf8"))
        assertEquals("""{"hello":"world"}""", ov["utf8"])
    }

    @Test
    fun originalValueEncodingHex() {
        val router = DlqRouter(defaultTopic = "dlq")
        // 0xff 0xfe 0xfd is not valid UTF-8.
        val bytes = byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0xFD.toByte())
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
                originalValue = bytes,
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(record.value)

        @Suppress("UNCHECKED_CAST")
        val ov = parsed["original_value"] as Map<String, Any?>
        assertTrue(ov.containsKey("hex"))
        assertEquals("fffefd", ov["hex"])
    }

    @Test
    fun sourceFieldsPresentWithNullsWhenNotSupplied() {
        val router = DlqRouter(defaultTopic = "dlq")
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(record.value)

        @Suppress("UNCHECKED_CAST")
        val source = parsed["source"] as Map<String, Any?>
        assertEquals("src", source["topic"])
        assertTrue(source.containsKey("partition"))
        assertNull(source["partition"])
        assertTrue(source.containsKey("offset"))
        assertNull(source["offset"])
    }

    @Test
    fun payloadVersionAndVerdictPinned() {
        val router = DlqRouter(defaultTopic = "dlq")
        val record =
            router.buildRecord(
                sourceTopic = "src",
                requestId = "req",
                receipt = buildDenyReceipt(),
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(record.value)
        assertEquals("chio-streaming/dlq/v1", parsed["version"])
        assertEquals("deny", parsed["verdict"])
        assertEquals("blocked", parsed["reason"])
        assertEquals("G", parsed["guard"])
    }

    @Test
    fun topicForAndDefaultTopicAccessors() {
        val router =
            DlqRouter(
                defaultTopic = "fallback",
                topicMap = mapOf("a" to "a-dlq"),
            )
        assertEquals("a-dlq", router.topicFor("a"))
        assertNull(router.topicFor("missing"))
        assertEquals("fallback", router.defaultTopic())
    }

    private fun buildAllowReceipt(): ChioReceipt =
        ChioReceipt(
            id = "r1",
            timestamp = 1L,
            capabilityId = "cap",
            toolServer = "s",
            toolName = "t",
            action = ToolCallAction(parameters = emptyMap(), parameterHash = "h"),
            decision = Decision.allow(),
            receiptKind = "mediated_decision",
            boundaryClass = "prevent",
            toolOrigin = "caller_executed",
            redactionMode = "none",
            trustLevel = "mediated",
            contentHash = "c",
            policyHash = "p",
            evidence = emptyList(),
            kernelKey = "k",
            signature = "s",
        )

    private fun buildDenyReceipt(): ChioReceipt = buildAllowReceipt().copy(decision = Decision.deny("blocked", "G"))
}
