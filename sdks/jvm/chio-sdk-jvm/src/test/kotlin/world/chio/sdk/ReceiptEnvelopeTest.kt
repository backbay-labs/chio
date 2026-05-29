package world.chio.sdk

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import world.chio.sdk.errors.ChioValidationError
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReceiptEnvelopeTest {
    @Test
    fun versionPinned() {
        assertEquals("chio-streaming/v1", ReceiptEnvelope.ENVELOPE_VERSION)
    }

    @Test
    fun buildProducesCanonicalJsonWithVersionTag() {
        val receipt = buildDummyReceipt()
        val env = ReceiptEnvelope.build(requestId = "req-1", receipt = receipt)
        val parsed: Map<String, Any?> =
            jacksonObjectMapper().readValue(env.value)
        assertEquals("chio-streaming/v1", parsed["version"])
        assertEquals("req-1", parsed["request_id"])
        assertEquals("allow", parsed["verdict"])
    }

    @Test
    fun buildHeadersMatchExpected() {
        val receipt = buildDummyReceipt()
        val env = ReceiptEnvelope.build(requestId = "req", receipt = receipt)
        val names = env.headers.map { it.first }
        assertEquals(listOf("X-Chio-Receipt", "X-Chio-Verdict"), names)
        assertEquals(receipt.id, String(env.headers[0].second, Charsets.UTF_8))
        assertEquals("allow", String(env.headers[1].second, Charsets.UTF_8))
    }

    @Test
    fun keyIsRequestIdUtf8() {
        val receipt = buildDummyReceipt()
        val env = ReceiptEnvelope.build(requestId = "rid", receipt = receipt)
        assertTrue("rid".toByteArray(Charsets.UTF_8).contentEquals(env.key))
        assertEquals("rid", env.requestId)
    }

    @Test
    fun buildRejectsEmptyRequestId() {
        assertThrows<ChioValidationError> {
            ReceiptEnvelope.build(requestId = "", receipt = buildDummyReceipt())
        }
    }

    @Test
    fun sourceFieldsOmittedWhenNull() {
        val env =
            ReceiptEnvelope.build(
                requestId = "r",
                receipt = buildDummyReceipt(),
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(env.value)
        assertFalse(parsed.containsKey("source_topic"))
        assertFalse(parsed.containsKey("source_partition"))
        assertFalse(parsed.containsKey("source_offset"))
        assertFalse(parsed.containsKey("metadata"))
    }

    @Test
    fun sourceFieldsPresentWhenSupplied() {
        val env =
            ReceiptEnvelope.build(
                requestId = "r",
                receipt = buildDummyReceipt(),
                sourceTopic = "events",
                sourcePartition = 3,
                sourceOffset = 42L,
                extraMetadata = mapOf("k" to "v"),
            )
        val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(env.value)
        assertEquals("events", parsed["source_topic"])
        assertEquals(3, (parsed["source_partition"] as Number).toInt())
        assertEquals(42L, (parsed["source_offset"] as Number).toLong())
        @Suppress("UNCHECKED_CAST")
        assertEquals("v", (parsed["metadata"] as Map<String, Any?>)["k"])
    }

    @Test
    fun denyEnvelopeCarriesDenyVerdictHeader() {
        val receipt = buildDummyDenyReceipt()
        val env = ReceiptEnvelope.build(requestId = "r", receipt = receipt)
        assertEquals("deny", String(env.headers[1].second, Charsets.UTF_8))
    }

    private fun buildDummyReceipt(): ChioReceipt =
        ChioReceipt(
            id = "receipt-id",
            timestamp = 1_700_000_000L,
            capabilityId = "cap",
            toolServer = "srv",
            toolName = "events:consume:topic",
            action = ToolCallAction(parameters = mapOf("a" to 1), parameterHash = "p"),
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

    private fun buildDummyDenyReceipt(): ChioReceipt = buildDummyReceipt().copy(decision = Decision.deny("r", "g"))
}
