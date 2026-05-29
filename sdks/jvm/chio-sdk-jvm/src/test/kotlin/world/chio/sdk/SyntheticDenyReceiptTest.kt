package world.chio.sdk

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Tag("parity")
class SyntheticDenyReceiptTest {
    @Test
    fun markerValueIsWireStable() {
        assertEquals("chio-streaming/synthetic-deny/v1", SyntheticDenyReceipt.MARKER)
    }

    @Test
    fun reasonPrefixAppliedOnce() {
        val once =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "sidecar down",
                guard = "chio-streaming-sidecar",
            )
        assertEquals("[unsigned] sidecar down", once.decision?.reason)

        val twice =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "[unsigned] sidecar down",
                guard = "g",
            )
        assertEquals("[unsigned] sidecar down", twice.decision?.reason)
    }

    @Test
    fun kernelKeyAndSignatureEmpty() {
        val r =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "r",
                guard = "g",
            )
        assertEquals("", r.kernelKey)
        assertEquals("", r.signature)
    }

    @Test
    fun metadataContainsMarker() {
        val r =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "r",
                guard = "g",
            )
        assertTrue(r.metadata!!.containsKey("chio_streaming_synthetic"))
        assertEquals(true, r.metadata!!["chio_streaming_synthetic"])
        assertEquals(
            SyntheticDenyReceipt.MARKER,
            r.metadata!!["chio_streaming_synthetic_marker"],
        )
    }

    @Test
    fun parameterHashMatchesCanonicalSha256() {
        val params: Map<String, Any?> = mapOf("b" to 2, "a" to 1)
        val r =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = params,
                reason = "r",
                guard = "g",
            )
        val expected = Hashing.sha256Hex(CanonicalJson.writeBytes(params))
        assertEquals(expected, r.action.parameterHash)
        assertEquals(expected, r.contentHash)
        assertEquals("", r.policyHash)
        assertTrue(r.evidence.isEmpty())
    }

    @Test
    fun suppliedClockAndIdSupplierAreUsed() {
        val r =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "r",
                guard = "g",
                clock = { 4242L },
                idSupplier = { "fixed-id" },
            )
        assertEquals(4242L, r.timestamp)
        assertEquals("fixed-id", r.id)
    }

    @Test
    fun isDeniedByConstruction() {
        val r =
            SyntheticDenyReceipt.synthesize(
                capabilityId = "cap",
                toolServer = "s",
                toolName = "t",
                parameters = emptyMap(),
                reason = "r",
                guard = "g",
            )
        assertTrue(r.isDenied())
    }
}
