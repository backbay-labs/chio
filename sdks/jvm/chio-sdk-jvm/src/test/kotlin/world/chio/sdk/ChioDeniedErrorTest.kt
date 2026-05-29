package world.chio.sdk

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import world.chio.sdk.errors.ChioDeniedError
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ChioDeniedErrorTest {
    private val mapper = ObjectMapper()

    @Test
    fun fromWireAcceptsAll11Fields() {
        val data =
            mapOf<String, Any?>(
                "message" to "denied by guard",
                "guard" to "CapabilityGuard",
                "reason" to "missing scope",
                "tool_name" to "delete_user",
                "tool_server" to "user-service",
                "requested_action" to "delete",
                "required_scope" to "tools:delete_user",
                "granted_scope" to "tools:read_user",
                "reason_code" to "MISSING_SCOPE",
                "receipt_id" to "receipt-123",
                "hint" to "mint a token with delete scope",
                "docs_url" to "https://docs.example/caps",
            )
        val err = ChioDeniedError.fromWire(data)

        assertEquals("denied by guard", err.message)
        assertEquals("CapabilityGuard", err.guard)
        assertEquals("missing scope", err.reason)
        assertEquals("delete_user", err.toolName)
        assertEquals("user-service", err.toolServer)
        assertEquals("delete", err.requestedAction)
        assertEquals("tools:delete_user", err.requiredScope)
        assertEquals("tools:read_user", err.grantedScope)
        assertEquals("MISSING_SCOPE", err.reasonCode)
        assertEquals("receipt-123", err.receiptId)
        assertEquals("mint a token with delete scope", err.hint)
        assertEquals("https://docs.example/caps", err.docsUrl)
    }

    @Test
    fun fromWireFallbackReasonAsMessage() {
        val err = ChioDeniedError.fromWire(mapOf("reason" to "blocked"))
        assertEquals("blocked", err.message)
    }

    @Test
    fun fromWireFallbackDenied() {
        val err = ChioDeniedError.fromWire(emptyMap())
        assertEquals("denied", err.message)
    }

    @Test
    fun fromWireAcceptsSuggestedFixAsHint() {
        val err =
            ChioDeniedError.fromWire(
                mapOf("message" to "x", "suggested_fix" to "use scope Y"),
            )
        assertEquals("use scope Y", err.hint)
    }

    @Test
    fun toWireOmitsNullFields() {
        val err = ChioDeniedError("denied", guard = "G")
        val wire = err.toWire()
        assertEquals("denied", wire["message"])
        assertEquals("DENIED", wire["code"])
        assertEquals("G", wire["guard"])
        assertTrue(!wire.containsKey("tool_name"))
        assertNull(wire["reason"]) // null means absent from lookup
    }

    @Test
    fun toWireRoundTrips() {
        val src =
            ChioDeniedError(
                "nope",
                guard = "G",
                reason = "r",
                toolName = "t",
                toolServer = "s",
                requestedAction = "a",
                requiredScope = "req",
                grantedScope = "gr",
                reasonCode = "rc",
                receiptId = "rid",
                hint = "h",
                docsUrl = "u",
            )
        val wire = src.toWire()
        val dst = ChioDeniedError.fromWire(wire)
        assertEquals("nope", dst.message)
        assertEquals("G", dst.guard)
        assertEquals("r", dst.reason)
        assertEquals("t", dst.toolName)
        assertEquals("s", dst.toolServer)
        assertEquals("a", dst.requestedAction)
        assertEquals("req", dst.requiredScope)
        assertEquals("gr", dst.grantedScope)
        assertEquals("rc", dst.reasonCode)
        assertEquals("rid", dst.receiptId)
        assertEquals("h", dst.hint)
        assertEquals("u", dst.docsUrl)
    }

    @Test
    fun fromWireJsonNodeVariant() {
        val node =
            mapper.readTree(
                """
                {
                  "message": "access denied",
                  "guard": "G",
                  "reason": "r",
                  "tool_name": "t",
                  "tool_server": "s"
                }
                """.trimIndent(),
            )
        val err = ChioDeniedError.fromWire(node)
        assertEquals("access denied", err.message)
        assertEquals("G", err.guard)
        assertEquals("t", err.toolName)
        assertEquals("s", err.toolServer)
    }
}
