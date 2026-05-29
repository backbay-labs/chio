/**
 * Conformance tests for Chio JVM SDK types.
 *
 * Validates that JVM types serialize to the same JSON structure as the
 * Rust kernel types (shared test vectors).
 */
package world.chio.sdk

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ChioTypesTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun `verdict allow serialization`() {
        val verdict = Verdict.allow()
        val json = mapper.writeValueAsString(verdict)
        assertTrue(json.contains("\"verdict\":\"allow\""))

        val back: Verdict = mapper.readValue(json)
        assertTrue(back.isAllowed())
        assertFalse(back.isDenied())
    }

    @Test
    fun `verdict deny serialization`() {
        val verdict = Verdict.deny("no capability", "CapabilityGuard", 403)
        val json = mapper.writeValueAsString(verdict)
        assertTrue(json.contains("\"verdict\":\"deny\""))
        assertTrue(json.contains("\"reason\":\"no capability\""))
        assertTrue(json.contains("\"guard\":\"CapabilityGuard\""))
        assertTrue(json.contains("\"http_status\":403"))

        val back: Verdict = mapper.readValue(json)
        assertTrue(back.isDenied())
        assertFalse(back.isAllowed())
        assertEquals("no capability", back.reason)
    }

    @Test
    fun `caller identity anonymous serialization`() {
        val caller = CallerIdentity.anonymous()
        val json = mapper.writeValueAsString(caller)
        assertTrue(json.contains("\"subject\":\"anonymous\""))
        assertTrue(json.contains("\"method\":\"anonymous\""))
        assertTrue(json.contains("\"verified\":false"))

        val back: CallerIdentity = mapper.readValue(json)
        assertEquals("anonymous", back.subject)
        assertFalse(back.verified)
    }

    @Test
    fun `caller identity bearer serialization`() {
        val caller =
            CallerIdentity(
                subject = "bearer:abc123",
                authMethod = AuthMethod.bearer("abc123def456"),
            )
        val json = mapper.writeValueAsString(caller)
        assertTrue(json.contains("\"subject\":\"bearer:abc123\""))
        assertTrue(json.contains("\"method\":\"bearer\""))
        assertTrue(json.contains("\"token_hash\":\"abc123def456\""))

        val back: CallerIdentity = mapper.readValue(json)
        assertEquals("bearer:abc123", back.subject)
        assertEquals("bearer", back.authMethod.method)
    }

    @Test
    fun `chio http request serialization`() {
        val request =
            ChioHttpRequest(
                requestId = "req-001",
                method = "GET",
                routePattern = "/pets/{petId}",
                path = "/pets/42",
                query = mapOf("verbose" to "true"),
                caller = CallerIdentity.anonymous(),
                timestamp = 1700000000,
            )
        val json = mapper.writeValueAsString(request)
        assertTrue(json.contains("\"request_id\":\"req-001\""))
        assertTrue(json.contains("\"method\":\"GET\""))
        assertTrue(json.contains("\"route_pattern\":\"/pets/{petId}\""))
        assertTrue(json.contains("\"path\":\"/pets/42\""))
        assertTrue(json.contains("\"timestamp\":1700000000"))

        val back: ChioHttpRequest = mapper.readValue(json)
        assertEquals("req-001", back.requestId)
        assertEquals("/pets/{petId}", back.routePattern)
    }

    @Test
    fun `http receipt serialization roundtrip`() {
        val receipt =
            HttpReceipt(
                id = "receipt-001",
                requestId = "req-001",
                routePattern = "/pets/{petId}",
                method = "GET",
                callerIdentityHash = "abc123",
                verdict = Verdict.allow(),
                receiptKind = "mediated_decision",
                boundaryClass = "prevent",
                toolOrigin = "caller_executed",
                redactionMode = "none",
                evidence = emptyList(),
                responseStatus = 200,
                timestamp = 1700000000,
                contentHash = "deadbeef",
                policyHash = "cafebabe",
                trustLevel = "mediated",
                kernelKey = "test-key",
                signature = "test-sig",
            )

        val json = mapper.writeValueAsString(receipt)
        val back: HttpReceipt = mapper.readValue(json)

        assertEquals("receipt-001", back.id)
        assertEquals("req-001", back.requestId)
        assertTrue(back.verdict.isAllowed())
        assertEquals(200, back.responseStatus)
    }

    @Test
    fun `guard evidence serialization`() {
        val evidence =
            GuardEvidence(
                guardName = "CapabilityGuard",
                verdict = true,
                details = "capability token presented",
            )
        val json = mapper.writeValueAsString(evidence)
        assertTrue(json.contains("\"guard_name\":\"CapabilityGuard\""))
        assertTrue(json.contains("\"verdict\":true"))

        val back: GuardEvidence = mapper.readValue(json)
        assertEquals("CapabilityGuard", back.guardName)
        assertTrue(back.verdict)
    }

    @Test
    fun `sha256 hex known vector`() {
        val hash = Hashing.sha256Hex("")
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
    }

    @Test
    fun `evaluate response deserialization`() {
        val json =
            """
            {
                "verdict": {"verdict": "allow"},
                "receipt": {
                    "id": "receipt-001",
                    "request_id": "req-001",
                    "route_pattern": "/pets",
                    "method": "GET",
                    "caller_identity_hash": "hash",
                    "verdict": {"verdict": "allow"},
                    "receipt_kind": "mediated_decision",
                    "boundary_class": "prevent",
                    "tool_origin": "caller_executed",
                    "redaction_mode": "none",
                    "trust_level": "mediated",
                    "evidence": [],
                    "response_status": 200,
                    "timestamp": 1700000000,
                    "content_hash": "abc",
                    "policy_hash": "def",
                    "kernel_key": "key",
                    "signature": "sig"
                },
                "evidence": []
            }
            """.trimIndent()

        val response: EvaluateResponse = mapper.readValue(json)
        assertTrue(response.verdict.isAllowed())
        assertEquals("receipt-001", response.receipt.id)
    }

    @Test
    fun `error response serialization`() {
        val error =
            ChioErrorResponse(
                error = ChioErrorCodes.ACCESS_DENIED,
                message = "no capability",
                receiptId = "receipt-001",
                suggestion = "provide a valid capability token",
            )
        val json = mapper.writeValueAsString(error)
        assertTrue(json.contains("\"error\":\"chio_access_denied\""))
        assertTrue(json.contains("\"receipt_id\":\"receipt-001\""))
    }

    @Test
    fun `verdict toDecision maps verdicts`() {
        assertEquals("allow", Verdict.allow().toDecision().verdict)
        assertEquals("deny", Verdict.deny("r", "g").toDecision().verdict)
        assertEquals(
            "cancelled",
            Verdict(verdict = "cancel", reason = "timeout").toDecision().verdict,
        )
        assertEquals(
            "incomplete",
            Verdict(verdict = "incomplete", reason = "partial").toDecision().verdict,
        )
    }
}
