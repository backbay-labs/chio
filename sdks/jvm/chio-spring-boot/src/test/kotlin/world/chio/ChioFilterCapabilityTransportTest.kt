package world.chio

import com.sun.net.httpserver.HttpServer
import jakarta.servlet.FilterChain
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ChioFilterCapabilityTransportTest {
    private fun structuredVerifyResponse(authorized: Boolean): ByteArray =
        """
        {
          "signature_valid": $authorized,
          "signer_trusted": $authorized,
          "receipt_id_valid": $authorized,
          "parameter_hash_valid": $authorized,
          "receipt_kind": "mediated_decision",
          "boundary_class": "prevent",
          "trust_level": "mediated",
          "result": "${if (authorized) "allow" else "deny"}",
          "authorized": $authorized,
          "signer_key_hex": "${"d".repeat(64)}",
          "ok": $authorized
        }
        """.trimIndent().toByteArray()

    @Test
    fun `query capability token is forwarded to sidecar`() {
        val observedCapability = AtomicReference<String?>()
        val sidecar = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        sidecar.createContext("/chio/evaluate") { exchange ->
            observedCapability.set(exchange.requestHeaders.getFirst("X-Chio-Capability"))
            val body =
                """
                {
                  "verdict": {"verdict":"allow"},
                  "receipt": {
                    "id": "receipt-query-capability",
                    "request_id": "req-1",
                    "route_pattern": "/echo",
                    "method": "POST",
                    "caller_identity_hash": "hash",
                    "verdict": {"verdict":"allow"},
                    "receipt_kind": "mediated_decision",
                    "boundary_class": "prevent",
                    "tool_origin": "caller_executed",
                    "redaction_mode": "none",
                    "trust_level": "mediated",
                    "evidence": [],
                    "response_status": 200,
                    "timestamp": 1700000000,
                    "content_hash": "content",
                    "policy_hash": "policy",
                    "kernel_key": "kernel",
                    "signature": "signature"
                  },
                  "evidence": []
                }
                """.trimIndent().toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        sidecar.createContext("/chio/verify") { exchange ->
            val body = structuredVerifyResponse(true)
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        sidecar.start()

        try {
            val filter =
                ChioFilter(
                    ChioFilterConfig(sidecarUrl = "http://127.0.0.1:${sidecar.address.port}"),
                )
            val request =
                MockHttpServletRequest().apply {
                    method = "POST"
                    requestURI = "/echo"
                    contentType = "application/json"
                    addParameter("chio_capability", "query-token")
                    setContent("""{"hello":"world"}""".toByteArray())
                }
            val response = MockHttpServletResponse()
            val chainCalled = AtomicBoolean(false)
            val chain = FilterChain { _, _ -> chainCalled.set(true) }

            filter.doFilter(request, response, chain)

            assertTrue(chainCalled.get())
            assertEquals("query-token", observedCapability.get())
            assertEquals("receipt-query-capability", response.getHeader("X-Chio-Receipt-Id"))
        } finally {
            sidecar.stop(0)
        }
    }

    @Test
    fun `reserved fail-open setting still fails closed`() {
        val filter =
            ChioFilter(
                ChioFilterConfig(
                    sidecarUrl = "http://127.0.0.1:1",
                    timeoutSeconds = 1,
                    onSidecarError = "allow",
                ),
            )
        val request =
            MockHttpServletRequest().apply {
                method = "GET"
                requestURI = "/echo"
            }
        val response = MockHttpServletResponse()
        val chainCalled = AtomicBoolean(false)
        val chain = FilterChain { _, _ -> chainCalled.set(true) }

        filter.doFilter(request, response, chain)

        assertFalse(chainCalled.get())
        assertEquals(502, response.status)
        assertEquals(null, response.getHeader("X-Chio-Receipt-Id"))
    }

    @Test
    fun `unverified allow fails closed`() {
        val sidecar = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        sidecar.createContext("/chio/evaluate") { exchange ->
            val body =
                """
                {
                  "verdict": {"verdict":"allow"},
                  "receipt": {
                    "id": "receipt-unverified",
                    "request_id": "req-1",
                    "route_pattern": "/echo",
                    "method": "POST",
                    "caller_identity_hash": "hash",
                    "verdict": {"verdict":"allow"},
                    "receipt_kind": "mediated_decision",
                    "boundary_class": "prevent",
                    "tool_origin": "caller_executed",
                    "redaction_mode": "none",
                    "trust_level": "mediated",
                    "evidence": [],
                    "response_status": 200,
                    "timestamp": 1700000000,
                    "content_hash": "content",
                    "policy_hash": "policy",
                    "kernel_key": "kernel",
                    "signature": "signature"
                  },
                  "evidence": []
                }
                """.trimIndent().toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        sidecar.createContext("/chio/verify") { exchange ->
            val body = structuredVerifyResponse(false)
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        sidecar.start()

        try {
            val filter =
                ChioFilter(
                    ChioFilterConfig(sidecarUrl = "http://127.0.0.1:${sidecar.address.port}"),
                )
            val request =
                MockHttpServletRequest().apply {
                    method = "POST"
                    requestURI = "/echo"
                    contentType = "application/json"
                    setContent("""{"hello":"world"}""".toByteArray())
                }
            val response = MockHttpServletResponse()
            val chainCalled = AtomicBoolean(false)
            val chain = FilterChain { _, _ -> chainCalled.set(true) }

            filter.doFilter(request, response, chain)

            assertFalse(chainCalled.get())
            assertEquals(502, response.status)
            assertEquals(null, response.getHeader("X-Chio-Receipt-Id"))
        } finally {
            sidecar.stop(0)
        }
    }
}
