package world.chio.sdk

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import world.chio.sdk.errors.ChioConnectionError
import world.chio.sdk.errors.ChioDeniedError
import world.chio.sdk.errors.ChioError
import world.chio.sdk.errors.ChioTimeoutError
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ChioClientHttpTest {
    private lateinit var server: HttpServer
    private lateinit var baseUrl: String
    private var serverStarted: Boolean = false

    @BeforeEach
    fun startServer() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        baseUrl = "http://127.0.0.1:${server.address.port}"
        serverStarted = false
    }

    @AfterEach
    fun stopServer() {
        server.stop(0)
    }

    private fun register(
        path: String,
        handler: HttpHandler,
    ) {
        server.createContext(path, handler)
        if (!serverStarted) {
            server.start()
            serverStarted = true
        }
    }

    private fun respond(
        exchange: HttpExchange,
        status: Int,
        body: String,
    ) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        exchange.responseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(status, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }

    private fun readBody(exchange: HttpExchange): ByteArray = exchange.requestBody.readAllBytes()

    private fun structuredVerifyResponse(authorized: Boolean): String =
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
        """.trimIndent()

    @Test
    fun evaluateToolCallSendsParameterHash() {
        val observed = AtomicReference<Map<String, Any?>>()
        register("/v1/evaluate") { exchange ->
            val body = readBody(exchange)
            val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(body)
            observed.set(parsed)
            // Minimal valid ChioReceipt response.
            val resp =
                """
                {
                  "id": "r1", "timestamp": 1700000000, "capability_id": "cap",
                  "tool_server": "s", "tool_name": "t",
                  "action": {"parameters": ${'$'}{params}, "parameter_hash": "${'$'}{ph}"},
                  "decision": {"verdict": "allow"},
                  "receipt_kind": "mediated_decision",
                  "boundary_class": "prevent",
                  "tool_origin": "caller_executed",
                  "redaction_mode": "none",
                  "trust_level": "mediated",
                  "content_hash": "c", "policy_hash": "p",
                  "evidence": [], "kernel_key": "k", "signature": "sig"
                }
                """.trimIndent()
                    .replace("\${params}", """{"a":1}""")
                    .replace("\${ph}", "abc")
            respond(exchange, 200, resp)
        }
        register("/v1/receipts/verify") { exchange ->
            respond(exchange, 200, structuredVerifyResponse(true))
        }

        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val receipt = c.evaluateToolCall("cap", "s", "t", mapOf("a" to 1))
            assertTrue(receipt.isAllowed())
        }
        val sent = observed.get()
        assertEquals("cap", sent["capability_id"])
        assertEquals("s", sent["tool_server"])
        assertEquals("t", sent["tool_name"])
        // Canonical parameter hash matches SHA-256 of canonical JSON bytes.
        val expectedHash = Hashing.sha256Hex(CanonicalJson.writeBytes(mapOf("a" to 1)))
        assertEquals(expectedHash, sent["parameter_hash"])
    }

    @Test
    fun evaluateToolCallRejectsUnverifiedAllowReceipt() {
        register("/v1/evaluate") { exchange ->
            val body = readBody(exchange)
            val parsed: Map<String, Any?> = jacksonObjectMapper().readValue(body)
            val resp =
                """
                {
                  "id": "r1", "timestamp": 1700000000, "capability_id": "cap",
                  "tool_server": "s", "tool_name": "t",
                  "action": {"parameters": ${'$'}{params}, "parameter_hash": "abc"},
                  "decision": {"verdict": "allow"},
                  "receipt_kind": "mediated_decision",
                  "boundary_class": "prevent",
                  "tool_origin": "caller_executed",
                  "redaction_mode": "none",
                  "trust_level": "mediated",
                  "content_hash": "c", "policy_hash": "p",
                  "evidence": [], "kernel_key": "k", "signature": "sig"
                }
                """.trimIndent()
                    .replace("\${params}", jacksonObjectMapper().writeValueAsString(parsed["parameters"]))
            respond(exchange, 200, resp)
        }
        register("/v1/receipts/verify") { exchange ->
            respond(exchange, 200, structuredVerifyResponse(false))
        }

        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val err =
                assertThrows<ChioError> {
                    c.evaluateToolCall("cap", "s", "t", mapOf("a" to 1))
                }
            assertEquals(ChioErrorCodes.INVALID_RECEIPT, err.code)
        }
    }

    @Test
    fun verifyReceiptPostsToRightPath() {
        val calls = AtomicReference<String?>()
        register("/v1/receipts/verify") { exchange ->
            calls.set(exchange.requestURI.path)
            respond(exchange, 200, structuredVerifyResponse(true))
        }
        val receipt = buildDummyReceipt()
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            assertTrue(c.verifyReceipt(receipt))
        }
        assertEquals("/v1/receipts/verify", calls.get())
    }

    @Test
    fun verifyHttpReceiptPostsToVerifyPath() {
        val calls = AtomicReference<String?>()
        register("/chio/verify") { exchange ->
            calls.set(exchange.requestURI.path)
            respond(exchange, 200, structuredVerifyResponse(false))
        }
        val http =
            HttpReceipt(
                id = "r",
                requestId = "req",
                routePattern = "/x",
                method = "GET",
                callerIdentityHash = "h",
                verdict = Verdict.allow(),
                receiptKind = "mediated_decision",
                boundaryClass = "prevent",
                toolOrigin = "caller_executed",
                redactionMode = "none",
                responseStatus = 200,
                timestamp = 1L,
                contentHash = "c",
                policyHash = "p",
                trustLevel = "mediated",
                kernelKey = "k",
                signature = "s",
            )
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            assertFalse(c.verifyHttpReceipt(http).ok)
        }
        assertEquals("/chio/verify", calls.get())
    }

    @Test
    fun healthReturnsParsedMap() {
        register("/chio/health") { exchange ->
            respond(exchange, 200, """{"status": "ok", "version": "0.1"}""")
        }
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val m = c.health()
            assertEquals("ok", m["status"])
            assertEquals("0.1", m["version"])
            assertTrue(c.isHealthy())
        }
    }

    @Test
    fun deny403MapsToStructuredError() {
        register("/v1/evaluate") { exchange ->
            val body =
                """
                {
                  "message": "denied",
                  "guard": "CapabilityGuard",
                  "reason": "missing scope",
                  "tool_name": "t",
                  "tool_server": "s",
                  "required_scope": "tools:delete",
                  "granted_scope": "tools:read",
                  "receipt_id": "r-403",
                  "hint": "mint a new token"
                }
                """.trimIndent()
            respond(exchange, 403, body)
        }
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val err =
                assertThrows<ChioDeniedError> {
                    c.evaluateToolCall("cap", "s", "t", mapOf("a" to 1))
                }
            assertEquals("denied", err.message)
            assertEquals("CapabilityGuard", err.guard)
            assertEquals("missing scope", err.reason)
            assertEquals("t", err.toolName)
            assertEquals("s", err.toolServer)
            assertEquals("tools:delete", err.requiredScope)
            assertEquals("tools:read", err.grantedScope)
            assertEquals("r-403", err.receiptId)
            assertEquals("mint a new token", err.hint)
        }
    }

    @Test
    fun connectionFailureMapsToConnectionError() {
        // Use a port we never open.
        val offline = ChioClient("http://127.0.0.1:1", Duration.ofSeconds(1))
        assertThrows<ChioConnectionError> {
            offline.evaluateToolCall("c", "s", "t", emptyMap())
        }
        offline.close()
    }

    @Test
    fun timeoutMapsToTimeoutError() {
        register("/v1/evaluate") { exchange ->
            // Hold the connection longer than the client timeout.
            Thread.sleep(2000)
            respond(exchange, 200, "{}")
        }
        ChioClient(baseUrl, Duration.ofMillis(250)).use { c ->
            assertThrows<ChioTimeoutError> {
                c.evaluateToolCall("c", "s", "t", emptyMap())
            }
        }
    }

    @Test
    fun verifyReceiptChainReturnsTrueForEmptyOrSingle() {
        ChioClient(baseUrl, Duration.ofSeconds(1)).use { c ->
            assertTrue(c.verifyReceiptChain(emptyList()))
            assertTrue(c.verifyReceiptChain(listOf(buildDummyReceipt())))
        }
    }

    @Test
    fun verifyReceiptChainUsesCanonicalHash() {
        val r1 = buildDummyReceipt(id = "r-1", content = "c1")
        val r1Canonical =
            CanonicalJson.writeBytes(
                CanonicalJson.MAPPER.convertValue(r1, Map::class.java),
            )
        val expected = Hashing.sha256Hex(r1Canonical)
        val r2Good = buildDummyReceipt(id = "r-2", content = expected)
        val r2Bad = buildDummyReceipt(id = "r-2", content = "wrong")
        ChioClient(baseUrl, Duration.ofSeconds(1)).use { c ->
            assertTrue(c.verifyReceiptChain(listOf(r1, r2Good)))
            assertFalse(c.verifyReceiptChain(listOf(r1, r2Bad)))
        }
    }

    @Test
    fun evaluateHttpRequestSendsCapabilityHeader() {
        val observedCap = AtomicReference<String?>()
        register("/chio/evaluate") { exchange ->
            observedCap.set(exchange.requestHeaders.getFirst("X-Chio-Capability"))
            val resp =
                """
                {
                  "verdict": {"verdict":"allow"},
                  "receipt": {
                    "id":"r","request_id":"req","route_pattern":"/","method":"GET",
                    "caller_identity_hash":"h","verdict":{"verdict":"allow"},
                    "receipt_kind":"mediated_decision",
                    "boundary_class":"prevent",
                    "tool_origin":"caller_executed",
                    "redaction_mode":"none",
                    "trust_level":"mediated",
                    "evidence":[],"response_status":200,"timestamp":1,
                    "content_hash":"c","policy_hash":"p",
                    "kernel_key":"k","signature":"s"
                  },
                  "evidence":[]
                }
                """.trimIndent()
            respond(exchange, 200, resp)
        }
        register("/chio/verify") { exchange ->
            respond(exchange, 200, structuredVerifyResponse(true))
        }
        val request =
            ChioHttpRequest(
                requestId = "req",
                method = "GET",
                routePattern = "/",
                path = "/",
                caller = CallerIdentity.anonymous(),
                timestamp = 1L,
            )
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val resp = c.evaluateHttpRequest(request, "tok-1")
            assertTrue(resp.verdict.isAllowed())
        }
        assertEquals("tok-1", observedCap.get())
    }

    @Test
    fun evaluateHttpRequestRejectsUnverifiedAllowReceipt() {
        register("/chio/evaluate") { exchange ->
            val resp =
                """
                {
                  "verdict": {"verdict":"allow"},
                  "receipt": {
                    "id":"r","request_id":"req","route_pattern":"/","method":"GET",
                    "caller_identity_hash":"h","verdict":{"verdict":"allow"},
                    "receipt_kind":"mediated_decision",
                    "boundary_class":"prevent",
                    "tool_origin":"caller_executed",
                    "redaction_mode":"none",
                    "trust_level":"mediated",
                    "evidence":[],"response_status":200,"timestamp":1,
                    "content_hash":"c","policy_hash":"p",
                    "kernel_key":"k","signature":"s"
                  },
                  "evidence":[]
                }
                """.trimIndent()
            respond(exchange, 200, resp)
        }
        register("/chio/verify") { exchange ->
            respond(exchange, 200, structuredVerifyResponse(false))
        }
        val request =
            ChioHttpRequest(
                requestId = "req",
                method = "GET",
                routePattern = "/",
                path = "/",
                caller = CallerIdentity.anonymous(),
                timestamp = 1L,
            )
        ChioClient(baseUrl, Duration.ofSeconds(2)).use { c ->
            val err =
                assertThrows<ChioError> {
                    c.evaluateHttpRequest(request, "tok-1")
                }
            assertEquals(ChioErrorCodes.INVALID_RECEIPT, err.code)
        }
    }

    private fun buildDummyReceipt(
        id: String = "r1",
        content: String = "c",
    ): ChioReceipt =
        ChioReceipt(
            id = id,
            timestamp = 1700000000L,
            capabilityId = "cap",
            toolServer = "srv",
            toolName = "events:consume:x",
            action = ToolCallAction(parameters = mapOf("a" to 1), parameterHash = "h"),
            decision = Decision.allow(),
            receiptKind = "mediated_decision",
            boundaryClass = "prevent",
            toolOrigin = "caller_executed",
            redactionMode = "none",
            trustLevel = "mediated",
            contentHash = content,
            policyHash = "p",
            evidence = emptyList(),
            kernelKey = "k",
            signature = "s",
        )
}
