/**
 * Typed blocking HTTP client for the Chio sidecar.
 *
 * Mirrors chio_sdk.client.ChioClient.
 */
package world.chio.sdk

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import world.chio.sdk.errors.ChioConnectionError
import world.chio.sdk.errors.ChioDeniedError
import world.chio.sdk.errors.ChioError
import world.chio.sdk.errors.ChioTimeoutError
import java.io.IOException
import java.net.ConnectException
import java.net.URI
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.time.Duration
import java.net.http.HttpClient as JdkHttpClient

class ChioClient
    @JvmOverloads
    constructor(
        baseUrl: String = SidecarPaths.DEFAULT_BASE_URL,
        private val timeout: Duration = Duration.ofSeconds(5),
    ) : AutoCloseable,
        ChioClientLike {
        private val base: String = baseUrl.trimEnd('/')

        private val http: JdkHttpClient =
            JdkHttpClient
                .newBuilder()
                .connectTimeout(timeout)
                .build()

        // Response-side parser tolerates unknown fields. Request side uses
        // CanonicalJson where byte-identical output matters (parameter_hash).
        private val parser: ObjectMapper =
            jacksonObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

        // --------------------------------------------------------------
        // Lifecycle
        // --------------------------------------------------------------

        /**
         * No-op on JDK 17: java.net.http.HttpClient has no close() until
         * JDK 21. Present so callers can use-resource the client and to
         * mirror Python's async client.close() shape. Replace with
         * http.close() when the toolchain bumps to JDK 21+.
         */
        override fun close() {}

        // --------------------------------------------------------------
        // Health
        // --------------------------------------------------------------

        fun health(): Map<String, Any?> {
            val node = getJson(SidecarPaths.HEALTH)
            return parser.convertValue(node, Map::class.java) as Map<String, Any?>
        }

        /** Boolean health check used by the Spring Boot ChioSidecarClient.healthCheck() wrapper. */
        fun isHealthy(): Boolean =
            try {
                val (status, _) = sendGet(SidecarPaths.HEALTH)
                status == 200
            } catch (_: Exception) {
                false
            }

        // --------------------------------------------------------------
        // Tool evaluation
        // --------------------------------------------------------------

        /** Require mediated tool-call authorization. The current sidecar route emits audit receipts only. */
        override fun evaluateToolCall(
            capabilityId: String,
            toolServer: String,
            toolName: String,
            parameters: Map<String, Any?>,
        ): ChioReceipt {
            val receipt =
                evaluateToolCallAdvisory(
                    capabilityId = capabilityId,
                    toolServer = toolServer,
                    toolName = toolName,
                    parameters = parameters,
                )
            if (receipt.observationOutcome == "dropped") {
                throw ChioDeniedError("Chio sidecar advisory evaluation refused the tool call")
            }
            throw ChioDeniedError(
                "Chio sidecar returned an advisory evaluation, not an authoritative authorization decision",
            )
        }

        /** POST /v1/evaluate/advisory. Returns advisory observation receipts only. */
        fun evaluateToolCallAdvisory(
            capabilityId: String,
            toolServer: String,
            toolName: String,
            parameters: Map<String, Any?>,
        ): ChioReceipt {
            val paramCanonical = CanonicalJson.writeBytes(parameters)
            val paramHash = Hashing.sha256Hex(paramCanonical)
            val body =
                linkedMapOf<String, Any?>(
                    "capability_id" to capabilityId,
                    "tool_server" to toolServer,
                    "tool_name" to toolName,
                    "parameters" to parameters,
                    "parameter_hash" to paramHash,
                )
            val node = postJson(SidecarPaths.EVALUATE_TOOL_CALL, body)
            if (!isAdvisoryEvaluationWrapper(node)) {
                throw ChioError(
                    "Chio sidecar advisory evaluation response did not use the advisory non-authorization wrapper",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            val receiptNode = wrappedAdvisoryReceiptNode(node)
            val receipt = parser.treeToValue(receiptNode, ChioReceipt::class.java)
            if (!receipt.isAdvisoryEvaluation()) {
                throw ChioError(
                    "Chio sidecar advisory evaluation response did not include an advisory receipt",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            if (!verifyReceiptIntegrity(receipt)) {
                throw ChioError(
                    "Chio sidecar returned an advisory evaluation receipt that failed integrity checks",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            return receipt
        }

        private fun ChioReceipt.isAdvisoryEvaluation(): Boolean =
            receiptKind == "advisory_evaluation" &&
                boundaryClass == "advisory_only" &&
                trustLevel == "advisory"

        /** POST /chio/evaluate. Mirrors evaluate_http_request. */
        @JvmOverloads
        fun evaluateHttpRequest(
            request: ChioHttpRequest,
            capabilityToken: String? = null,
        ): EvaluateResponse {
            val headers =
                if (capabilityToken.isNullOrBlank()) {
                    emptyMap()
                } else {
                    mapOf("X-Chio-Capability" to capabilityToken)
                }
            val node = postJson(SidecarPaths.EVALUATE_HTTP, request, extraHeaders = headers)
            val result = parser.treeToValue(node, EvaluateResponse::class.java)
            if (result.verdict.isAllowed() || result.receipt.verdict.isAllowed()) {
                if (!result.verdict.isAllowed() || !result.receipt.isAuthorized()) {
                    throw ChioError(
                        "Chio sidecar returned an allow-shaped response without mediated receipt authorization",
                        ChioErrorCodes.INVALID_RECEIPT,
                    )
                }
                val verification = verifyHttpReceipt(result.receipt)
                if (!verification.authorizes(result.receipt)) {
                    throw ChioError(
                        "Chio sidecar returned an unverified HTTP receipt",
                        ChioErrorCodes.INVALID_RECEIPT,
                    )
                }
            }
            return result
        }

        /** Field-taking overload for Java callers (no model pre-built). */
        @JvmOverloads
        fun evaluateHttpRequest(
            requestId: String,
            method: String,
            routePattern: String,
            path: String,
            caller: CallerIdentity,
            query: Map<String, String> = emptyMap(),
            headers: Map<String, String> = emptyMap(),
            bodyHash: String? = null,
            bodyLength: Long = 0L,
            sessionId: String? = null,
            capabilityId: String? = null,
            capabilityToken: String? = null,
            timestamp: Long? = null,
        ): EvaluateResponse {
            val ts = timestamp ?: (System.currentTimeMillis() / 1000L)
            val request =
                ChioHttpRequest(
                    requestId = requestId,
                    method = method,
                    routePattern = routePattern,
                    path = path,
                    query = query,
                    headers = headers,
                    caller = caller,
                    bodyHash = bodyHash,
                    bodyLength = bodyLength,
                    sessionId = sessionId,
                    capabilityId = capabilityId,
                    timestamp = ts,
                )
            return evaluateHttpRequest(request, capabilityToken)
        }

        // --------------------------------------------------------------
        // Receipt verification
        // --------------------------------------------------------------

        /** POST /v1/receipts/verify. Mirrors verify_receipt. */
        override fun verifyReceipt(receipt: ChioReceipt): Boolean {
            val node = postJson(SidecarPaths.VERIFY_RECEIPT, receipt)
            return node.has("ok") &&
                node.has("authorized") &&
                node.path("ok").asBoolean(false) &&
                node.path("authorized").asBoolean(false) &&
                node.path("signer_trusted").asBoolean(false) &&
                node.path("receipt_id_valid").asBoolean(false) &&
                node.path("signature_valid").asBoolean(false) &&
                node.path("parameter_hash_valid").asBoolean(false) &&
                node.path("receipt_kind").asText("") == "mediated_decision" &&
                node.path("boundary_class").asText("") == "prevent" &&
                node.path("trust_level").asText("") == "mediated" &&
                node.path("result").asText("") in setOf("allow", "authorized", "Authorized")
        }

        private fun verifyReceiptIntegrity(receipt: ChioReceipt): Boolean {
            val node = postJson(SidecarPaths.VERIFY_RECEIPT, receipt)
            return node.path("signature_valid").asBoolean(false) &&
                node.path("signer_trusted").asBoolean(false) &&
                node.path("receipt_id_valid").asBoolean(false) &&
                node.path("parameter_hash_valid").asBoolean(false)
        }

        /** POST /chio/verify. Mirrors verify_http_receipt. */
        fun verifyHttpReceipt(receipt: HttpReceipt): VerifyReceiptResponse {
            val node = postJson(SidecarPaths.VERIFY_HTTP_RECEIPT, receipt)
            return parser.treeToValue(node, VerifyReceiptResponse::class.java)
        }

        /** Short-name alias for callers that already use Chio as the package context. */
        fun verifyReceipt(receipt: HttpReceipt): VerifyReceiptResponse = verifyHttpReceipt(receipt)

        /**
         * Pure client-side Merkle chain walk. Mirrors verify_receipt_chain;
         * byte-identical hashes via CanonicalJson.
         */
        fun verifyReceiptChain(receipts: List<ChioReceipt>): Boolean {
            if (receipts.size < 2) {
                return true
            }
            for (i in 1 until receipts.size) {
                val prev = CanonicalJson.writeBytes(receiptToMap(receipts[i - 1]))
                val expected = Hashing.sha256Hex(prev)
                if (receipts[i].contentHash != expected) {
                    return false
                }
            }
            return true
        }

        /**
         * Convert a receipt to a Python-pydantic-equivalent exclude_none dict
         * so the canonical hash tree matches exactly. Jackson's NON_NULL
         * inclusion on the POJO side already drops null fields; we then run
         * through the canonical mapper which sorts keys.
         */
        private fun receiptToMap(receipt: ChioReceipt): Map<String, Any?> {
            // Route the receipt through the canonical mapper to a JsonNode, then
            // to a Map<String, Any?>. NON_NULL property inclusion trims null
            // top-level fields; ALWAYS content-inclusion preserves null map
            // entries inside metadata.
            val node = CanonicalJson.MAPPER.valueToTree<JsonNode>(receipt)
            @Suppress("UNCHECKED_CAST")
            return parser.convertValue(node, Map::class.java) as Map<String, Any?>
        }

        private fun isAdvisoryEvaluationWrapper(node: JsonNode): Boolean =
            node.path("schema").asText("") == "chio.sidecar.advisory-evaluation.v1"

        private fun wrappedAdvisoryReceiptNode(node: JsonNode): JsonNode {
            if (!node.path("authorization").isBoolean || node.path("authorization").asBoolean(true)) {
                throw ChioError(
                    "Chio sidecar advisory evaluation did not explicitly mark authorization as false",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            if (node.path("authorizationBasis").asText("") != "advisory_only") {
                throw ChioError(
                    "Chio sidecar advisory evaluation did not identify its authorization basis",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            val receipt = node.get("receipt")
            if (receipt == null || !receipt.isObject) {
                throw ChioError(
                    "Chio sidecar advisory evaluation response is missing receipt",
                    ChioErrorCodes.INVALID_RECEIPT,
                )
            }
            return receipt
        }

        // --------------------------------------------------------------
        // Evidence helpers
        // --------------------------------------------------------------

        companion object {
            /** Mirrors chio_sdk.client.ChioClient.collect_evidence. */
            @JvmStatic
            fun collectEvidence(receipts: List<ChioReceipt>): List<GuardEvidence> {
                val out = ArrayList<GuardEvidence>()
                for (r in receipts) out.addAll(r.evidence)
                return out
            }

            /** Default base URL shared with the Spring Boot integration. */
            const val DEFAULT_BASE_URL: String = SidecarPaths.DEFAULT_BASE_URL
        }

        // --------------------------------------------------------------
        // HTTP plumbing
        // --------------------------------------------------------------

        private fun getJson(path: String): JsonNode {
            val (status, body) = sendGet(path)
            return handleResponse(status, body, path)
        }

        private fun postJson(
            path: String,
            body: Any?,
            extraHeaders: Map<String, String> = emptyMap(),
        ): JsonNode {
            val payload = CanonicalJson.writeBytes(body)
            val builder =
                HttpRequest
                    .newBuilder()
                    .uri(URI.create("$base$path"))
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
            for ((k, v) in extraHeaders) builder.header(k, v)

            val (status, respBody) =
                try {
                    val resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString())
                    resp.statusCode() to resp.body()
                } catch (e: HttpTimeoutException) {
                    throw ChioTimeoutError("Request to $path timed out", e)
                } catch (e: HttpConnectTimeoutException) {
                    throw ChioTimeoutError("Connection to $base timed out", e)
                } catch (e: ConnectException) {
                    throw ChioConnectionError("Failed to connect to Chio sidecar at $base", e)
                } catch (e: IOException) {
                    throw ChioConnectionError("Failed to connect to Chio sidecar at $base: ${e.message}", e)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw ChioConnectionError("Request to $path interrupted", e)
                }

            return handleResponse(status, respBody, path)
        }

        private fun sendGet(path: String): Pair<Int, String> {
            val req =
                HttpRequest
                    .newBuilder()
                    .uri(URI.create("$base$path"))
                    .timeout(timeout)
                    .GET()
                    .build()
            return try {
                val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
                resp.statusCode() to resp.body()
            } catch (e: HttpTimeoutException) {
                throw ChioTimeoutError("Request to $path timed out", e)
            } catch (e: HttpConnectTimeoutException) {
                throw ChioTimeoutError("Connection to $base timed out", e)
            } catch (e: ConnectException) {
                throw ChioConnectionError("Failed to connect to Chio sidecar at $base", e)
            } catch (e: IOException) {
                throw ChioConnectionError("Failed to connect to Chio sidecar at $base: ${e.message}", e)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw ChioConnectionError("Request to $path interrupted", e)
            }
        }

        private fun handleResponse(
            status: Int,
            body: String,
            path: String,
        ): JsonNode {
            if (status == 403) {
                val node =
                    try {
                        parser.readTree(body)
                    } catch (_: Exception) {
                        throw ChioDeniedError(body.ifBlank { "denied" })
                    }
                throw ChioDeniedError.fromWire(node)
            }
            if (status >= 400) {
                val detail: Any =
                    try {
                        parser.readValue<Map<String, Any?>>(body)
                    } catch (_: Exception) {
                        body
                    }
                throw ChioError(
                    "Chio sidecar returned $status: $detail",
                    code = "HTTP_$status",
                )
            }
            return parser.readTree(body)
        }
    }
