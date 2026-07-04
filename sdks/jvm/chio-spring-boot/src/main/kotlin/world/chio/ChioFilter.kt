/**
 * Servlet filter that protects HTTP endpoints with Chio evaluation.
 *
 * Intercepts all requests, extracts caller identity, sends evaluation
 * requests to the Chio sidecar kernel, and either allows the request to
 * proceed with a verified signed receipt or returns a structured deny
 * response.
 *
 * Fails closed: if the sidecar is unreachable, the request is denied.
 */
package world.chio

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import world.chio.sdk.Hashing.sha256Hex
import java.util.UUID

private fun capabilityIdFromToken(rawToken: String?): String? {
    if (rawToken.isNullOrBlank()) {
        return null
    }
    return try {
        jacksonObjectMapper()
            .readTree(rawToken)
            .get("id")
            ?.takeIf { it.isTextual }
            ?.asText()
    } catch (_: Exception) {
        null
    }
}

internal fun extractCapabilityToken(request: HttpServletRequest): String? =
    request.getHeader("X-Chio-Capability") ?: request.getParameter("chio_capability")

const val CHIO_PASSTHROUGH_ATTRIBUTE = "chioPassthrough"

/**
 * Configuration for the Chio servlet filter.
 *
 * @param sidecarUrl Base URL of the Chio sidecar kernel.
 * @param timeoutSeconds HTTP timeout for sidecar calls.
 * @param onSidecarError Reserved no-op option. The filter always denies sidecar errors.
 * @param identityExtractor Custom identity extraction function.
 * @param routeResolver Custom route pattern resolver.
 */
data class ChioFilterConfig(
    val sidecarUrl: String = System.getenv("CHIO_SIDECAR_URL") ?: "http://127.0.0.1:9090",
    val timeoutSeconds: Long = 5,
    val onSidecarError: String = "deny",
    val identityExtractor: IdentityExtractorFn = ::defaultIdentityExtractor,
    val routeResolver: (String, String) -> String = { _, path -> path },
)

/** Chio servlet filter for protecting HTTP APIs. */
class ChioFilter(
    private val config: ChioFilterConfig = ChioFilterConfig(),
) : Filter {
    private val client = ChioSidecarClient(config.sidecarUrl, config.timeoutSeconds)
    private val objectMapper = jacksonObjectMapper()

    override fun init(filterConfig: FilterConfig?) {
        // No initialization needed.
    }

    override fun doFilter(
        request: ServletRequest,
        response: ServletResponse,
        chain: FilterChain,
    ) {
        val httpRequest = request as HttpServletRequest
        val httpResponse = response as HttpServletResponse
        val cachedRequest =
            when (httpRequest) {
                is CachedBodyHttpServletRequest -> httpRequest
                else -> CachedBodyHttpServletRequest(httpRequest)
            }

        val method = cachedRequest.method.uppercase()
        val validMethods = setOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        if (method !in validMethods) {
            writeJsonError(
                httpResponse,
                405,
                ChioErrorResponse(
                    error = ChioErrorCodes.EVALUATION_FAILED,
                    message = "unsupported HTTP method: $method",
                ),
            )
            return
        }

        // Extract caller identity.
        val caller = config.identityExtractor(cachedRequest)

        // Resolve route pattern.
        val routePattern = config.routeResolver(method, cachedRequest.requestURI)

        val bodyBytes = cachedRequest.cachedBody
        val bodyHash = bodyBytes.takeIf { it.isNotEmpty() }?.let { sha256Hex(it) }

        // Extract selected headers.
        val headers = mutableMapOf<String, String>()
        for (header in listOf("content-type", "content-length")) {
            val value = cachedRequest.getHeader(header)
            if (value != null) {
                headers[header] = value
            }
        }

        val capabilityToken = extractCapabilityToken(cachedRequest)

        // Build Chio HTTP request.
        val chioRequest =
            ChioHttpRequest(
                requestId = UUID.randomUUID().toString(),
                method = method,
                routePattern = routePattern,
                path = cachedRequest.requestURI,
                query = cachedRequest.parameterMap.mapValues { it.value.firstOrNull() ?: "" },
                headers = headers,
                caller = caller,
                bodyHash = bodyHash,
                bodyLength = bodyBytes.size.toLong(),
                capabilityId = capabilityIdFromToken(capabilityToken),
                timestamp = System.currentTimeMillis() / 1000,
            )

        // Evaluate against sidecar.
        val result: EvaluateResponse
        try {
            result = client.evaluate(chioRequest, capabilityToken)
        } catch (e: Exception) {
            writeJsonError(
                httpResponse,
                502,
                ChioErrorResponse(
                    error = ChioErrorCodes.SIDECAR_UNREACHABLE,
                    message = "Chio sidecar error: ${e.message}",
                ),
            )
            return
        }

        // Check verdict and signed receipt semantics. Anything other than
        // explicit response allow plus mediated receipt authorization fails closed.
        if (!result.verdict.isAllowed() || !result.receipt.isAuthorized()) {
            val status = result.verdict.httpStatus ?: 403
            writeJsonError(
                httpResponse,
                status,
                ChioErrorResponse(
                    error = ChioErrorCodes.ACCESS_DENIED,
                    message = result.verdict.reason ?: "denied",
                    receiptId = result.receipt.id,
                    suggestion = "provide a valid capability token in the X-Chio-Capability header or chio_capability query parameter",
                ),
            )
            return
        }

        val receiptValid =
            try {
                client.verifyReceipt(result.receipt)
            } catch (_: Exception) {
                false
            }
        if (!receiptValid) {
            writeJsonError(
                httpResponse,
                502,
                ChioErrorResponse(
                    error = ChioErrorCodes.INVALID_RECEIPT,
                    message = "Chio sidecar returned an unverified receipt",
                    receiptId = result.receipt.id,
                ),
            )
            return
        }

        // Attach receipt ID only after semantic and signature verification.
        httpResponse.setHeader("X-Chio-Receipt-Id", result.receipt.id)

        // Request allowed -- forward to next filter/servlet.
        chain.doFilter(cachedRequest, response)
    }

    override fun destroy() {
        // No cleanup needed.
    }

    private fun writeJsonError(
        response: HttpServletResponse,
        status: Int,
        body: ChioErrorResponse,
    ) {
        response.status = status
        response.contentType = "application/json"
        response.writer.write(objectMapper.writeValueAsString(body))
        response.writer.flush()
    }
}
