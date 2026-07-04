/**
 * Core types for the Chio HTTP substrate.
 *
 * These types mirror the Rust chio-http-core crate and define the contract
 * between JVM middleware and the Chio sidecar kernel. Package:
 * world.chio.sdk. Typealiases in chio-spring-boot/compat/
 * expose the Spring Boot integration names without duplicating type
 * definitions.
 */
package world.chio.sdk

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

/** How the caller authenticated to the upstream API. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthMethod
    @JvmOverloads
    constructor(
        @JsonProperty("method") val method: String,
        @JsonProperty("token_hash") val tokenHash: String? = null,
        @JsonProperty("key_name") val keyName: String? = null,
        @JsonProperty("key_hash") val keyHash: String? = null,
        @JsonProperty("cookie_name") val cookieName: String? = null,
        @JsonProperty("cookie_hash") val cookieHash: String? = null,
        @JsonProperty("subject_dn") val subjectDn: String? = null,
        @JsonProperty("fingerprint") val fingerprint: String? = null,
    ) : Serializable {
        companion object {
            private const val serialVersionUID: Long = 1L

            @JvmStatic
            fun anonymous(): AuthMethod = AuthMethod(method = "anonymous")

            @JvmStatic
            fun bearer(tokenHash: String): AuthMethod = AuthMethod(method = "bearer", tokenHash = tokenHash)

            @JvmStatic
            fun apiKey(
                keyName: String,
                keyHash: String,
            ): AuthMethod = AuthMethod(method = "api_key", keyName = keyName, keyHash = keyHash)

            @JvmStatic
            fun cookie(
                cookieName: String,
                cookieHash: String,
            ): AuthMethod = AuthMethod(method = "cookie", cookieName = cookieName, cookieHash = cookieHash)
        }
    }

/** The identity of the caller as extracted from the HTTP request. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class CallerIdentity(
    @JsonProperty("subject") val subject: String,
    @JsonProperty("auth_method") val authMethod: AuthMethod,
    @JsonProperty("verified") val verified: Boolean = false,
    @JsonProperty("tenant") val tenant: String? = null,
    @JsonProperty("agent_id") val agentId: String? = null,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L

        @JvmStatic
        fun anonymous(): CallerIdentity =
            CallerIdentity(
                subject = "anonymous",
                authMethod = AuthMethod.anonymous(),
            )
    }
}

/** The kernel's HTTP-layer verdict. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class Verdict(
    @JsonProperty("verdict") val verdict: String,
    @JsonProperty("reason") val reason: String? = null,
    @JsonProperty("guard") val guard: String? = null,
    @JsonProperty("http_status") val httpStatus: Int? = null,
) : Serializable {
    @JsonIgnore
    fun isAllowed(): Boolean = verdict == "allow"

    @JsonIgnore
    fun isDenied(): Boolean = verdict == "deny"

    /** Convert to core Decision type. Mirrors models.py. */
    fun toDecision(): Decision =
        when (verdict) {
            "allow" -> Decision.allow()
            "deny" -> Decision.deny(reason = reason ?: "", guard = guard ?: "")
            "cancel" -> Decision.cancelled(reason = reason ?: "")
            else -> Decision.incomplete(reason = reason ?: "")
        }

    companion object {
        private const val serialVersionUID: Long = 1L

        @JvmStatic
        fun allow(): Verdict = Verdict(verdict = "allow")

        @JvmOverloads
        @JvmStatic
        fun deny(
            reason: String,
            guard: String,
            httpStatus: Int = 403,
        ): Verdict = Verdict(verdict = "deny", reason = reason, guard = guard, httpStatus = httpStatus)
    }
}

/** Per-guard evaluation evidence. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class GuardEvidence(
    @JsonProperty("guard_name") val guardName: String,
    @JsonProperty("verdict") val verdict: Boolean,
    @JsonProperty("details") val details: String? = null,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Signed receipt for an HTTP request evaluation. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class HttpReceipt(
    @JsonProperty("id") val id: String,
    @JsonProperty("request_id") val requestId: String,
    @JsonProperty("route_pattern") val routePattern: String,
    @JsonProperty("method") val method: String,
    @JsonProperty("caller_identity_hash") val callerIdentityHash: String,
    @JsonProperty("session_id") val sessionId: String? = null,
    @JsonProperty("verdict") val verdict: Verdict,
    @JsonProperty("receipt_kind") val receiptKind: String,
    @JsonProperty("boundary_class") val boundaryClass: String,
    @JsonProperty("observation_outcome") val observationOutcome: String? = null,
    @JsonProperty("tool_origin") val toolOrigin: String,
    @JsonProperty("redaction_mode") val redactionMode: String,
    @JsonProperty("actor_chain") val actorChain: List<Map<String, Any?>> = emptyList(),
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
    @JsonProperty("response_status") val responseStatus: Int,
    @JsonProperty("timestamp") val timestamp: Long,
    @JsonProperty("content_hash") val contentHash: String,
    @JsonProperty("policy_hash") val policyHash: String,
    @JsonProperty("trust_level") val trustLevel: String,
    @JsonProperty("capability_id") val capabilityId: String? = null,
    @JsonProperty("metadata") val metadata: Any? = null,
    @JsonProperty("kernel_key") val kernelKey: String,
    @JsonProperty("signature") val signature: String,
) : Serializable {
    @JsonIgnore
    fun isAuthorized(): Boolean =
        receiptKind == "mediated_decision" &&
            boundaryClass == "prevent" &&
            observationOutcome == null &&
            trustLevel == "mediated" &&
            verdict.isAllowed()

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** HTTP request sent to the Chio sidecar for evaluation. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioHttpRequest(
    @JsonProperty("request_id") val requestId: String,
    @JsonProperty("method") val method: String,
    @JsonProperty("route_pattern") val routePattern: String,
    @JsonProperty("path") val path: String,
    @JsonProperty("query") val query: Map<String, String> = emptyMap(),
    @JsonProperty("headers") val headers: Map<String, String> = emptyMap(),
    @JsonProperty("caller") val caller: CallerIdentity,
    @JsonProperty("body_hash") val bodyHash: String? = null,
    @JsonProperty("body_length") val bodyLength: Long = 0,
    @JsonProperty("session_id") val sessionId: String? = null,
    @JsonProperty("capability_id") val capabilityId: String? = null,
    @JsonProperty("timestamp") val timestamp: Long,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Sidecar evaluation response. */
data class EvaluateResponse(
    @JsonProperty("verdict") val verdict: Verdict,
    @JsonProperty("receipt") val receipt: HttpReceipt,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Structured authority result returned by /chio/verify. */
data class VerifyReceiptResponse(
    @JsonProperty("signature_valid") val signatureValid: Boolean,
    @JsonProperty("signer_trusted") val signerTrusted: Boolean,
    @JsonProperty("receipt_id_valid") val receiptIdValid: Boolean,
    @JsonProperty("parameter_hash_valid") val parameterHashValid: Boolean,
    @JsonProperty("receipt_kind") val receiptKind: String,
    @JsonProperty("boundary_class") val boundaryClass: String,
    @JsonProperty("trust_level") val trustLevel: String,
    @JsonProperty("result") val result: String,
    @JsonProperty("authorized") val authorized: Boolean,
    @JsonProperty("signer_key_hex") val signerKeyHex: String,
    @JsonProperty("ok") val ok: Boolean,
) : Serializable {
    @JsonIgnore
    fun authorizes(receipt: HttpReceipt): Boolean =
        ok &&
            authorized &&
            signatureValid &&
            signerTrusted &&
            receiptIdValid &&
            parameterHashValid &&
            receiptKind == "mediated_decision" &&
            boundaryClass == "prevent" &&
            trustLevel == "mediated" &&
            (result == "allow" || result == "authorized" || result == "Authorized") &&
            receipt.isAuthorized()

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Explicit fail-open degraded state where no Chio receipt exists. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioPassthrough(
    @JsonProperty("mode") val mode: String = "allow_without_receipt",
    @JsonProperty("error") val error: String = ChioErrorCodes.SIDECAR_UNREACHABLE,
    @JsonProperty("message") val message: String,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Structured error response body. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioErrorResponse(
    @JsonProperty("error") val error: String,
    @JsonProperty("message") val message: String,
    @JsonProperty("receipt_id") val receiptId: String? = null,
    @JsonProperty("suggestion") val suggestion: String? = null,
) : Serializable {
    companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Chio error codes. */
object ChioErrorCodes {
    const val ACCESS_DENIED = "chio_access_denied"
    const val SIDECAR_UNREACHABLE = "chio_sidecar_unreachable"
    const val EVALUATION_FAILED = "chio_evaluation_failed"
    const val INVALID_RECEIPT = "chio_invalid_receipt"
    const val TIMEOUT = "chio_timeout"
}
