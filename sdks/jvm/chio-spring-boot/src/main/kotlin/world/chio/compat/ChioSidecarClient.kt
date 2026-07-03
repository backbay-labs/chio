/**
 * Thin wrapper so chio-spring-boot users can use world.chio.sdk.ChioClient
 * without duplicating the HTTP client logic.
 */
package world.chio

import world.chio.sdk.ChioClient
import world.chio.sdk.SidecarPaths
import java.time.Duration

class ChioSidecarClient
    @JvmOverloads
    constructor(
        baseUrl: String = DEFAULT_SIDECAR_URL,
        private val timeoutSeconds: Long = 5,
    ) {
        private val delegate: ChioClient = ChioClient(baseUrl, Duration.ofSeconds(timeoutSeconds))

        @JvmOverloads
        fun evaluate(
            request: ChioHttpRequest,
            capabilityToken: String? = null,
        ): EvaluateResponse = delegate.evaluateHttpRequest(request, capabilityToken)

        fun verifyReceipt(receipt: HttpReceipt): Boolean = delegate.verifyHttpReceipt(receipt).authorizes(receipt)

        fun healthCheck(): Boolean = delegate.isHealthy()

        companion object {
            const val DEFAULT_SIDECAR_URL: String = SidecarPaths.DEFAULT_BASE_URL
        }
    }

/** Exception alias for Spring Boot integration callers. */
typealias ChioSidecarException = world.chio.sdk.errors.ChioError
