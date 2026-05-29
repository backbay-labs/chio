/**
 * Deprecated thin shim so chio-spring-boot users keep compiling while
 * migrating to world.chio.sdk.ChioClient. Removed in 0.2.0.
 */
package world.chio

import world.chio.sdk.ChioClient
import world.chio.sdk.SidecarPaths
import java.time.Duration

@Deprecated(
    "Use world.chio.sdk.ChioClient directly",
    ReplaceWith(
        "world.chio.sdk.ChioClient(baseUrl, java.time.Duration.ofSeconds(timeoutSeconds))",
    ),
)
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

/** Legacy exception alias. Prefer world.chio.sdk.errors.ChioError. */
typealias ChioSidecarException = world.chio.sdk.errors.ChioError
