/**
 * Streaming-level wrapper for sidecar evaluation failures. Mirrors
 * chio_streaming.errors.ChioStreamingError. Carries routing context
 * (topic, partition, offset, request_id) that Python's
 * evaluate_with_chio populates from failure_context.
 *
 * The Kotlin Flink operator uses this to decorate ChioError with the
 * subject / request_id that was being processed when the sidecar
 * call failed. The original ChioError stays as the cause.
 */
package world.chio.sdk.errors

class ChioStreamingError
    @JvmOverloads
    constructor(
        message: String,
        val topic: String? = null,
        val partition: Long? = null,
        val offset: Long? = null,
        val requestId: String? = null,
        cause: Throwable? = null,
    ) : ChioError(message, code = "CHIO_STREAMING", cause = cause)
