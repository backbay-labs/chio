/**
 * Request to the Chio sidecar timed out. Mirrors chio_sdk.errors.ChioTimeoutError.
 */
package world.chio.sdk.errors

class ChioTimeoutError
    @JvmOverloads
    constructor(
        message: String,
        cause: Throwable? = null,
    ) : ChioError(message, "TIMEOUT", cause)
